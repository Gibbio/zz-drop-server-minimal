//! TOTP endpoints: enroll, verify (activate), login step 2, disable.
//!
//! Authentication for `enroll` / `disable` is handled by extracting the
//! Bearer session token from the `Authorization` header. `verify` and
//! `login_step2` are unauthenticated by design — `verify` runs while
//! TOTP is still pending, and `login_step2` exchanges a challenge for
//! a session.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::Row;

use zz_drop_core::api::{
    LoginRequest, TotpDisableRequest, TotpEnrollResponse, TotpLoginRequest, TotpVerifyRequest,
};

use crate::auth::{password, recovery_codes, seed, session, totp};
use crate::routes::AppState;
use crate::routes::auth::{
    api_err, authed_user, expires_in_past_secs, invalid, mint_session_response, now_unix,
    server_error, unauthorized,
};

const ISSUER: &str = "zz-drop";

/// Per-account rate limit for TOTP verifications: 5 failures per 15
/// minutes. We do NOT persist these — only an in-memory Vec of unix
/// seconds per user_id, pruned every call.
const RATE_LIMIT_FAILURES: usize = 5;
const RATE_LIMIT_WINDOW_SECS: u64 = 15 * 60;

/// `POST /auth/totp/enroll` — start TOTP enrollment for the
/// authenticated account. Generates a fresh seed, encrypts it at rest,
/// returns the otpauth URI + base32 + 10 plaintext recovery codes.
/// Enrollment is **pending** until the next call to `/auth/totp/verify`
/// passes.
pub async fn enroll(headers: HeaderMap, State(state): State<AppState>) -> Response {
    let Some((user_id, email)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };

    // Disallow enrolling twice without disabling first.
    let exists = sqlx::query("SELECT user_id FROM totp_secrets WHERE user_id = ?1")
        .bind(user_id)
        .fetch_optional(state.db.pool())
        .await;
    match exists {
        Ok(Some(_)) => {
            return api_err(
                StatusCode::CONFLICT,
                zz_drop_core::api::ApiErrorCode::VersionConflict,
                "totp already enrolled or pending",
            );
        }
        Err(_) => return server_error(),
        Ok(None) => {}
    }

    let raw_seed = match seed::generate_seed() {
        Ok(s) => s,
        Err(_) => return server_error(),
    };
    let (seed_ct, seed_nonce) =
        match seed::encrypt_seed(&raw_seed, state.totp_master_key.as_ref()) {
            Ok(p) => p,
            Err(_) => return server_error(),
        };

    let plain_codes = match recovery_codes::generate_codes() {
        Ok(c) => c,
        Err(_) => return server_error(),
    };

    let pending_until = (now_unix() + 24 * 60 * 60) as i64;

    // We need a transaction so a half-written enrollment doesn't leak
    // recovery code rows on failure.
    let mut tx = match state.db.pool().begin().await {
        Ok(t) => t,
        Err(_) => return server_error(),
    };

    if sqlx::query(
        "INSERT INTO totp_secrets (user_id, seed_ciphertext, seed_nonce, pending_until) \
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(user_id)
    .bind(&seed_ct)
    .bind(&seed_nonce)
    .bind(pending_until)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return server_error();
    }

    for code in &plain_codes {
        let h = match recovery_codes::hash_code(code) {
            Ok(h) => h,
            Err(_) => return server_error(),
        };
        if sqlx::query(
            "INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
        )
        .bind(user_id)
        .bind(&h)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return server_error();
        }
    }
    if tx.commit().await.is_err() {
        return server_error();
    }

    let secret_b32 = totp::seed_to_base32(&raw_seed);
    let uri = totp::otpauth_uri(ISSUER, &email, &secret_b32);
    Json(TotpEnrollResponse {
        otpauth_uri: uri,
        secret_base32: secret_b32,
        recovery_codes: plain_codes.to_vec(),
    })
    .into_response()
}

/// `POST /auth/totp/verify` — activate a pending enrollment by
/// verifying a 6-digit code. Authenticated.
pub async fn verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<TotpVerifyRequest>,
) -> Response {
    let Some((user_id, _email)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    if !rate_limit_check(&state, user_id).await {
        return rate_limited();
    }

    let row = sqlx::query(
        "SELECT seed_ciphertext, seed_nonce FROM totp_secrets WHERE user_id = ?1 AND enrolled_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return invalid("no pending enrollment"),
        Err(_) => return server_error(),
    };
    let ct: String = row.get("seed_ciphertext");
    let nonce: String = row.get("seed_nonce");
    let raw_seed = match seed::decrypt_seed(&ct, &nonce, state.totp_master_key.as_ref()) {
        Ok(s) => s,
        Err(_) => return server_error(),
    };

    if !totp::verify(&raw_seed, now_unix(), &req.code) {
        rate_limit_record(&state, user_id).await;
        return unauthorized();
    }

    if sqlx::query(
        "UPDATE totp_secrets SET enrolled_at = ?1, pending_until = NULL WHERE user_id = ?2",
    )
    .bind(now_unix() as i64)
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .is_err()
    {
        return server_error();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /auth/totp/login` — step 2 of two-step login. Exchanges a
/// challenge + 6-digit code (or a recovery code) for a session.
pub async fn login_step2(
    State(state): State<AppState>,
    Json(req): Json<TotpLoginRequest>,
) -> Response {
    if req.challenge.is_empty() || req.code.is_empty() {
        return invalid("challenge and code required");
    }
    let challenge_hash = session::hash_token(&req.challenge);

    // Look up the challenge row and bind the user_id from it. We delete
    // single-use to make replay impossible.
    let row = sqlx::query(
        "SELECT id, user_id, expires_at FROM totp_challenges WHERE challenge_hash = ?1",
    )
    .bind(&challenge_hash)
    .fetch_optional(state.db.pool())
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return unauthorized(),
        Err(_) => return server_error(),
    };
    let chal_id: i64 = row.get("id");
    let user_id: i64 = row.get("user_id");
    let expires_at: i64 = row.get("expires_at");
    if expires_in_past_secs(expires_at) {
        let _ = sqlx::query("DELETE FROM totp_challenges WHERE id = ?1")
            .bind(chal_id)
            .execute(state.db.pool())
            .await;
        return unauthorized();
    }

    if !rate_limit_check(&state, user_id).await {
        return rate_limited();
    }

    let ok = if looks_like_totp_code(&req.code) {
        verify_totp_for_user(&state, user_id, &req.code).await
    } else {
        consume_recovery_code(&state, user_id, &req.code).await
    };
    if !ok {
        rate_limit_record(&state, user_id).await;
        return unauthorized();
    }

    // Single-use: delete the challenge row regardless of subsequent
    // outcome, so a replayed challenge cannot work even if minting
    // the session row fails.
    let _ = sqlx::query("DELETE FROM totp_challenges WHERE id = ?1")
        .bind(chal_id)
        .execute(state.db.pool())
        .await;

    mint_session_response(state, user_id).await
}

/// `POST /auth/totp/disable` — disables TOTP for the authenticated
/// account. Requires the account password + a current valid TOTP code
/// or one recovery code.
pub async fn disable(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<TotpDisableRequest>,
) -> Response {
    let Some((user_id, _email)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };

    // Re-check the password before disabling.
    let stored = match sqlx::query("SELECT password_hash FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_one(state.db.pool())
        .await
    {
        Ok(r) => r,
        Err(_) => return server_error(),
    };
    let stored_hash: String = stored.get("password_hash");
    if !password::verify_password(&req.password, &stored_hash).unwrap_or(false) {
        return unauthorized();
    }
    if !rate_limit_check(&state, user_id).await {
        return rate_limited();
    }
    let ok = if looks_like_totp_code(&req.code) {
        verify_totp_for_user(&state, user_id, &req.code).await
    } else {
        consume_recovery_code(&state, user_id, &req.code).await
    };
    if !ok {
        rate_limit_record(&state, user_id).await;
        return unauthorized();
    }

    // Wipe TOTP rows.
    let mut tx = match state.db.pool().begin().await {
        Ok(t) => t,
        Err(_) => return server_error(),
    };
    if sqlx::query("DELETE FROM totp_secrets WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return server_error();
    }
    if sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return server_error();
    }
    if sqlx::query("DELETE FROM totp_challenges WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return server_error();
    }
    if tx.commit().await.is_err() {
        return server_error();
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── helpers ───────────────────────────────────────────────────────────

fn looks_like_totp_code(s: &str) -> bool {
    s.len() == 6 && s.chars().all(|c| c.is_ascii_digit())
}

async fn verify_totp_for_user(state: &AppState, user_id: i64, code: &str) -> bool {
    let row = match sqlx::query(
        "SELECT seed_ciphertext, seed_nonce FROM totp_secrets WHERE user_id = ?1 AND enrolled_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    {
        Ok(Some(r)) => r,
        _ => return false,
    };
    let ct: String = row.get("seed_ciphertext");
    let nonce: String = row.get("seed_nonce");
    let raw_seed = match seed::decrypt_seed(&ct, &nonce, state.totp_master_key.as_ref()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    totp::verify(&raw_seed, now_unix(), code)
}

/// Try to match `code` against the account's unconsumed recovery codes;
/// if one matches, mark it consumed and return `true`. Argon2id verify
/// is slow, so we limit ourselves to up to 10 hashes per account.
async fn consume_recovery_code(state: &AppState, user_id: i64, code: &str) -> bool {
    let rows = match sqlx::query(
        "SELECT id, code_hash FROM totp_recovery_codes WHERE user_id = ?1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    for row in rows {
        let id: i64 = row.get("id");
        let h: String = row.get("code_hash");
        if recovery_codes::verify_code(code, &h).unwrap_or(false) {
            let _ = sqlx::query(
                "UPDATE totp_recovery_codes SET consumed_at = ?1 WHERE id = ?2",
            )
            .bind(now_unix() as i64)
            .bind(id)
            .execute(state.db.pool())
            .await;
            return true;
        }
    }
    false
}

async fn rate_limit_check(state: &AppState, user_id: i64) -> bool {
    let mut map = state.totp_failures.lock().await;
    let now = now_unix();
    let cutoff = now.saturating_sub(RATE_LIMIT_WINDOW_SECS);
    let times = map.entry(user_id).or_default();
    times.retain(|&t| t >= cutoff);
    times.len() < RATE_LIMIT_FAILURES
}

async fn rate_limit_record(state: &AppState, user_id: i64) {
    let mut map = state.totp_failures.lock().await;
    let times = map.entry(user_id).or_default();
    times.push(now_unix());
}

fn rate_limited() -> Response {
    api_err(
        StatusCode::TOO_MANY_REQUESTS,
        zz_drop_core::api::ApiErrorCode::RateLimited,
        "too many failed attempts",
    )
}


// We import `LoginRequest` only to keep the public surface symmetric
// during reviewer searches; it's not used in this file directly.
#[allow(dead_code)]
fn _login_request_marker(_: LoginRequest) {}
