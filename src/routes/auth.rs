//! `POST /auth/register` and `POST /auth/login` (step 1).
//!
//! Step 2 of login (TOTP) lives in `routes::totp::login`.
//!
//! Errors: we deliberately collapse "no such email" and "wrong password"
//! into a single `Unauthorized`. We never log the password, the token,
//! or the response body on the failure path.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use sqlx::Row;

use zz_drop_core::api::{
    ApiErrorBody, ApiErrorCode, LoginRequest, LoginResponse, LoginTotpChallenge, RegisterRequest,
    is_plausible_email,
};

use crate::auth::{password, session};
use crate::routes::AppState;

/// `POST /api/v1/auth/register` — create an account. Returns 201 No
/// Content on success. The password is hashed with Argon2id; the
/// plaintext is dropped before this function returns.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    if !is_plausible_email(&req.email) {
        return invalid("email is not a valid address");
    }
    if req.password.len() < password::MIN_PASSWORD_LEN {
        return invalid("password must be at least 16 characters");
    }
    let hash = match password::hash_password(&req.password) {
        Ok(h) => h,
        Err(_) => return server_error(),
    };
    let r = sqlx::query("INSERT INTO users (email, password_hash) VALUES (?1, ?2)")
        .bind(&req.email.to_lowercase())
        .bind(&hash)
        .execute(state.db.pool())
        .await;
    match r {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => api_err(
            StatusCode::CONFLICT,
            ApiErrorCode::VersionConflict, // generic "already taken" maps here
            "email already registered",
        ),
        Err(_) => server_error(),
    }
}

/// `POST /api/v1/auth/login` — step 1 of the login flow. With TOTP off
/// returns a `LoginResponse` (session token). With TOTP on returns a
/// `LoginTotpChallenge` and the client must follow up with
/// `/auth/totp/login`.
pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    let row = match sqlx::query(
        "SELECT id, password_hash FROM users WHERE email = ?1",
    )
    .bind(req.email.to_lowercase())
    .fetch_optional(state.db.pool())
    .await
    {
        Ok(r) => r,
        Err(_) => return server_error(),
    };
    let Some(row) = row else {
        return unauthorized();
    };
    let user_id: i64 = row.get("id");
    let stored_hash: String = row.get("password_hash");
    let ok = password::verify_password(&req.password, &stored_hash).unwrap_or(false);
    if !ok {
        return unauthorized();
    }

    // Is TOTP active for this user?
    let totp_active = match sqlx::query(
        "SELECT enrolled_at FROM totp_secrets WHERE user_id = ?1 AND enrolled_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    {
        Ok(r) => r.is_some(),
        Err(_) => return server_error(),
    };

    if !totp_active {
        return mint_session_response(state, user_id).await;
    }

    // TOTP active → mint a short-lived challenge, hash and store it.
    let challenge = match session::mint_token() {
        Ok(t) => t,
        Err(_) => return server_error(),
    };
    let challenge_hash = session::hash_token(&challenge);
    let expires_at = (now_unix() + session::TOTP_CHALLENGE_TTL_SECS) as i64;
    let r = sqlx::query(
        "INSERT INTO totp_challenges (user_id, challenge_hash, expires_at) VALUES (?1, ?2, ?3)",
    )
    .bind(user_id)
    .bind(&challenge_hash)
    .bind(expires_at)
    .execute(state.db.pool())
    .await;
    if r.is_err() {
        return server_error();
    }
    Json(LoginTotpChallenge {
        totp_required: true,
        challenge,
        expires_in: session::TOTP_CHALLENGE_TTL_SECS,
    })
    .into_response()
}

pub(crate) async fn mint_session_response(state: AppState, user_id: i64) -> Response {
    let token = match session::mint_token() {
        Ok(t) => t,
        Err(_) => return server_error(),
    };
    let token_hash = session::hash_token(&token);
    let expires_at = (now_unix() + session::SESSION_TTL_SECS) as i64;
    let r = sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?1, ?2, ?3)",
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(state.db.pool())
    .await;
    if r.is_err() {
        return server_error();
    }
    Json(LoginResponse {
        token,
        expires_in: session::SESSION_TTL_SECS,
    })
    .into_response()
}

// ── helpers ───────────────────────────────────────────────────────────

pub(crate) fn invalid(msg: &str) -> Response {
    api_err(StatusCode::BAD_REQUEST, ApiErrorCode::InvalidRequest, msg)
}

pub(crate) fn unauthorized() -> Response {
    api_err(StatusCode::UNAUTHORIZED, ApiErrorCode::Unauthorized, "unauthorized")
}

pub(crate) fn server_error() -> Response {
    api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiErrorCode::ServerError,
        "server error",
    )
}

pub(crate) fn api_err(status: StatusCode, code: ApiErrorCode, msg: &str) -> Response {
    let body = ApiErrorBody::new(code, msg.to_string());
    (status, Json(body)).into_response()
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compare a stored `expires_at` (unix seconds, as INTEGER in SQLite,
/// retrieved as `i64`) against the current time.
pub(crate) fn expires_in_past_secs(expires_at: i64) -> bool {
    expires_at as u64 <= now_unix()
}

// Random bytes utility used by other auth routes.
#[allow(dead_code)]
pub(crate) fn random_b64(n: usize) -> Result<String, getrandom::Error> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf)?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

/// Resolve `Authorization: Bearer <token>` to `(user_id, email)`.
/// The session must exist, not be expired, and belong to a known user.
/// Used by every authenticated route in this server.
pub(crate) async fn authed_user(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<(i64, String)> {
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    if token.is_empty() {
        return None;
    }
    let token_hash = session::hash_token(token);
    let row = sqlx::query(
        "SELECT u.id AS uid, u.email AS uemail, s.expires_at AS exp \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = ?1",
    )
    .bind(&token_hash)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten()?;
    let exp: i64 = row.get("exp");
    if expires_in_past_secs(exp) {
        return None;
    }
    let uid: i64 = row.get("uid");
    let email: String = row.get("uemail");
    Some((uid, email))
}

// `Serialize` import asserts JSON-bodies pass the right derived type;
// keep this no-op wrapper so dead-code warning stays quiet if we
// remove the import later.
#[allow(dead_code)]
fn _serialize_marker<T: Serialize>(_: &T) {}
