//! Profile-alias endpoints: list, create, delete + blob get/put.
//!
//! Authentication: every handler in this module requires a valid
//! `Authorization: Bearer <token>` and rejects with 401 otherwise.
//! Authorization: an alias is owned by exactly one user_id; only that
//! user can fetch its blob, replace it, or delete the alias.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sqlx::Row;

use zz_drop_core::api::{
    Alias, ApiErrorCode, CreateProfileRequest, ProfileList, ProfileSummary,
};

use crate::routes::AppState;
use crate::routes::auth::{api_err, authed_user, invalid, now_unix, server_error, unauthorized};

/// `GET /api/v1/profiles` — list the authenticated user's aliases.
pub async fn list(headers: HeaderMap, State(state): State<AppState>) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    let rows = sqlx::query(
        "SELECT alias, blob_size, blob_version, created_at, updated_at \
         FROM profiles WHERE user_id = ?1 ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await;
    let rows = match rows {
        Ok(r) => r,
        Err(_) => return server_error(),
    };
    let mut profiles = Vec::with_capacity(rows.len());
    for row in rows {
        let alias_s: String = row.get("alias");
        let alias = match Alias::new(alias_s) {
            Ok(a) => a,
            Err(_) => return server_error(),
        };
        profiles.push(ProfileSummary {
            alias,
            blob_size: row.get::<i64, _>("blob_size") as u64,
            blob_version: row.get::<i64, _>("blob_version") as u64,
            created_at: format_iso(row.get::<i64, _>("created_at")),
            updated_at: format_iso(row.get::<i64, _>("updated_at")),
        });
    }
    Json(ProfileList { profiles }).into_response()
}

/// `POST /api/v1/profiles` — create an alias for the authenticated
/// user. The alias is in the global namespace (per the spec) so it
/// must not already be taken by anyone else either. Returns 201 +
/// `ProfileSummary` with `blob_size = 0`, `blob_version = 0`.
pub async fn create(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateProfileRequest>,
) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };

    // Per-account quota check (Free plan: 5).
    let count_row = sqlx::query("SELECT COUNT(*) AS n FROM profiles WHERE user_id = ?1")
        .bind(user_id)
        .fetch_one(state.db.pool())
        .await;
    let count: i64 = match count_row {
        Ok(r) => r.get("n"),
        Err(_) => return server_error(),
    };
    if (count as u32) >= state.profile_limits.max_aliases_free {
        return api_err(
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "alias quota exceeded",
        );
    }

    let alias_str = req.alias.as_str().to_lowercase();
    let now = now_unix() as i64;
    let r = sqlx::query(
        "INSERT INTO profiles (user_id, alias, blob_size, blob_version, created_at, updated_at) \
         VALUES (?1, ?2, 0, 0, ?3, ?3)",
    )
    .bind(user_id)
    .bind(&alias_str)
    .bind(now)
    .execute(state.db.pool())
    .await;
    match r {
        Ok(_) => {
            let summary = ProfileSummary {
                alias: req.alias,
                blob_size: 0,
                blob_version: 0,
                created_at: format_iso(now),
                updated_at: format_iso(now),
            };
            (StatusCode::CREATED, Json(summary)).into_response()
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => api_err(
            StatusCode::CONFLICT,
            ApiErrorCode::VersionConflict,
            "alias already taken",
        ),
        Err(_) => server_error(),
    }
}

#[derive(Debug, Deserialize)]
pub struct PutBlobQuery {
    pub expected_version: u64,
}

/// `PUT /api/v1/profiles/{alias}/blob?expected_version=N` — atomic
/// upload. The server stores the opaque blob; size is enforced. The
/// `expected_version` parameter must match the current `blob_version`
/// on disk (or `0` for the first upload) — anything else is a 409.
pub async fn put_blob(
    Path(alias_path): Path<String>,
    Query(q): Query<PutBlobQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    let alias = match Alias::new(alias_path) {
        Ok(a) => a,
        Err(_) => return invalid("alias is malformed"),
    };
    if (body.len() as u64) > state.profile_limits.blob_max_bytes {
        return api_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            ApiErrorCode::BlobTooLarge,
            "blob exceeds the per-blob size limit",
        );
    }

    // Lookup + ownership check + expected_version match in a single
    // transaction so concurrent PUTs cannot both succeed.
    let mut tx = match state.db.pool().begin().await {
        Ok(t) => t,
        Err(_) => return server_error(),
    };
    let row = sqlx::query(
        "SELECT id, user_id, blob_version FROM profiles WHERE alias = ?1",
    )
    .bind(alias.as_str())
    .fetch_optional(&mut *tx)
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return api_err(StatusCode::NOT_FOUND, ApiErrorCode::NotFound, "alias not found"),
        Err(_) => return server_error(),
    };
    let pid: i64 = row.get("id");
    let owner: i64 = row.get("user_id");
    if owner != user_id {
        return api_err(StatusCode::FORBIDDEN, ApiErrorCode::Forbidden, "alias owned by another account");
    }
    let current: i64 = row.get("blob_version");
    if (current as u64) != q.expected_version {
        return api_err(
            StatusCode::CONFLICT,
            ApiErrorCode::VersionConflict,
            "expected_version does not match current blob_version",
        );
    }

    let new_version = current + 1;
    let now = now_unix() as i64;
    let blob_bytes = body.to_vec();
    let blob_len = blob_bytes.len() as i64;
    let upd = sqlx::query(
        "UPDATE profiles SET blob = ?1, blob_size = ?2, blob_version = ?3, updated_at = ?4 \
         WHERE id = ?5",
    )
    .bind(blob_bytes)
    .bind(blob_len)
    .bind(new_version)
    .bind(now)
    .bind(pid)
    .execute(&mut *tx)
    .await;
    if upd.is_err() {
        return server_error();
    }

    let row = sqlx::query("SELECT created_at FROM profiles WHERE id = ?1")
        .bind(pid)
        .fetch_one(&mut *tx)
        .await;
    let created_at: i64 = match row {
        Ok(r) => r.get("created_at"),
        Err(_) => return server_error(),
    };
    if tx.commit().await.is_err() {
        return server_error();
    }

    Json(ProfileSummary {
        alias,
        blob_size: blob_len as u64,
        blob_version: new_version as u64,
        created_at: format_iso(created_at),
        updated_at: format_iso(now),
    })
    .into_response()
}

/// `GET /api/v1/profiles/{alias}/blob` — download. Returns the
/// encrypted blob as `application/octet-stream`. 404 if not yet
/// uploaded; 403 if the alias belongs to a different account.
pub async fn get_blob(
    Path(alias_path): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    let alias = match Alias::new(alias_path) {
        Ok(a) => a,
        Err(_) => return invalid("alias is malformed"),
    };
    let row = sqlx::query(
        "SELECT user_id, blob, blob_size FROM profiles WHERE alias = ?1",
    )
    .bind(alias.as_str())
    .fetch_optional(state.db.pool())
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return api_err(StatusCode::NOT_FOUND, ApiErrorCode::NotFound, "alias not found"),
        Err(_) => return server_error(),
    };
    let owner: i64 = row.get("user_id");
    if owner != user_id {
        return api_err(StatusCode::FORBIDDEN, ApiErrorCode::Forbidden, "alias owned by another account");
    }
    let blob: Option<Vec<u8>> = row.get("blob");
    let bytes = match blob {
        Some(b) if !b.is_empty() => b,
        _ => {
            return api_err(
                StatusCode::NOT_FOUND,
                ApiErrorCode::NotFound,
                "no blob uploaded for this alias yet",
            );
        }
    };
    let mut resp = (StatusCode::OK, bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    resp
}

/// `DELETE /api/v1/profiles/{alias}` — remove the alias and its blob.
pub async fn delete(
    Path(alias_path): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    let alias = match Alias::new(alias_path) {
        Ok(a) => a,
        Err(_) => return invalid("alias is malformed"),
    };
    let row = sqlx::query("SELECT user_id FROM profiles WHERE alias = ?1")
        .bind(alias.as_str())
        .fetch_optional(state.db.pool())
        .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return api_err(StatusCode::NOT_FOUND, ApiErrorCode::NotFound, "alias not found"),
        Err(_) => return server_error(),
    };
    let owner: i64 = row.get("user_id");
    if owner != user_id {
        return api_err(StatusCode::FORBIDDEN, ApiErrorCode::Forbidden, "alias owned by another account");
    }
    let r = sqlx::query("DELETE FROM profiles WHERE alias = ?1 AND user_id = ?2")
        .bind(alias.as_str())
        .bind(user_id)
        .execute(state.db.pool())
        .await;
    if r.is_err() {
        return server_error();
    }
    StatusCode::OK.into_response()
}

// ── helpers ───────────────────────────────────────────────────────────

/// Format a unix-seconds timestamp as ISO 8601 in UTC. We don't need
/// to round-trip parse it (storage is INTEGER, comparisons are pure
/// arithmetic), so a hand-rolled formatter beats pulling in another
/// dependency for this single call.
fn format_iso(secs: i64) -> String {
    // Treat negative timestamps as the epoch (we never expect them).
    let s = secs.max(0) as u64;
    let (y, m, d, hh, mm, ss) = secs_to_civil(s);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert unix seconds to civil (Y/M/D HH:MM:SS) UTC. Algorithm from
/// Howard Hinnant's `<chrono>` proposal — short, branch-free, exact
/// over the entire i64 range we care about.
fn secs_to_civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let s = (secs % 86_400) as u32;
    let hh = s / 3600;
    let mm = (s / 60) % 60;
    let ss = s % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y_int = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy as u32) - (153 * mp as u32 + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y_int + 1 } else { y_int };
    (y, m as u32, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trip_known_values() {
        assert_eq!(format_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_iso(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_iso(1_800_000_000), "2027-01-15T08:00:00Z");
    }
}
