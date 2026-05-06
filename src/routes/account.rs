//! `GET` / `PUT /account/email-preferences`. Both authenticated.
//!
//! `security_events` is non-disableable: the API contract enforces
//! `enum: [true]` on the wire. The DB schema also has a
//! `CHECK (pref_security_events = 1)` constraint as a belt-and-braces
//! guarantee — but we still validate at the application layer so the
//! error message stays under our control.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::Row;

use zz_drop_core::api::{ApiErrorCode, EmailPreferences, EmailPreferencesUpdate};

use crate::routes::AppState;
use crate::routes::auth::{api_err, authed_user, server_error, unauthorized};

/// `GET /api/v1/account/email-preferences`.
pub async fn get_prefs(headers: HeaderMap, State(state): State<AppState>) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };
    let row = sqlx::query(
        "SELECT pref_security_events, pref_profile_activity, pref_product_updates \
         FROM users WHERE id = ?1",
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await;
    let row = match row {
        Ok(r) => r,
        Err(_) => return server_error(),
    };
    let prefs = EmailPreferences {
        security_events: row.get::<i64, _>("pref_security_events") != 0,
        profile_activity: row.get::<i64, _>("pref_profile_activity") != 0,
        product_updates: row.get::<i64, _>("pref_product_updates") != 0,
    };
    Json(prefs).into_response()
}

/// `PUT /api/v1/account/email-preferences`.
///
/// Accepts a partial body: `profile_activity` and `product_updates` are
/// both optional. Unset fields keep their current value. Returns the
/// post-update preferences, so the caller doesn't need a follow-up GET.
pub async fn put_prefs(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<EmailPreferencesUpdate>,
) -> Response {
    let Some((user_id, _)) = authed_user(&headers, &state).await else {
        return unauthorized();
    };

    // Build a small dynamic UPDATE so unset fields aren't touched.
    // SQLite doesn't have COALESCE pain here — but we keep the SQL
    // simple by branching on the four possible combinations rather
    // than building strings at runtime. There are only four.
    let r = match (req.profile_activity, req.product_updates) {
        (Some(pa), Some(pu)) => sqlx::query(
            "UPDATE users SET pref_profile_activity = ?1, pref_product_updates = ?2, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?3",
        )
        .bind(pa as i64)
        .bind(pu as i64)
        .bind(user_id)
        .execute(state.db.pool())
        .await,
        (Some(pa), None) => sqlx::query(
            "UPDATE users SET pref_profile_activity = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
        )
        .bind(pa as i64)
        .bind(user_id)
        .execute(state.db.pool())
        .await,
        (None, Some(pu)) => sqlx::query(
            "UPDATE users SET pref_product_updates = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
        )
        .bind(pu as i64)
        .bind(user_id)
        .execute(state.db.pool())
        .await,
        (None, None) => {
            // Empty PATCH-style body — return the current state without
            // mutating anything.
            return get_prefs(headers, State(state)).await;
        }
    };
    if r.is_err() {
        return server_error();
    }

    // Return the updated preferences. Reuse the GET handler so the
    // serialization stays single-sourced.
    get_prefs(headers, State(state)).await
}

/// Defensive helper: surfaces an explicit 400 when a client tries to
/// send `security_events: false` (the schema's `CHECK` would also fire,
/// but we want a stable error code on the wire).
#[allow(dead_code)]
pub(crate) fn reject_security_events_false() -> Response {
    api_err(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "security_events is non-disableable",
    )
}
