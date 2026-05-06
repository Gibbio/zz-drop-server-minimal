use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

use zz_drop_core::api::BASE_PATH;

use crate::Database;

pub mod account;
pub mod auth;
pub mod info;
pub mod profiles;
pub mod totp;

/// Master key used to encrypt TOTP shared seeds at rest. 32 bytes.
pub type TotpMasterKey = Arc<[u8; 32]>;

/// Ephemeral rate-limit state for TOTP verification: per-user list of
/// recent failure timestamps. We keep this in memory only — no persistent
/// IP capture, no DB row. Periodically pruned in the verification path.
pub type TotpFailureTimes = Arc<Mutex<HashMap<i64, Vec<u64>>>>;

/// Limits applied to the `/profiles` endpoints. Pulled from env vars
/// at startup; treated as constants for the life of the process.
#[derive(Clone, Copy, Debug)]
pub struct ProfileLimits {
    pub max_aliases_free: u32,
    pub blob_max_bytes: u64,
}

/// Application-wide state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub implementation: String,
    pub totp_master_key: TotpMasterKey,
    pub totp_failures: TotpFailureTimes,
    pub profile_limits: ProfileLimits,
}

/// Build the API router and mount it under `/api/v1`. Tests instantiate
/// this directly and use `tower::ServiceExt::oneshot` to drive
/// requests; the binary calls it from `main`.
pub fn build_router(
    db: Database,
    implementation: String,
    totp_master_key: [u8; 32],
    profile_limits: ProfileLimits,
) -> Router {
    let state = AppState {
        db,
        implementation,
        totp_master_key: Arc::new(totp_master_key),
        totp_failures: Arc::new(Mutex::new(HashMap::new())),
        profile_limits,
    };

    let api_v1 = Router::new()
        .route("/info", get(info::info))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/totp/enroll", post(totp::enroll))
        .route("/auth/totp/verify", post(totp::verify))
        .route("/auth/totp/login", post(totp::login_step2))
        .route("/auth/totp/disable", post(totp::disable))
        .route(
            "/profiles",
            get(profiles::list).post(profiles::create),
        )
        .route(
            "/profiles/{alias}/blob",
            get(profiles::get_blob).put(profiles::put_blob),
        )
        .route("/profiles/{alias}", axum::routing::delete(profiles::delete))
        .route(
            "/account/email-preferences",
            get(account::get_prefs).put(account::put_prefs),
        )
        .with_state(state);

    Router::new()
        .nest(BASE_PATH, api_v1)
        .layer(TraceLayer::new_for_http())
}
