use axum::Json;
use axum::extract::State;

use zz_drop_core::api::{API_VERSION, Info};

use crate::routes::AppState;

/// `GET /api/v1/info` — discovery endpoint. Returns the API version
/// and a free-form implementation tag. No authentication.
pub async fn info(State(state): State<AppState>) -> Json<Info> {
    Json(Info {
        api_version: API_VERSION.to_string(),
        implementation: Some(state.implementation.clone()),
        notes: Some(
            "Minimal reference server. Not production-ready. See the project README.".into(),
        ),
    })
}
