// Integration test for `GET /api/v1/info`. Drives the Axum router
// directly via `tower::ServiceExt::oneshot` — no TCP listener, no
// network. The DB is in-memory.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zz_drop_core::api::{API_VERSION, BASE_PATH, Info};
use zz_drop_server_minimal::routes::ProfileLimits;
use zz_drop_server_minimal::{Database, build_router};

async fn app() -> axum::Router {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    build_router(
        db,
        "test-server v0.0.0".into(),
        [0u8; 32],
        ProfileLimits {
            max_aliases_free: 5,
            blob_max_bytes: 1 << 20,
        },
    )
}

async fn body_json<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("body deserializes")
}

#[tokio::test]
async fn info_returns_api_version_one() {
    let app = app().await;
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("{BASE_PATH}/info"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let info: Info = body_json(resp).await;
    assert_eq!(info.api_version, API_VERSION);
}

#[tokio::test]
async fn info_includes_implementation_tag() {
    let app = app().await;
    let req = Request::builder()
        .uri(format!("{BASE_PATH}/info"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let info: Info = body_json(resp).await;
    assert_eq!(info.implementation.as_deref(), Some("test-server v0.0.0"));
}

#[tokio::test]
async fn info_carries_no_provider_or_secret_fields() {
    // Defensive sanity: the `/info` payload must never leak
    // implementation internals, credentials, or provider metadata.
    let app = app().await;
    let req = Request::builder()
        .uri(format!("{BASE_PATH}/info"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    let raw = std::str::from_utf8(&raw).unwrap();
    for forbidden in [
        "passphrase",
        "password",
        "token",
        "secret",
        "nextcloud",
        "provider",
        "oauth",
        "DATABASE_URL",
    ] {
        assert!(
            !raw.to_lowercase().contains(&forbidden.to_lowercase()),
            "/info leaked `{forbidden}`: `{raw}`"
        );
    }
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = app().await;
    let req = Request::builder()
        .uri(format!("{BASE_PATH}/this-does-not-exist"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
