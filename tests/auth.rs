// Integration tests for `/auth/register` and `/auth/login` (no TOTP).
// Drives the router via `tower::ServiceExt::oneshot`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zz_drop_core::api::{ApiErrorBody, ApiErrorCode, BASE_PATH, LoginResponse};
use zz_drop_server_minimal::routes::ProfileLimits;
use zz_drop_server_minimal::{Database, build_router};

async fn app() -> axum::Router {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    build_router(
        db,
        "test v0".into(),
        [7u8; 32],
        ProfileLimits {
            max_aliases_free: 5,
            blob_max_bytes: 1 << 20,
        },
    )
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn json_request(method: Method, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("{BASE_PATH}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn register_creates_user_and_login_returns_session_token() {
    let app = app().await;
    let r = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/register",
            serde_json::json!({
                "email": "alice@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);

    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "email": "alice@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: LoginResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(!body.token.is_empty());
    assert!(body.expires_in > 0);
}

#[tokio::test]
async fn register_rejects_short_password() {
    let app = app().await;
    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/register",
            serde_json::json!({
                "email": "alice@example.org",
                "password": "short"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let body: ApiErrorBody = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert_eq!(body.error, ApiErrorCode::InvalidRequest);
}

#[tokio::test]
async fn login_with_wrong_password_returns_401() {
    let app = app().await;
    let _ = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/register",
            serde_json::json!({
                "email": "bob@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "email": "bob@example.org",
                "password": "wrong-password-1234567"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let body: ApiErrorBody = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert_eq!(body.error, ApiErrorCode::Unauthorized);
}

#[tokio::test]
async fn login_for_unknown_email_returns_401_not_404() {
    // Guarding against email-enumeration: same response for "no user"
    // and "wrong password".
    let app = app().await;
    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "email": "nobody@example.org",
                "password": "any-password-1234567890"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn duplicate_register_fails_with_conflict() {
    let app = app().await;
    let body = serde_json::json!({
        "email": "carol@example.org",
        "password": "correct-horse-battery-9!"
    });
    let r1 = app
        .clone()
        .oneshot(json_request(Method::POST, "/auth/register", body.clone()))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = app
        .oneshot(json_request(Method::POST, "/auth/register", body))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn email_is_case_insensitive_at_login() {
    let app = app().await;
    let _ = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/register",
            serde_json::json!({
                "email": "Dave@Example.Org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "email": "DAVE@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_response_does_not_carry_password_or_user_id() {
    // Defensive grep on the wire: the token + expires_in are the only
    // two fields — never echo back password, hash, user_id, etc.
    let app = app().await;
    let _ = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/register",
            serde_json::json!({
                "email": "leaktest@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    let r = app
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "email": "leaktest@example.org",
                "password": "correct-horse-battery-9!"
            }),
        ))
        .await
        .unwrap();
    let raw = body_bytes(r).await;
    let s = std::str::from_utf8(&raw).unwrap();
    for forbidden in [
        "correct-horse",
        "password",
        "password_hash",
        "user_id",
        "argon2",
        "leaktest@example.org",
    ] {
        assert!(
            !s.to_lowercase().contains(&forbidden.to_lowercase()),
            "login response leaked `{forbidden}`: `{s}`"
        );
    }
}
