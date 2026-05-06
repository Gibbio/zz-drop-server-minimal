// Integration tests for `GET` / `PUT /account/email-preferences`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zz_drop_core::api::{BASE_PATH, EmailPreferences, LoginResponse};
use zz_drop_server_minimal::routes::ProfileLimits;
use zz_drop_server_minimal::{Database, build_router};

const PASSWORD: &str = "correct-horse-battery-9!";

async fn fresh_app() -> axum::Router {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    build_router(
        db,
        "test v0".into(),
        [99u8; 32],
        ProfileLimits {
            max_aliases_free: 5,
            blob_max_bytes: 1 << 20,
        },
    )
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn req(method: Method, path: &str, bearer: Option<&str>, body: Body) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("{BASE_PATH}{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(body).unwrap()
}

fn json_req(
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    req(method, path, bearer, Body::from(serde_json::to_vec(&body).unwrap()))
}

async fn register_and_login(app: &axum::Router, email: &str) -> String {
    let _ = app
        .clone()
        .oneshot(json_req(
            Method::POST,
            "/auth/register",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    let r = app
        .clone()
        .oneshot(json_req(
            Method::POST,
            "/auth/login",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    let body: LoginResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    body.token
}

#[tokio::test]
async fn defaults_are_security_on_profile_on_product_off() {
    let app = fresh_app().await;
    let token = register_and_login(&app, "alice@example.org").await;
    let r = app
        .oneshot(req(
            Method::GET,
            "/account/email-preferences",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let prefs: EmailPreferences = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(prefs.security_events, "security_events must default true");
    assert!(prefs.profile_activity, "profile_activity defaults true");
    assert!(!prefs.product_updates, "product_updates defaults false");
}

#[tokio::test]
async fn put_partial_body_only_changes_named_fields() {
    let app = fresh_app().await;
    let token = register_and_login(&app, "alice@example.org").await;
    // Flip product_updates on; profile_activity unchanged.
    let r = app
        .clone()
        .oneshot(json_req(
            Method::PUT,
            "/account/email-preferences",
            Some(&token),
            serde_json::json!({ "product_updates": true }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let prefs: EmailPreferences = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(prefs.security_events);
    assert!(prefs.profile_activity, "left untouched");
    assert!(prefs.product_updates, "flipped to true");
}

#[tokio::test]
async fn put_empty_body_returns_current_state_without_mutation() {
    let app = fresh_app().await;
    let token = register_and_login(&app, "alice@example.org").await;
    // Set a known state first.
    let _ = app
        .clone()
        .oneshot(json_req(
            Method::PUT,
            "/account/email-preferences",
            Some(&token),
            serde_json::json!({ "profile_activity": false, "product_updates": true }),
        ))
        .await
        .unwrap();
    // Empty PATCH body — should be a no-op echo.
    let r = app
        .oneshot(json_req(
            Method::PUT,
            "/account/email-preferences",
            Some(&token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let prefs: EmailPreferences = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(prefs.security_events);
    assert!(!prefs.profile_activity);
    assert!(prefs.product_updates);
}

#[tokio::test]
async fn unauthenticated_requests_are_401() {
    let app = fresh_app().await;
    let r = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/account/email-preferences",
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let r = app
        .oneshot(json_req(
            Method::PUT,
            "/account/email-preferences",
            None,
            serde_json::json!({ "product_updates": true }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn email_preferences_payload_does_not_leak_user_id_or_email() {
    let app = fresh_app().await;
    let token = register_and_login(&app, "leak@example.org").await;
    let r = app
        .oneshot(req(
            Method::GET,
            "/account/email-preferences",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    let raw = body_bytes(r).await;
    let s = std::str::from_utf8(&raw).unwrap().to_lowercase();
    for forbidden in [
        "user_id",
        "leak@example.org",
        "password",
        "argon2",
        "token",
    ] {
        assert!(
            !s.contains(forbidden),
            "/email-preferences leaked `{forbidden}`: `{s}`"
        );
    }
}
