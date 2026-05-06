// Integration tests for the TOTP enroll / verify / login / disable flow
// + recovery codes. Drives the router via `tower::ServiceExt::oneshot`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zz_drop_core::api::{
    BASE_PATH, LoginResponse, LoginTotpChallenge, TotpEnrollResponse,
};
use zz_drop_server_minimal::auth::totp;
use zz_drop_server_minimal::routes::ProfileLimits;
use zz_drop_server_minimal::{Database, build_router};

const PASSWORD: &str = "correct-horse-battery-9!";

async fn fresh_app() -> axum::Router {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    build_router(
        db,
        "test v0".into(),
        [11u8; 32],
        ProfileLimits {
            max_aliases_free: 5,
            blob_max_bytes: 1 << 20,
        },
    )
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn json_req_authed(
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("{BASE_PATH}{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

async fn register(app: &axum::Router, email: &str) {
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/register",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "register failed");
}

async fn login_no_totp(app: &axum::Router, email: &str) -> String {
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/login",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: LoginResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    body.token
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn seed_from_b32(b32: &str) -> Vec<u8> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, b32)
        .expect("seed_base32 decodes")
}

async fn enroll_and_activate(app: &axum::Router, token: &str) -> TotpEnrollResponse {
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/enroll",
            Some(token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let enroll: TotpEnrollResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    let seed = seed_from_b32(&enroll.secret_base32);
    let code = totp::code_at(&seed, now_unix()).unwrap();
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/verify",
            Some(token),
            serde_json::json!({ "code": code }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "verify activation failed");
    enroll
}

#[tokio::test]
async fn enroll_returns_otpauth_uri_secret_and_ten_recovery_codes() {
    let app = fresh_app().await;
    register(&app, "alice@example.org").await;
    let token = login_no_totp(&app, "alice@example.org").await;

    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/enroll",
            Some(&token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let enroll: TotpEnrollResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(enroll.otpauth_uri.starts_with("otpauth://totp/"));
    assert!(!enroll.secret_base32.is_empty());
    assert_eq!(enroll.recovery_codes.len(), 10);
    let mut set = std::collections::HashSet::new();
    for c in &enroll.recovery_codes {
        assert!(set.insert(c.clone()), "duplicate recovery code");
    }
}

#[tokio::test]
async fn verify_with_wrong_code_does_not_activate() {
    let app = fresh_app().await;
    register(&app, "bob@example.org").await;
    let token = login_no_totp(&app, "bob@example.org").await;
    let _ = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/enroll",
            Some(&token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/verify",
            Some(&token),
            serde_json::json!({ "code": "000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // Login should still be single-step (TOTP not active yet).
    let _ = login_no_totp(&app, "bob@example.org").await;
}

#[tokio::test]
async fn login_after_activation_requires_two_steps() {
    let app = fresh_app().await;
    register(&app, "carol@example.org").await;
    let token = login_no_totp(&app, "carol@example.org").await;
    let enroll = enroll_and_activate(&app, &token).await;
    let seed = seed_from_b32(&enroll.secret_base32);

    // Step 1: password → totp_required
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/login",
            None,
            serde_json::json!({ "email": "carol@example.org", "password": PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let challenge: LoginTotpChallenge =
        serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(challenge.totp_required);
    assert!(!challenge.challenge.is_empty());

    // Step 2: challenge + valid code → session
    let code = totp::code_at(&seed, now_unix()).unwrap();
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/login",
            None,
            serde_json::json!({ "challenge": challenge.challenge, "code": code }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let session: LoginResponse = serde_json::from_slice(&body_bytes(r).await).unwrap();
    assert!(!session.token.is_empty());
}

#[tokio::test]
async fn recovery_code_consumes_and_completes_login() {
    let app = fresh_app().await;
    register(&app, "dave@example.org").await;
    let token = login_no_totp(&app, "dave@example.org").await;
    let enroll = enroll_and_activate(&app, &token).await;
    let recovery = enroll.recovery_codes[0].clone();

    // Step 1
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/login",
            None,
            serde_json::json!({ "email": "dave@example.org", "password": PASSWORD }),
        ))
        .await
        .unwrap();
    let challenge: LoginTotpChallenge =
        serde_json::from_slice(&body_bytes(r).await).unwrap();

    // Step 2 with recovery code
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/login",
            None,
            serde_json::json!({ "challenge": challenge.challenge, "code": recovery }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "recovery code login failed");

    // Same recovery code can't be reused: re-login + re-try
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/login",
            None,
            serde_json::json!({ "email": "dave@example.org", "password": PASSWORD }),
        ))
        .await
        .unwrap();
    let challenge2: LoginTotpChallenge =
        serde_json::from_slice(&body_bytes(r).await).unwrap();
    let recovery2 = enroll.recovery_codes[0].clone();
    let r = app
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/login",
            None,
            serde_json::json!({ "challenge": challenge2.challenge, "code": recovery2 }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disable_requires_password_and_totp_or_recovery() {
    let app = fresh_app().await;
    register(&app, "erin@example.org").await;
    let token = login_no_totp(&app, "erin@example.org").await;
    let enroll = enroll_and_activate(&app, &token).await;
    let seed = seed_from_b32(&enroll.secret_base32);

    // Disable with wrong password → 401
    let code = totp::code_at(&seed, now_unix()).unwrap();
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/disable",
            Some(&token),
            serde_json::json!({ "password": "wrong-password-1234567", "code": code }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // Disable with right password + valid TOTP → 204
    let code = totp::code_at(&seed, now_unix()).unwrap();
    let r = app
        .clone()
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/disable",
            Some(&token),
            serde_json::json!({ "password": PASSWORD, "code": code }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Subsequent login is single-step again
    let _ = login_no_totp(&app, "erin@example.org").await;
}

#[tokio::test]
async fn enroll_without_bearer_token_is_unauthorized() {
    let app = fresh_app().await;
    let r = app
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/enroll",
            None,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_response_does_not_leak_seed_or_master_key() {
    let app = fresh_app().await;
    register(&app, "leak@example.org").await;
    let token = login_no_totp(&app, "leak@example.org").await;
    let r = app
        .oneshot(json_req_authed(
            Method::POST,
            "/auth/totp/enroll",
            Some(&token),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let raw = body_bytes(r).await;
    let s = std::str::from_utf8(&raw).unwrap().to_lowercase();
    for forbidden in ["password", "argon2", "ciphertext", "nonce", "master"] {
        assert!(!s.contains(forbidden), "/enroll leaked `{forbidden}`");
    }
    // The plain-text recovery codes ARE intentionally in the response
    // (shown once to the user), so we only forbid implementation tells.
}
