mod common;
use common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use serde_json::{json, Value};
use filesrv::config::Config;
use filesrv::crypto::{self, sha256};

#[tokio::test]
async fn replay_tamper_stale_denied() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let _ = app_id;

    let make = |nonce: &str, sig: String, ts: String| {
        Request::builder()
            .method("GET")
            .uri("/v1/files")
            .header("x-app-key", &key)
            .header("x-app-signature", sig)
            .header("x-timestamp", ts)
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap()
    };
    let mk_sig = |ts: &str, nonce: &str| {
        let bh = sha256(b"");
        crypto::app_signature(
            secret.as_bytes(),
            &crypto::app_canonical("GET", "/v1/files", "", &bh, ts, nonce),
        )
    };

    // first use with nonce N1 -> ok
    let ts = Config::now().to_string();
    let (s, _) = send(&ctx.public, make("rp-1", mk_sig(&ts, "rp-1"), ts.clone())).await;
    assert_eq!(s, StatusCode::OK);
    // replay same nonce -> 401
    let (s, v) = json_of(send(&ctx.public, make("rp-1", mk_sig(&ts, "rp-1"), ts.clone())).await).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    // tampered signature (fresh nonce, bad sig) -> 401
    let (s, _) = send(&ctx.public, make("rp-2", "deadbeef".into(), ts.clone())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // stale timestamp -> 401
    let stale = (Config::now() - 10_000).to_string();
    let (s, _) = send(&ctx.public, make("rp-3", mk_sig(&stale, "rp-3"), stale)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_and_unregistered_user_jwt_denied() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u1", b"y", "").await;
    assert_eq!(s, StatusCode::OK);

    // JWT signed with wrong secret -> 401
    let jwt_bad = crypto::jwt_encode(b"wrong-secret", &format!("app:{app_id}"), "u1", Config::now() + 3600);
    let (s, _) = send(
        &ctx.public,
        Request::builder()
            .method("GET")
            .uri("/v1/files")
            .header("authorization", format!("Bearer {jwt_bad}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // JWT for unregistered user (correct secret) -> 401
    let jwt_unknown = crypto::jwt_encode(secret.as_bytes(), &format!("app:{app_id}"), "u_ghost", Config::now() + 3600);
    let (s, _) = send(
        &ctx.public,
        Request::builder()
            .method("GET")
            .uri("/v1/files")
            .header("authorization", format!("Bearer {jwt_unknown}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_signature_headers_rejected_before_streaming() {
    // §5.3: an app-level upload that claims an app key but lacks the HMAC
    // headers is rejected immediately — no body buffering happens.
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let _ = (key, secret);
    let _ = app_id;
    let (s, b) = send(
        &ctx.public,
        Request::builder()
            .method("POST")
            .uri("/v1/upload")
            .header("x-app-key", "missing")
            .header("x-user-id", "u1")
            .body(Body::from(Bytes::from_static(b"data")))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, v) = json_of((s, b)).await;
    assert!(v["error"]["message"].as_str().unwrap().contains("Missing signature header"));
}

#[tokio::test]
async fn xff_spoof_is_ignored_by_default() {
    // Secure default (§5.2): the server does NOT trust X-Forwarded-For, so a
    // client-sent header cannot satisfy an IP-bound share token.
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"ip-bound", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let _ = app_id;

    let (s, v) = generate_link(
        &ctx,
        &key,
        &secret,
        file_id,
        "u1",
        json!({"scope": "share", "allowed_ip": "203.0.113.45"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    // The spoofed header must NOT grant access: peer IP (empty here, no
    // connect info in one-shot tests) does not match the bound IP.
    let (s, _) = download(&ctx, &token, &[("x-forwarded-for", "203.0.113.45")]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
