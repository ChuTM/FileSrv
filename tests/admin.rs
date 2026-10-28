mod common;
use common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use serde_json::{json, Value};
use tempfile::TempDir;
use filesrv::build_app;

#[tokio::test]
async fn admin_auth_required_and_create_app() {
    let ctx = new_test_ctx();
    let (s, _) = send(
        &ctx.admin,
        Request::builder()
            .method("POST")
            .uri("/admin/v1/apps")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _) = send(
        &ctx.admin,
        Request::builder()
            .method("POST")
            .uri("/admin/v1/apps")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, v) = json_of(send(&ctx.admin, admin_req("POST", "/admin/v1/apps", json!({"name": "A"}))).await).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["app_secret"].as_str().unwrap().len() >= 32);
    assert!(v["app_key"].as_str().unwrap().starts_with("app_"));

    // Admin routes must NOT be reachable on the public router
    let (s, _) = send(
        &ctx.public,
        Request::builder()
            .method("GET")
            .uri("/admin/v1/apps")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn persistence_across_reopen() {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let (public, admin, db1) = build_app(cfg.clone()).unwrap();
    let ctx1 = TestCtx {
        _dir: TempDir::new().unwrap(),
        cfg: cfg.clone(),
        public,
        admin,
        db: db1,
    };

    let (app_id, key, secret) = create_app_quota(&ctx1.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx1, &key, &secret, "u1", b"persisted-content", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx1, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();
    let _ = app_id;

    // Reopen: brand-new process state, same DB + blob dir
    let (public2, admin2, db2) = build_app(cfg).unwrap();
    let (s, b) = download(
        &TestCtx {
            _dir: TempDir::new().unwrap(),
            cfg: ctx1.cfg.clone(),
            public: public2.clone(),
            admin: admin2.clone(),
            db: db2,
        },
        &token,
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "token must survive restart");
    assert_eq!(b, Bytes::from_static(b"persisted-content"));

    let (s, v) = json_of(
        send(&public2, signed_req(&key, &secret, "GET", "/v1/files", "", Value::Null, &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["files"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn secret_rotation_invalidates_old() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &secret, "GET", "/v1/files", "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = json_of(
        send(&ctx.admin, admin_req("POST", "/admin/v1/apps/1/secret/rotate", Value::Null)).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let new_secret = v["app_secret"].as_str().unwrap().to_string();
    assert_ne!(new_secret, secret);

    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &secret, "GET", "/v1/files", "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &new_secret, "GET", "/v1/files", "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn healthz_and_admin_soft_delete() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let _ = app_id;

    let (s, b) = send(
        &ctx.public,
        Request::builder().method("GET").uri("/healthz").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"OK"));

    let (s, _) = send(&ctx.admin, admin_req("DELETE", "/admin/v1/apps/1", Value::Null)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &secret, "GET", "/v1/files", "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_add_user_list_and_jwt_login() {
    let ctx = new_test_ctx();
    let (app_id, _key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;

    // invalid user_ids are rejected under the same rules as uploads (F4)
    for bad in ["../evil", "a/b", "a\\b", ".."] {
        let (s, v) = json_of(
            send(
                &ctx.admin,
                admin_req("POST", &format!("/admin/v1/apps/{app_id}/users"), json!({ "user_id": bad })),
            )
            .await,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "user_id {bad:?} must be rejected: {v}");
    }
    // unknown app -> 404
    let (s, _) = json_of(
        send(&ctx.admin, admin_req("POST", "/admin/v1/apps/9999/users", json!({ "user_id": "u1" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // add u1 (created), duplicate (already exists)
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("POST", &format!("/admin/v1/apps/{app_id}/users"), json!({ "user_id": "u1" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["created"], json!(true));
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("POST", &format!("/admin/v1/apps/{app_id}/users"), json!({ "user_id": "u1" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["created"], json!(false));

    // list
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("GET", &format!("/admin/v1/apps/{app_id}/users"), Value::Null)).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let users = v["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["user_id"], json!("u1"));

    // an admin-provisioned user can authenticate with a JWT immediately
    let (s, _) = send(
        &ctx.public,
        jwt_req(&secret, app_id, "u1", "GET", "/v1/files", Value::Null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}
