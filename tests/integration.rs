use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tenant_fs_server::config::Config;
use tenant_fs_server::crypto::{self, sha256};
use tenant_fs_server::db::{self, Db};
use tenant_fs_server::storage;
use tenant_fs_server::build_app;
use tower::ServiceExt;
use uuid::Uuid;

struct TestCtx {
    _dir: TempDir,
    cfg: Config,
    public: Router,
    admin: Router,
    db: Db,
}

fn cfg_at(dir: &TempDir) -> Config {
    Config {
        db_path: dir.path().join("fs.db"),
        blob_root: dir.path().join("blobs"),
        admin_token: "test-admin-token".into(),
        server_secret: "test-server-secret".into(),
        public_bind: "0.0.0.0:0".into(),
        admin_bind: "127.0.0.1:0".into(),
        embed_ttl_secs: 1800,
        share_ttl_secs: 300,
        max_batch_acl: 1000,
        trust_xff: false, // secure default: X-Forwarded-For is ignored
        audit_retention_secs: 30 * 86400,
        encrypt_blobs: true,
        soft_delete_grace_secs: 7 * 86400,
        purge_interval_secs: 600,
    }
}

fn new_test_ctx() -> TestCtx {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let (public, admin, db) = build_app(cfg.clone()).unwrap();
    TestCtx {
        _dir: dir,
        cfg,
        public,
        admin,
        db,
    }
}

/// Test context simulating a deployment behind a trusted reverse proxy:
/// X-Forwarded-For is honored (the legitimate use of §5.2).
fn new_test_ctx_trust_xff() -> TestCtx {
    let dir = TempDir::new().unwrap();
    let mut cfg = cfg_at(&dir);
    cfg.trust_xff = true;
    let (public, admin, db) = build_app(cfg.clone()).unwrap();
    TestCtx {
        _dir: dir,
        cfg,
        public,
        admin,
        db,
    }
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

async fn json_of(resp: (StatusCode, Bytes)) -> (StatusCode, Value) {
    let (s, b) = resp;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// App-level signed request (X-App-Key + HMAC + timestamp + nonce + body hash).
fn signed_req_raw(
    app_key: &str,
    secret: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Request<Body> {
    let ts = Config::now().to_string();
    let nonce = format!("n_{}", Uuid::new_v4());
    let bh = sha256(body);
    let canonical = crypto::app_canonical(method, path, query, &bh, &ts, &nonce);
    let sig = crypto::app_signature(secret.as_bytes(), &canonical);
    let uri = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let mut rb = Request::builder()
        .method(method)
        .uri(&uri)
        .header("x-app-key", app_key)
        .header("x-app-signature", sig)
        .header("x-timestamp", ts)
        .header("x-nonce", nonce);
    for (k, v) in extra_headers {
        rb = rb.header(*k, *v);
    }
    rb.body(Body::from(body.to_vec())).unwrap()
}

/// App-level signed request with a JSON body (Value::Null = empty body).
fn signed_req(
    app_key: &str,
    secret: &str,
    method: &str,
    path: &str,
    query: &str,
    body: Value,
    extra_headers: &[(&str, &str)],
) -> Request<Body> {
    let body_bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    signed_req_raw(app_key, secret, method, path, query, &body_bytes, extra_headers)
}

/// User-context JWT request (Authorization: Bearer <jwt>).
fn jwt_req(secret: &str, app_id: i64, user: &str, method: &str, path: &str, body: Value) -> Request<Body> {
    let jwt = crypto::jwt_encode(
        secret.as_bytes(),
        &format!("app:{app_id}"),
        user,
        Config::now() + 3600,
    );
    let body_bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {jwt}"))
        .body(Body::from(body_bytes))
        .unwrap()
}

fn admin_req(method: &str, path: &str, body: Value) -> Request<Body> {
    let body_bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer test-admin-token")
        .body(Body::from(body_bytes))
        .unwrap()
}

async fn create_app_quota(admin: &Router, name: &str, quota: i64, max_payload: i64) -> (i64, String, String) {
    let (s, v) = json_of(
        send(
            admin,
            admin_req(
                "POST",
                "/admin/v1/apps",
                json!({ "name": name, "quota_bytes": quota, "max_payload_bytes": max_payload }),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create app: {v}");
    (
        v["app_id"].as_i64().unwrap(),
        v["app_key"].as_str().unwrap().to_string(),
        v["app_secret"].as_str().unwrap().to_string(),
    )
}

async fn upload_bytes(
    ctx: &TestCtx,
    app_key: &str,
    secret: &str,
    user: &str,
    data: &[u8],
    query: &str,
) -> (StatusCode, Value) {
    json_of(
        send(
            &ctx.public,
            signed_req_raw(
                app_key,
                secret,
                "POST",
                "/v1/upload",
                query,
                data,
                &[("x-user-id", user)],
            ),
        )
        .await,
    )
    .await
}

async fn generate_link(ctx: &TestCtx, app_key: &str, secret: &str, file_id: i64, extra: Value) -> (StatusCode, Value) {
    let mut body = json!({ "file_id": file_id });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            body[k] = v;
        }
    }
    json_of(
        send(
            &ctx.public,
            signed_req(app_key, secret, "POST", "/v1/links/generate", "", body, &[]),
        )
        .await,
    )
    .await
}

async fn download(ctx: &TestCtx, token: &str, headers: &[(&str, &str)]) -> (StatusCode, Bytes) {
    let mut rb = Request::builder().method("GET").uri(format!("/v1/download/{token}"));
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    send(&ctx.public, rb.body(Body::empty()).unwrap()).await
}

// ---------------- Tests ----------------

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
async fn upload_download_embed_idempotent_revoke() {
    let ctx = new_test_ctx();
    let (_app_id, app_key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;

    let (s, v) = upload_bytes(&ctx, &app_key, &secret, "u1", b"hello tenant", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let file_id = v["file_id"].as_i64().unwrap();
    assert_eq!(v["owner"], json!("u1"));

    let (s, v) = generate_link(&ctx, &app_key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let token1 = v["token"].as_str().unwrap().to_string();
    assert_eq!(v["reused"], json!(false));

    // Idempotent within the fixed window: same token, reused=true, TTL NOT extended
    let (s, v) = generate_link(&ctx, &app_key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["token"], json!(token1));
    assert_eq!(v["reused"], json!(true));

    let (s, b) = download(&ctx, &token1, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"hello tenant"));

    // Revoke -> immediately invalid
    let (s, _) = json_of(
        send(
            &ctx.public,
            signed_req(&app_key, &secret, "POST", "/v1/tokens/revoke", "", json!({"token": token1}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = download(&ctx, &token1, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Next generate mints a NEW token
    let (s, v) = generate_link(&ctx, &app_key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["reused"], json!(false));
    let token2 = v["token"].as_str().unwrap().to_string();
    assert_ne!(token1, token2);
    let (s, _) = download(&ctx, &token2, &[]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn cross_tenant_isolation() {
    let ctx = new_test_ctx();
    let (_a1, key_a, secret_a) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (_a2, key_b, secret_b) = create_app_quota(&ctx.admin, "B", 1 << 20, 1 << 20).await;

    let (s, v) = upload_bytes(&ctx, &key_a, &secret_a, "u_a", b"app-a-secret", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_a = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx, &key_a, &secret_a, file_a, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token_a = v["token"].as_str().unwrap().to_string();

    // App B cannot generate a link for A's file (404 hides existence)
    let (s, v) = generate_link(&ctx, &key_b, &secret_b, file_a, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");

    // App B cannot read A's file meta
    let (s, _) = send(
        &ctx.public,
        signed_req(&key_b, &secret_b, "GET", &format!("/v1/files/{file_a}"), "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // App B sees an empty list (WHERE app_id = identity)
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key_b, &secret_b, "GET", "/v1/files", "", Value::Null, &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["files"].as_array().unwrap().len(), 0);

    // A's token still works for A
    let (s, b) = download(&ctx, &token_a, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"app-a-secret"));
}

#[tokio::test]
async fn quota_enforced() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "Q", 100, 100).await;

    let (s, _) = upload_bytes(&ctx, &key, &secret, "u1", b"0123456789", "").await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u1", b"abcdefghij", "").await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", &[b'x'; 90], "").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"]["code"], json!("quota_exceeded"));

    let (s, v) = json_of(
        send(&ctx.admin, admin_req("GET", "/admin/v1/apps/1/usage", Value::Null)).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["usage_bytes"], json!(20));
}

#[tokio::test]
async fn user_acl_and_folder_inheritance_deny_wins() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;

    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"file-of-u1", "").await;
    assert_eq!(s, StatusCode::OK);
    let f1 = v["file_id"].as_i64().unwrap();
    // register u2
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u2", b"x", "").await;
    assert_eq!(s, StatusCode::OK);

    // owner u1 can read
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u1", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
    // u2 cannot
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // u2 cannot generate a link either
    let (s, _) = json_of(
        send(
            &ctx.public,
            jwt_req(&secret, app_id, "u2", "POST", "/v1/links/generate", json!({"file_id": f1})),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Create folder, grant read to u2, upload a file inside
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/folders", "", json!({"name": "invoices"}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let folder_id = v["folder_id"].as_i64().unwrap();

    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"invoice-content", &format!("folder_id={folder_id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let f2 = v["file_id"].as_i64().unwrap();

    // u2 cannot read yet (no ACL anywhere)
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // grant folder read to u2
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // u2 can now read f2 via folder inheritance
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK, "u2 should read via folder inheritance");

    // deny wins: add deny u2 on the folder -> u2 locked out despite allow
    let (s, _) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": [], "deny": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "inherited deny must win");
}

#[tokio::test]
async fn inherited_folder_deny_beats_file_explicit_acl() {
    // Regression for test report §5.1 (HIGH): a file-level explicit allow must
    // NOT override a deny inherited from the folder chain ("档案盖不掉继承的 deny").
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u2", b"x", "").await;
    assert_eq!(s, StatusCode::OK);

    // folder with read u2 AND deny u2
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/folders", "", json!({"name": "locked"}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let folder_id = v["folder_id"].as_i64().unwrap();
    let (s, _) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": ["u2"], "deny": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // u1 uploads into the folder
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"confidential", &format!("folder_id={folder_id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let f2 = v["file_id"].as_i64().unwrap();
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "u2 denied before file-level grant");

    // THE VULNERABILITY: file-level explicit allow for u2 must still be blocked
    // by the inherited folder deny.
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "POST",
                "/v1/files/batch/acl",
                "",
                json!({"file_ids": [f2], "action": "read", "add": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["updated"].as_i64().unwrap_or(0), 1);

    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "file explicit ACL must not override inherited folder deny");

    // owner u1 keeps access
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u1", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
}

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
async fn range_and_etag() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"0123456789", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    let (s, b) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"0123456789"));

    let (s, b) = download(&ctx, &token, &[("range", "bytes=2-5")]).await;
    assert_eq!(s, StatusCode::PARTIAL_CONTENT);
    assert_eq!(b, Bytes::from_static(b"2345"));

    let (s, b) = download(&ctx, &token, &[("range", "bytes=-3")]).await;
    assert_eq!(s, StatusCode::PARTIAL_CONTENT);
    assert_eq!(b, Bytes::from_static(b"789"));

    let (s, _) = download(&ctx, &token, &[("range", "bytes=99-200")]).await;
    assert_eq!(s, StatusCode::RANGE_NOT_SATISFIABLE);

    let etag = format!("\"sha256-{}\"", sha256(b"0123456789"));
    let (s, _) = download(&ctx, &token, &[("if-none-match", &etag)]).await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
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
async fn delete_file_frees_usage_and_tokens() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"delete-me", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &secret, "DELETE", &format!("/v1/files/{file_id}"), "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, _) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, v) = json_of(send(&ctx.admin, admin_req("GET", "/admin/v1/apps/1/usage", Value::Null)).await).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["usage_bytes"], json!(0));
}

#[tokio::test]
async fn batch_acl_app_level_only() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"f1", "").await;
    assert_eq!(s, StatusCode::OK);
    let f1 = v["file_id"].as_i64().unwrap();
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"f2", "").await;
    assert_eq!(s, StatusCode::OK);
    let f2 = v["file_id"].as_i64().unwrap();
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u3", b"z", "").await;
    assert_eq!(s, StatusCode::OK);

    // user JWT cannot batch
    let (s, _) = send(
        &ctx.public,
        jwt_req(
            &secret,
            app_id,
            "u1",
            "POST",
            "/v1/files/batch/acl",
            json!({"file_ids": [f1], "action": "read", "add": ["u3"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // app-level batch works and is scoped to its own tenant
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "POST",
                "/v1/files/batch/acl",
                "",
                json!({"file_ids": [f1, f2], "action": "read", "add": ["u3"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["updated"], json!(2));

    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u3", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u3", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn payload_limit_enforced() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "L", 1 << 20, 5).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"1234567890", "").await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
}

#[tokio::test]
async fn export_creates_tar() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u1", b"export-me", "").await;
    assert_eq!(s, StatusCode::OK);
    let _ = app_id;

    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/apps/export", "", Value::Null, &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let job_id = v["job_id"].as_i64().unwrap();

    let mut ready = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (s, v) = json_of(
            send(
                &ctx.public,
                signed_req(&key, &secret, "GET", &format!("/v1/apps/exports/{job_id}"), "", Value::Null, &[]),
            )
            .await,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        if v["status"] == json!("ready") {
            ready = true;
            break;
        }
    }
    assert!(ready, "export job should become ready");

    let (s, b) = send(
        &ctx.public,
        signed_req(&key, &secret, "GET", &format!("/v1/apps/exports/{job_id}/download"), "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b.is_empty());
    assert!(b.windows(5).any(|w| w == b"ustar"), "should be a tar archive");
}

#[tokio::test]
async fn share_token_with_ip_binding() {
    // Trusted-proxy deployment: XFF is honored, IP binding works as designed.
    let ctx = new_test_ctx_trust_xff();
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
        json!({"scope": "share", "allowed_ip": "203.0.113.45"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    let (s, b) = download(&ctx, &token, &[("x-forwarded-for", "203.0.113.45")]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"ip-bound"));

    let (s, _) = download(&ctx, &token, &[("x-forwarded-for", "6.6.6.6")]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
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

// ---------------- New: blob envelope encryption ----------------

#[tokio::test]
async fn encrypted_blob_read_old_write_new() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "Enc", 1 << 20, 1 << 20).await;
    let content = b"envelope-payload-bytes";

    // Write-new: a fresh upload lands on disk in the envelope format
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", content, "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let file_id = v["file_id"].as_i64().unwrap();
    let uuid = v["storage_uuid"].as_str().unwrap().to_string();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    // On-disk raw blob carries the TSFS magic + version
    let (blob_path, raw) = {
        let conn = ctx.db.lock().unwrap();
        let f = db::file_by_id(&conn, file_id).unwrap().unwrap();
        let raw = storage::locate_blob(&ctx.cfg, app_id, &f.storage_uuid, f.blob_path.as_deref()).unwrap();
        (f.blob_path.clone(), raw)
    };
    let on_disk = std::fs::read(&raw).unwrap();
    assert!(crypto::looks_like_encrypted_blob(&on_disk[..5]), "new blob must be envelope-encrypted");
    assert!(!on_disk.windows(content.len()).any(|w| w == content), "plaintext must not appear verbatim on disk");

    // Read-new: download transparently decrypts (via the dec_cache materialization)
    let (s, b) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(content));

    // Read-old: simulate a legacy plaintext blob from before encryption.
    // Replace the on-disk blob with raw plaintext, drop the dec_cache entry,
    // and confirm the legacy path still serves it.
    let cache = ctx.cfg.blob_root.join("dec_cache").join(&uuid);
    let _ = std::fs::remove_file(&cache);
    std::fs::write(&raw, content).unwrap();
    let (s, b) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK, "legacy plaintext blob must still download");
    assert_eq!(b, Bytes::from_static(content));

    // Re-encrypt in place via the one-shot migration, then download again
    let _ = blob_path;
    assert_eq!(storage::migrate_plaintext_blobs(&ctx.cfg).unwrap(), 1);
    let on_disk = std::fs::read(&raw).unwrap();
    assert!(crypto::looks_like_encrypted_blob(&on_disk[..5]));
    let _ = std::fs::remove_file(&cache);
    let (s, b) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(content));
}

// ---------------- New: soft-delete grace lifecycle ----------------

#[tokio::test]
async fn soft_delete_lifecycle_grace_then_purge() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "Soft", 1 << 20, 1 << 20).await;

    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"grace-period-content", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let uuid = v["storage_uuid"].as_str().unwrap().to_string();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();
    // Warm the download path (materializes the decrypted cache entry)
    let (s, b) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, Bytes::from_static(b"grace-period-content"));

    // DELETE -> tombstone
    let (s, _) = send(
        &ctx.public,
        signed_req(&key, &secret, "DELETE", &format!("/v1/files/{file_id}"), "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Token/link instant failure; usage rolled back; listing excludes it
    let (s, _) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "GET", "/v1/files", "", Value::Null, &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["files"].as_array().unwrap().is_empty());
    let (s, v) = json_of(send(&ctx.admin, admin_req("GET", "/admin/v1/apps/1/usage", Value::Null)).await).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["usage_bytes"], json!(0));

    // Within the grace window the blob file must STILL be on disk (no hard delete)
    let raw = {
        let conn = ctx.db.lock().unwrap();
        let f = db::file_by_id(&conn, file_id).unwrap().unwrap();
        storage::locate_blob(&ctx.cfg, app_id, &f.storage_uuid, f.blob_path.as_deref()).unwrap()
    };
    assert!(raw.exists(), "blob must survive the grace window");
    let cache = ctx.cfg.blob_root.join("dec_cache").join(&uuid);
    assert!(cache.exists(), "decrypted cache should still exist");

    // Purge with grace=0 (cutoff slightly in the future absorbs the 1s clock
    // granularity between DELETE and this call; the time-window semantics are
    // covered by the db::purge_expired_tombstones unit test).
    let conn = ctx.db.lock().unwrap();
    let cutoff = Config::now() + 10;
    let due = db::purge_expired_tombstones(&conn, cutoff).unwrap();
    assert_eq!(due.len(), 1);
    drop(conn);
    storage::remove_blob(&ctx.cfg, app_id, &uuid, None);
    assert!(!raw.exists());
    assert!(!cache.exists());
    let conn = ctx.db.lock().unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM files WHERE id=?1", [file_id], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "row physically purged");
}

// ---------------- API-layer: backup, chunked upload, rate limit, HEAD, zip, idempotency, TTL ----------------

use std::sync::{Arc, Mutex};
use tenant_fs_server::config::Ops;
use tenant_fs_server::state::AppState;

async fn send_full(
    router: &Router,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

/// Build a router pair on a temp DB with a hand-tuned rate-limit budget and
/// backup root (env-driven defaults are not reachable from TestCtx).
fn custom_routers(cfg: &Config, ops: Ops, rate_limit: u32) -> (Router, Router) {
    let conn = db::open_db(&cfg.db_path).unwrap();
    db::migrate(&conn).unwrap();
    let db: db::Db = Arc::new(Mutex::new(conn));
    let state = AppState {
        cfg: cfg.clone(),
        ops,
        db,
        ratelimit: Arc::new(tenant_fs_server::ratelimit::RateLimiter::new(rate_limit, 1000)),
        idem: Arc::new(tenant_fs_server::idem::IdemStore::new(3600, 1000)),
    };
    (
        tenant_fs_server::routes::public_router(state.clone()),
        tenant_fs_server::routes::admin_router(state),
    )
}

fn test_ops(dir: &TempDir) -> Ops {
    Ops {
        backup_root: dir.path().join("backups"),
        backup_retention: 7,
        backup_schedule_secs: 0,
        chunk_ttl_secs: 3600,
        rate_limit_per_min: 120,
        rate_limit_max_entries: 10000,
        idem_window_secs: 3600,
        idem_max_entries: 10000,
        export_ttl_secs: 86400,
    }
}

#[tokio::test]
async fn chunked_upload_flow_and_unauth_rejected() {
    let ctx = new_test_ctx();
    let (_, key, secret) = create_app_quota(&ctx.admin, "cu", 1 << 20, 1 << 20).await;

    // init
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/upload/init", "", json!({"total_size": 11}), &[("x-user-id", "u1")]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "init: {v}");
    let up_id = v["upload_id"].as_str().unwrap().to_string();
    assert!(up_id.len() >= 32, "upload_id must be long random");

    // chunk 1 (5 bytes) at offset 0
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req_raw(&key, &secret, "PUT", &format!("/v1/upload/{up_id}"), "", b"hello", &[("x-chunk-offset", "0")]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "chunk1: {v}");
    assert_eq!(v["received_size"], json!(5));

    // chunk 2 (6 bytes) at offset 5
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req_raw(&key, &secret, "PUT", &format!("/v1/upload/{up_id}"), "", b" world", &[("x-chunk-offset", "5")]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "chunk2: {v}");
    assert_eq!(v["received_size"], json!(11));

    // out-of-order chunk rejected with resume hint
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req_raw(&key, &secret, "PUT", &format!("/v1/upload/{up_id}"), "", b"ZZ", &[("x-chunk-offset", "9")]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "gap: {v}");

    // finalize
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", &format!("/v1/upload/{up_id}/finalize"), "", Value::Null, &[("x-user-id", "u1")]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "finalize: {v}");
    assert_eq!(v["size"], json!(11));
    assert_eq!(v["sha256"], json!(sha256(b"hello world")));

    // roundtrip content matches (encrypted through storage layer)
    let file_id = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK, "gen: {v}");
    let token = v["token"].as_str().unwrap().to_string();
    let (s, body) = download(&ctx, &token, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(&body[..], b"hello world");

    // unauthenticated chunk upload rejected before streaming
    let (s, _) = send(
        &ctx.public,
        Request::builder()
            .method("PUT")
            .uri(format!("/v1/upload/{up_id}"))
            .header("x-chunk-offset", "11")
            .body(Body::from("x"))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn head_download_headers_and_404() {
    let ctx = new_test_ctx();
    let (_, key, secret) = create_app_quota(&ctx.admin, "hd", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"head-body-12345", "").await;
    assert_eq!(s, StatusCode::OK);
    let file_id = v["file_id"].as_i64().unwrap();
    let (s, v) = generate_link(&ctx, &key, &secret, file_id, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    // HEAD: 200 + Content-Length + empty body
    let (s, headers, body) = send_full(
        &ctx.public,
        Request::builder()
            .method("HEAD")
            .uri(format!("/v1/download/{token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(headers.get("content-length").unwrap().to_str().unwrap(), "15");
    assert!(body.is_empty(), "HEAD must have no body");

    // unknown token HEAD -> 404 (same semantics as GET)
    let (s, _, _) = send_full(
        &ctx.public,
        Request::builder()
            .method("HEAD")
            .uri("/v1/download/nope")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn zip_export_organized_by_user() {
    let ctx = new_test_ctx();
    let (_, key, secret) = create_app_quota(&ctx.admin, "ze", 1 << 20, 1 << 20).await;
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u1", b"AAA", "").await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u2", b"BBBB", "").await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/apps/export", "", json!({"format": "zip"}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "export: {v}");
    let job_id = v["job_id"].as_i64().unwrap();

    let mut ready = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (s, v) = json_of(
            send(&ctx.public, signed_req(&key, &secret, "GET", &format!("/v1/apps/exports/{job_id}"), "", Value::Null, &[])).await,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        if v["status"] == json!("ready") {
            ready = true;
            break;
        }
    }
    assert!(ready);

    let (s, headers, body) = send_full(
        &ctx.public,
        signed_req(&key, &secret, "GET", &format!("/v1/apps/exports/{job_id}/download"), "", Value::Null, &[]),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(headers.get("content-type").unwrap().to_str().unwrap().contains("zip"));

    // entries organized per user
    use zip::read::ZipArchive;
    let mut za = ZipArchive::new(std::io::Cursor::new(body)).unwrap();
    let names: Vec<String> = (0..za.len()).map(|i| za.by_index(i).unwrap().name().to_string()).collect();
    assert!(names.iter().any(|n| n.starts_with("files/u1/")), "u1 missing: {names:?}");
    assert!(names.iter().any(|n| n.starts_with("files/u2/")), "u2 missing: {names:?}");
}

#[tokio::test]
async fn idempotency_key_returns_same_result() {
    let ctx = new_test_ctx();
    let (_, key, secret) = create_app_quota(&ctx.admin, "idem", 1 << 20, 1 << 20).await;

    let r1 = signed_req_raw(&key, &secret, "POST", "/v1/upload", "", b"IDEM-BODY", &[("x-user-id", "u1"), ("idempotency-key", "key-1")]);
    let (s, v1) = json_of(send(&ctx.public, r1).await).await;
    assert_eq!(s, StatusCode::OK, "first: {v1}");

    let r2 = signed_req_raw(&key, &secret, "POST", "/v1/upload", "", b"IDEM-BODY", &[("x-user-id", "u1"), ("idempotency-key", "key-1")]);
    let (s, v2) = json_of(send(&ctx.public, r2).await).await;
    assert_eq!(s, StatusCode::OK, "retry: {v2}");
    assert_eq!(v1["file_id"], v2["file_id"], "same idempotent result");

    // only one row persisted for this app
    let conn = ctx.db.lock().unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM files WHERE user_id='u1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "retry must not create a second file");
}

#[tokio::test]
async fn rate_limit_429_carries_retry_after() {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let ops = test_ops(&dir);
    let (public, admin) = custom_routers(&cfg, ops, 1); // single request per window
    let (_, key, secret) = create_app_quota(&admin, "rl", 1 << 20, 1 << 20).await;

    // first request consumes the single slot (fails validation, but passes the gate)
    let (s, _, _) = send_full(
        &public,
        signed_req(&key, &secret, "POST", "/v1/links/generate", "", json!({"file_id": 1}), &[]),
    )
    .await;
    assert!(s != StatusCode::TOO_MANY_REQUESTS, "first call must not be limited: {s}");

    // second request: 429 + Retry-After
    let (s, headers, body) = send_full(
        &public,
        signed_req(&key, &secret, "POST", "/v1/links/generate", "", json!({"file_id": 1}), &[]),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers.get("retry-after").unwrap().to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["code"], json!("rate_limited"));
}

#[tokio::test]
async fn backup_admin_api_run_list_detail_config() {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let ops = test_ops(&dir);
    let (public, admin) = custom_routers(&cfg, ops, 1000);
    let (_, key, secret) = create_app_quota(&admin, "bk", 1 << 20, 1 << 20).await;
    let (s, _) = json_of(
        send(&public, signed_req_raw(&key, &secret, "POST", "/v1/upload", "", b"blob-1", &[("x-user-id", "u1")])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // run
    let (s, v) = json_of(send(&admin, admin_req("POST", "/admin/v1/backups/run", Value::Null)).await).await;
    assert_eq!(s, StatusCode::OK, "run: {v}");
    assert_eq!(v["status"], json!("ready"));
    assert!(v["size"].as_i64().unwrap() > 0);
    let files = v["files"].as_array().unwrap();
    assert!(files.iter().any(|f| f["name"] == json!("db.sqlite")));
    assert!(files.iter().any(|f| f["name"] == json!("blobs.tar")));
    let sha = files.iter().find(|f| f["name"] == json!("blobs.tar")).unwrap()["sha256"].as_str().unwrap().to_string();
    let backup_dir = dir.path().join("backups/default").join(v["backup_id"].as_str().unwrap());

    // manifest sha256 matches the on-disk artifact (dir named by random id)
    let on_disk = std::fs::read(backup_dir.join("blobs.tar")).unwrap();
    assert_eq!(sha256(&on_disk), sha);

    // list
    let (s, v) = json_of(send(&admin, admin_req("GET", "/admin/v1/backups", Value::Null)).await).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["backups"].as_array().unwrap().len(), 1);

    // detail (manifest parsed)
    let (s, v) = json_of(send(&admin, admin_req("GET", "/admin/v1/backups/1", Value::Null)).await).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["manifest"].is_object(), "detail: {v}");

    // unknown id -> 404 hidden
    let (s, _) = send(&admin, admin_req("GET", "/admin/v1/backups/9999", Value::Null)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // config PATCH
    let (s, v) = json_of(
        send(&admin, admin_req("PATCH", "/admin/v1/backups/config", json!({"retention": 3, "target": "t1", "schedule": 0}))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "config: {v}");
    assert_eq!(v["retention"], json!(3));
    assert_eq!(v["target"], json!("t1"));

    // path escape rejected
    let (s, _) = send(&admin, admin_req("PATCH", "/admin/v1/backups/config", json!({"target": "../esc"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // backup artifacts contain no key material (server secret)
    let tar = std::fs::read(backup_dir.join("blobs.tar")).unwrap();
    assert!(!tar.windows(b"test-server-secret".len()).any(|w| w == b"test-server-secret"));
}

#[tokio::test]
async fn export_ttl_and_upload_job_prune() {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let conn = db::open_db(&cfg.db_path).unwrap();
    db::migrate(&conn).unwrap();
    let now = Config::now();

    conn.execute(
        "INSERT INTO export_jobs(app_id,status,created_at,done_at,size,path) VALUES(1,'ready',?1,?2,5,'/tmp/ttl.tar')",
        [now - 200, now - 200],
    )
    .unwrap();
    let stale = db::prune_expired_exports(&conn, now - 100).unwrap();
    assert_eq!(stale, vec!["/tmp/ttl.tar".to_string()]);

    conn.execute(
        "INSERT INTO upload_jobs(upload_id,app_id,user_id,total_size,received_size,status,path,created_at,expires_at)
         VALUES('up_x',1,'u1',10,0,'open','/tmp/up.part',?1,?2)",
        [now, now - 1],
    )
    .unwrap();
    let partials = db::prune_expired_uploads(&conn, now).unwrap();
    assert_eq!(partials, vec!["/tmp/up.part".to_string()]);
}
