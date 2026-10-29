use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use filesrv::build_app;
use filesrv::config::{Config, Ops};
use filesrv::crypto::{self, sha256};
use filesrv::db::{self, Db};
use filesrv::state::AppState;
use tower::ServiceExt;
use uuid::Uuid;

pub struct TestCtx {
    pub _dir: TempDir,
    pub cfg: Config,
    pub public: Router,
    pub admin: Router,
    pub db: Db,
}

pub fn cfg_at(dir: &TempDir) -> Config {
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
        allow_non_loopback_admin: false,
    }
}

pub fn new_test_ctx() -> TestCtx {
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
pub fn new_test_ctx_trust_xff() -> TestCtx {
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

pub async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

pub async fn json_of(resp: (StatusCode, Bytes)) -> (StatusCode, Value) {
    let (s, b) = resp;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// App-level signed request (X-App-Key + HMAC + timestamp + nonce + body hash).
pub fn signed_req_raw(
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
pub fn signed_req(
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
pub fn jwt_req(secret: &str, app_id: i64, user: &str, method: &str, path: &str, body: Value) -> Request<Body> {
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

pub fn admin_req(method: &str, path: &str, body: Value) -> Request<Body> {
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

pub async fn create_app_quota(admin: &Router, name: &str, quota: i64, max_payload: i64) -> (i64, String, String) {
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

pub async fn upload_bytes(
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

pub async fn generate_link(ctx: &TestCtx, app_key: &str, secret: &str, file_id: i64, extra: Value) -> (StatusCode, Value) {
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

pub async fn download(ctx: &TestCtx, token: &str, headers: &[(&str, &str)]) -> (StatusCode, Bytes) {
    let mut rb = Request::builder().method("GET").uri(format!("/v1/download/{token}"));
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    send(&ctx.public, rb.body(Body::empty()).unwrap()).await
}

pub async fn send_full(
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
pub fn custom_routers(cfg: &Config, ops: Ops, rate_limit: u32) -> (Router, Router) {
    let conn = db::open_db(&cfg.db_path).unwrap();
    db::migrate(&conn).unwrap();
    let db: Db = Arc::new(Mutex::new(conn));
    let state = AppState {
        cfg: cfg.clone(),
        ops,
        db,
        ratelimit: Arc::new(filesrv::ratelimit::RateLimiter::new(rate_limit, 1000)),
        idem: Arc::new(filesrv::idem::IdemStore::new(3600, 1000)),
    };
    (
        filesrv::routes::public_router(state.clone()),
        filesrv::routes::admin_router(state),
    )
}

pub fn test_ops(dir: &TempDir) -> Ops {
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
        dec_cache_ttl_secs: 86400,
        audit_downloads: false,
    }
}
