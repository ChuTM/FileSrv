mod common;
use common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use serde_json::{json, Value};
use tempfile::TempDir;
use filesrv::crypto::sha256;

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
async fn opt_in_download_audit_writes_a_row() {
    // TENANT_FS_AUDIT_DOWNLOADS=true (ops.audit_downloads) records a per-download
    // audit row; off by default so high-read workloads don't balloon the log.
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let mut ops = test_ops(&dir);
    ops.audit_downloads = true;
    let (public, admin) = custom_routers(&cfg, ops, 120);
    let (app_id, key, secret) = create_app_quota(&admin, "aud", 1 << 20, 1 << 20).await;

    let (s, v) = json_of(
        send(&public, signed_req_raw(&key, &secret, "POST", "/v1/upload", "", b"audit-me", &[("x-user-id", "u1")])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fid = v["file_id"].as_i64().unwrap();
    let (s, v) = json_of(
        send(&public, signed_req(&key, &secret, "POST", "/v1/links/generate", "", json!({"file_id": fid}), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    let (s, _) = send(
        &public,
        Request::builder().method("GET").uri(format!("/v1/download/{token}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = json_of(
        send(&admin, admin_req("GET", &format!("/admin/v1/audit?app_id={app_id}"), Value::Null)).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let entries = v["entries"].as_array().unwrap();
    assert!(
        entries.iter().any(|e| e["action"] == "download" && e["decision"] == "allow"),
        "expected a download audit row, got {v}"
    );
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
async fn download_rate_limited_per_app() {
    let dir = TempDir::new().unwrap();
    let cfg = cfg_at(&dir);
    let ops = test_ops(&dir);
    let (public, admin) = custom_routers(&cfg, ops, 3); // 3 requests/min budget per app
    let (_, key, secret) = create_app_quota(&admin, "dl", 1 << 20, 1 << 20).await;

    let (s, v) = json_of(
        send(&public, signed_req_raw(&key, &secret, "POST", "/v1/upload", "", b"data", &[("x-user-id", "u1")])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fid = v["file_id"].as_i64().unwrap();
    let (s, v) = json_of(
        send(&public, signed_req(&key, &secret, "POST", "/v1/links/generate", "", json!({ "file_id": fid }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = v["token"].as_str().unwrap().to_string();

    // upload(1) + generate(2) + download(3) fit the budget
    let (s, _) = send(
        &public,
        Request::builder().method("GET").uri(format!("/v1/download/{token}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // 4th request in the same window -> 429 + Retry-After (F7 fix)
    let (s, headers, _) = send_full(
        &public,
        Request::builder().method("GET").uri(format!("/v1/download/{token}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers.get("retry-after").unwrap().to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
}
