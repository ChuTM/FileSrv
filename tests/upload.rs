mod common;
use common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use serde_json::{json, Value};
use filesrv::crypto::{self, sha256};
use filesrv::db;
use filesrv::storage;

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
async fn payload_limit_enforced() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "L", 1 << 20, 5).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"1234567890", "").await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
}

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
async fn invalid_user_id_rejected_on_upload() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    for bad in ["../evil", "a/b", "a\\b", ".."] {
        let (s, v) = upload_bytes(&ctx, &key, &secret, bad, b"x", "").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "user_id {bad:?} must be rejected: {v}");
    }
    // a plain user_id still works
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u_ok", b"x", "").await;
    assert_eq!(s, StatusCode::OK);
}
