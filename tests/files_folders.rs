mod common;
use common::*;

use axum::http::StatusCode;
use bytes::Bytes;
use serde_json::{json, Value};
use filesrv::config::Config;
use filesrv::db;
use filesrv::storage;

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

#[tokio::test]
async fn folder_cycle_rejected() {
    let ctx = new_test_ctx();
    let (_app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/folders", "", json!({ "name": "rootA" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let fa = v["folder_id"].as_i64().unwrap();
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/folders", "", json!({ "name": "childB" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let fb = v["folder_id"].as_i64().unwrap();

    // B under A is fine
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "PATCH", &format!("/v1/folders/{fb}"), "", json!({ "parent_id": fa }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // A under B would create a cycle -> 400 (F5 fix)
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "PATCH", &format!("/v1/folders/{fa}"), "", json!({ "parent_id": fb }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // A can still be moved back to the root (null parent)
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "PATCH", &format!("/v1/folders/{fa}"), "", json!({ "parent_id": null }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}
