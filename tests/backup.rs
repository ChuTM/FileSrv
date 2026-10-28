mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::{json, Value};
use tempfile::TempDir;
use filesrv::crypto::sha256;

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
