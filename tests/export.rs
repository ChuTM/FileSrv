mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::{json, Value};
use tempfile::TempDir;
use filesrv::config::Config;
use filesrv::db;

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
