use std::net::SocketAddr;
use std::time::Duration;

use tenant_fs_server::config::Ops;
use tenant_fs_server::db;
use tenant_fs_server::{build_app, Config};

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let ops = Ops::from_env();
    // Warn loudly when the default server secret (which decrypts every app
    // secret) is left in place (test report §5.6).
    if cfg.server_secret == tenant_fs_server::DEFAULT_SERVER_SECRET {
        eprintln!(
            "WARNING: TENANT_FS_SERVER_SECRET is set to the development default \
             ('{DEFAULT}'). Do not deploy with this value; app secrets are \
             encrypted with it.",
            DEFAULT = tenant_fs_server::DEFAULT_SERVER_SECRET
        );
    }
    // Warn loudly when the default admin token is left in place too.
    if cfg.admin_token == tenant_fs_server::config::DEFAULT_ADMIN_TOKEN {
        eprintln!(
            "WARNING: TENANT_FS_ADMIN_TOKEN is set to the development default \
             ('{DEFAULT}'). Do not deploy with this value; it grants full \
             admin access on the admin interface.",
            DEFAULT = tenant_fs_server::config::DEFAULT_ADMIN_TOKEN
        );
    }
    let (public, admin, db_handle) = build_app(cfg.clone()).expect("failed to initialize server");

    let public_listener = tokio::net::TcpListener::bind(&cfg.public_bind)
        .await
        .unwrap_or_else(|e| panic!("public bind {} failed: {e}", cfg.public_bind));
    let admin_listener = tokio::net::TcpListener::bind(&cfg.admin_bind)
        .await
        .unwrap_or_else(|e| panic!("admin bind {} failed: {e}", cfg.admin_bind));

    println!("tenant-fs-server public  -> http://{}", cfg.public_bind);
    println!("tenant-fs-server admin   -> http://{} (localhost only)", cfg.admin_bind);
    println!("db   -> {}", cfg.db_path.display());
    println!("blob -> {}", cfg.blob_root.display());
    println!(
        "client IP mode -> {}",
        if cfg.trust_xff {
            "trusted X-Forwarded-For (set TENANT_FS_TRUST_XFF=true only behind a trusted proxy)"
        } else {
            "socket peer IP (X-Forwarded-For ignored)"
        }
    );

    // Periodic maintenance: expired nonces (they only need to outlive the
    // ±300s timestamp window), old audit rows (test report §5.4), and
    // soft-delete tombstones whose grace window elapsed (physical removal of
    // the DB row + blob file). Interval is configurable so tests/E2E can run
    // it quickly; 600s in production.
    let prune_db = db_handle.clone();
    let retention = cfg.audit_retention_secs;
    let grace = cfg.soft_delete_grace_secs;
    let maintenance_cfg = cfg.clone();
    let maintenance_ops = ops.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(maintenance_cfg.purge_interval_secs));
        loop {
            interval.tick().await;
            let (expired, export_paths, upload_paths) = {
                let conn = match prune_db.lock() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let now = tenant_fs_server::Config::now();
                let _ = db::prune_nonces(&conn, 3600);
                let _ = db::prune_audit(&conn, retention);
                let _ = db::prune_expired_tokens(&conn);
                let cutoff = now - grace;
                let expired = db::purge_expired_tombstones(&conn, cutoff).unwrap_or_default();
                // Export artifacts (tar/zip) and their rows past TTL.
                let export_paths = db::prune_expired_exports(&conn, now - maintenance_ops.export_ttl_secs)
                    .unwrap_or_default();
                // Interrupted chunked-upload sessions past their TTL.
                let upload_paths = db::prune_expired_uploads(&conn, now).unwrap_or_default();

                // Scheduled backups: if the operator set a schedule through
                // PATCH /admin/v1/backups/config (env default 0 = off), fire a
                // run when the interval has elapsed since the last backup.
                let settings = tenant_fs_server::backup::effective_settings(&conn, &maintenance_ops);
                if settings.schedule_secs > 0 {
                    let last = db::latest_backup_time(&conn).ok().flatten();
                    let due = match last {
                        Some(ts) => now - ts >= settings.schedule_secs as i64,
                        None => true,
                    };
                    if due {
                        let _ = tenant_fs_server::backup::run_backup(&maintenance_cfg, &maintenance_ops, &conn);
                    }
                }
                (expired, export_paths, upload_paths)
            };
            // DB row unlinked; now unlink the blob files outside the DB lock.
            for t in expired {
                tenant_fs_server::storage::remove_blob(
                    &maintenance_cfg,
                    t.app_id,
                    &t.storage_uuid,
                    t.blob_path.as_deref(),
                );
            }
            for p in export_paths {
                let _ = std::fs::remove_file(&p);
            }
            for p in upload_paths {
                let _ = std::fs::remove_file(&p);
            }
        }
    });

    let admin_task = tokio::spawn(async move {
        axum::serve(
            admin_listener,
            admin.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("admin server failed");
    });
    axum::serve(
        public_listener,
        public.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("public server failed");
    admin_task.await.ok();
}
