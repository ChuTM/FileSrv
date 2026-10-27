use std::net::SocketAddr;
use std::time::Duration;

use tenant_fs_server::db;
use tenant_fs_server::{build_app, Config};

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
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

    // Periodic cleanup of expired nonces (they only need to outlive the ±300s
    // timestamp window) and old audit rows (test report §5.4).
    let prune_db = db_handle.clone();
    let retention = cfg.audit_retention_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            let conn = match prune_db.lock() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let _ = db::prune_nonces(&conn, 3600);
            let _ = db::prune_audit(&conn, retention);
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
