pub mod admin_ui;
pub mod auth;
pub mod authz;
pub mod backup;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod idem;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod storage;
pub mod tokens;
pub mod upload;

pub use config::{Config, DEFAULT_SERVER_SECRET};
pub use routes::{admin_router, public_router};
pub use state::AppState;

use db::Db;
use std::path::Path;

/// Open + migrate the persistent DB and build both routers.
/// Fail at startup instead of serving every upload with an opaque 500.
fn ensure_writable(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"ok")?;
    std::fs::remove_file(&probe)?;
    Ok(())
}

pub fn build_app(cfg: Config) -> Result<(axum::Router, axum::Router, Db), Box<dyn std::error::Error>> {
    ensure_writable(&cfg.blob_root).map_err(|e| {
        format!(
            "blob directory {} is not writable: {e}",
            cfg.blob_root.display()
        )
    })?;
    let conn = db::open_db(&cfg.db_path)?;
    db::migrate(&conn)?;
    // Sweep leftover tmp_* blobs from interrupted uploads (test report §5.3).
    storage::cleanup_stale_tmp(&cfg);
    let db: Db = std::sync::Arc::new(std::sync::Mutex::new(conn));
    let state = AppState::new(cfg, db.clone());
    Ok((public_router(state.clone()), admin_router(state), db))
}
