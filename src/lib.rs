pub mod auth;
pub mod authz;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod routes;
pub mod state;
pub mod storage;
pub mod tokens;

pub use config::{Config, DEFAULT_SERVER_SECRET};
pub use routes::{admin_router, public_router};
pub use state::AppState;

use db::Db;

/// Open + migrate the persistent DB and build both routers.
pub fn build_app(cfg: Config) -> Result<(axum::Router, axum::Router, Db), Box<dyn std::error::Error>> {
    let conn = db::open_db(&cfg.db_path)?;
    db::migrate(&conn)?;
    // Sweep leftover tmp_* blobs from interrupted uploads (test report §5.3).
    storage::cleanup_stale_tmp(&cfg);
    let db: Db = std::sync::Arc::new(std::sync::Mutex::new(conn));
    let state = AppState::new(cfg, db.clone());
    Ok((public_router(state.clone()), admin_router(state), db))
}
