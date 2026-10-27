use crate::config::{Config, Ops};
use crate::db::Db;
use crate::idem::IdemStore;
use crate::ratelimit::RateLimiter;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub ops: Ops,
    pub db: Db,
    pub ratelimit: Arc<RateLimiter>,
    pub idem: Arc<IdemStore>,
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> Self {
        // Operational knobs are read from the environment here, alongside the
        // shared config; tests that need a different budget can build the
        // stores directly and spread a custom state.
        let ops = Ops::from_env();
        let ratelimit = Arc::new(RateLimiter::new(
            ops.rate_limit_per_min,
            ops.rate_limit_max_entries,
        ));
        let idem = Arc::new(IdemStore::new(ops.idem_window_secs, ops.idem_max_entries));
        AppState {
            cfg,
            ops,
            db,
            ratelimit,
            idem,
        }
    }
}
