use crate::config::Config;
use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub db: Db,
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> Self {
        AppState { cfg, db }
    }
}
