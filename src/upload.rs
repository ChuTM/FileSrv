//! Chunked / resumable upload sessions: DB-backed job state machine shared by
//! the init / chunk / finalize handlers in routes::app.
//!
//! Design: one staged partial file per session (`blob_root/tmp_up_<upload_id>`).
//! Chunks must arrive contiguously at offset == received_size; a gap returns
//! 409 with the current offset so a client can resume mid-stream. Interrupted
//! sessions expire (chunk TTL) and are swept by the background loop; orphan
//! staged files are also swept at startup by storage::cleanup_stale_tmp (the
//! `tmp_` prefix).

use crate::config::Config;
use rusqlite::Connection;

pub struct UploadJob {
    pub upload_id: String,
    pub app_id: i64,
    pub user_id: String,
    pub folder_id: Option<i64>,
    pub total_size: Option<i64>,
    pub received_size: i64,
    pub path: String,
    pub expires_at: i64,
}

pub fn staged_path(cfg: &Config, upload_id: &str) -> std::path::PathBuf {
    cfg.blob_root.join(format!("tmp_up_{upload_id}"))
}

#[allow(clippy::too_many_arguments)]
pub fn create(
    conn: &Connection,
    upload_id: &str,
    app_id: i64,
    user_id: &str,
    folder_id: Option<i64>,
    total_size: Option<i64>,
    path: &str,
    ttl_secs: i64,
) -> rusqlite::Result<()> {
    let now = Config::now();
    conn.execute(
        "INSERT INTO upload_jobs(upload_id,app_id,user_id,folder_id,total_size,received_size,status,path,created_at,expires_at)
         VALUES(?1,?2,?3,?4,?5,0,'open',?6,?7,?8)",
        rusqlite::params![upload_id, app_id, user_id, folder_id, total_size, path, now, now + ttl_secs],
    )?;
    Ok(())
}

pub fn get(conn: &Connection, upload_id: &str) -> rusqlite::Result<Option<UploadJob>> {
    let mut stmt = conn.prepare(
        "SELECT upload_id,app_id,user_id,folder_id,total_size,received_size,path,expires_at
         FROM upload_jobs WHERE upload_id=?1",
    )?;
    let mut rows = stmt.query_map(rusqlite::params![upload_id], |r| {
        Ok(UploadJob {
            upload_id: r.get(0)?,
            app_id: r.get(1)?,
            user_id: r.get(2)?,
            folder_id: r.get(3)?,
            total_size: r.get(4)?,
            received_size: r.get(5)?,
            path: r.get(6)?,
            expires_at: r.get(7)?,
        })
    })?;
    rows.next().transpose()
}

pub fn set_received(conn: &Connection, upload_id: &str, received: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE upload_jobs SET received_size=?1 WHERE upload_id=?2 AND status='open'",
        rusqlite::params![received, upload_id],
    )?;
    Ok(())
}

pub fn finish(conn: &Connection, upload_id: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM upload_jobs WHERE upload_id=?1", rusqlite::params![upload_id])?;
    Ok(())
}
