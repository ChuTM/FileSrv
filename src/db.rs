use rusqlite::{Connection, params};
use std::path::Path;

use crate::config::Config;

pub type Db = std::sync::Arc<std::sync::Mutex<Connection>>;

pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS apps(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          app_key TEXT NOT NULL UNIQUE,
          secret_sealed TEXT NOT NULL,
          quota_bytes INTEGER NOT NULL DEFAULT 10737418240,
          max_payload_bytes INTEGER NOT NULL DEFAULT 104857600,
          usage_bytes INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          deleted_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS app_users(
          app_id INTEGER NOT NULL REFERENCES apps(id),
          user_id TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY(app_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS folders(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          app_id INTEGER NOT NULL REFERENCES apps(id),
          parent_id INTEGER REFERENCES folders(id),
          name TEXT NOT NULL,
          acl TEXT NOT NULL DEFAULT '{}',
          classification TEXT NOT NULL DEFAULT 'internal',
          created_at INTEGER NOT NULL,
          deleted_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS files(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          app_id INTEGER NOT NULL REFERENCES apps(id),
          user_id TEXT NOT NULL,
          folder_id INTEGER REFERENCES folders(id),
          storage_uuid TEXT NOT NULL,
          blob_path TEXT,
          logical_path TEXT NOT NULL,
          content_type TEXT NOT NULL,
          size INTEGER NOT NULL,
          sha256 TEXT NOT NULL,
          classification TEXT NOT NULL DEFAULT 'internal',
          owner TEXT NOT NULL,
          acl TEXT NOT NULL DEFAULT '{}',
          created_at INTEGER NOT NULL,
          deleted_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS tokens(
          token TEXT PRIMARY KEY,
          app_id INTEGER NOT NULL,
          file_id INTEGER NOT NULL,
          user_id TEXT NOT NULL,
          scope TEXT NOT NULL,
          embed_key TEXT,
          allowed_ip TEXT,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_embed ON tokens(embed_key);

        CREATE TABLE IF NOT EXISTS nonces(
          nonce TEXT PRIMARY KEY,
          app_id INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          app_id INTEGER,
          target TEXT,
          ip TEXT,
          decision TEXT NOT NULL,
          at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS export_jobs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          app_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          done_at INTEGER,
          size INTEGER,
          path TEXT
        );
        "#,
    )
}

pub struct AppRow {
    pub id: i64,
    pub name: String,
    pub app_key: String,
    pub secret_sealed: String,
    pub quota_bytes: i64,
    pub max_payload_bytes: i64,
    pub usage_bytes: i64,
    pub enabled: bool,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

pub fn app_by_key(conn: &Connection, app_key: &str) -> rusqlite::Result<Option<AppRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,app_key,secret_sealed,quota_bytes,max_payload_bytes,usage_bytes,enabled,created_at,deleted_at
         FROM apps WHERE app_key=?1",
    )?;
    let mut rows = stmt.query_map(params![app_key], |r| {
        Ok(AppRow {
            id: r.get(0)?,
            name: r.get(1)?,
            app_key: r.get(2)?,
            secret_sealed: r.get(3)?,
            quota_bytes: r.get(4)?,
            max_payload_bytes: r.get(5)?,
            usage_bytes: r.get(6)?,
            enabled: r.get::<_, i64>(7)? != 0,
            created_at: r.get(8)?,
            deleted_at: r.get(9)?,
        })
    })?;
    rows.next().transpose()
}

pub fn app_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<AppRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,app_key,secret_sealed,quota_bytes,max_payload_bytes,usage_bytes,enabled,created_at,deleted_at
         FROM apps WHERE id=?1",
    )?;
    let mut rows = stmt.query_map(params![id], |r| {
        Ok(AppRow {
            id: r.get(0)?,
            name: r.get(1)?,
            app_key: r.get(2)?,
            secret_sealed: r.get(3)?,
            quota_bytes: r.get(4)?,
            max_payload_bytes: r.get(5)?,
            usage_bytes: r.get(6)?,
            enabled: r.get::<_, i64>(7)? != 0,
            created_at: r.get(8)?,
            deleted_at: r.get(9)?,
        })
    })?;
    rows.next().transpose()
}

pub struct FileRow {
    pub id: i64,
    pub app_id: i64,
    pub user_id: String,
    pub folder_id: Option<i64>,
    pub storage_uuid: String,
    pub blob_path: Option<String>,
    pub logical_path: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: String,
    pub classification: String,
    pub owner: String,
    pub acl: String,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

pub fn file_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<FileRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at
         FROM files WHERE id=?1",
    )?;
    let mut rows = stmt.query_map(params![id], |r| {
        Ok(FileRow {
            id: r.get(0)?,
            app_id: r.get(1)?,
            user_id: r.get(2)?,
            folder_id: r.get(3)?,
            storage_uuid: r.get(4)?,
            blob_path: r.get(5)?,
            logical_path: r.get(6)?,
            content_type: r.get(7)?,
            size: r.get(8)?,
            sha256: r.get(9)?,
            classification: r.get(10)?,
            owner: r.get(11)?,
            acl: r.get(12)?,
            created_at: r.get(13)?,
            deleted_at: r.get(14)?,
        })
    })?;
    rows.next().transpose()
}

pub struct FolderRow {
    pub id: i64,
    pub app_id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub acl: String,
    pub deleted_at: Option<i64>,
}

pub fn folder_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<FolderRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,app_id,parent_id,name,acl,deleted_at FROM folders WHERE id=?1",
    )?;
    let mut rows = stmt.query_map(params![id], |r| {
        Ok(FolderRow {
            id: r.get(0)?,
            app_id: r.get(1)?,
            parent_id: r.get(2)?,
            name: r.get(3)?,
            acl: r.get(4)?,
            deleted_at: r.get(5)?,
        })
    })?;
    rows.next().transpose()
}

/// One audit entry; bundled so `audit` keeps a small signature (clippy).
pub struct AuditEntry<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub app_id: Option<i64>,
    pub target: &'a str,
    pub ip: &'a str,
    pub decision: &'a str,
}

pub fn audit(conn: &Connection, entry: &AuditEntry, at: i64) {
    conn.execute(
        "INSERT INTO audit_log(actor,action,app_id,target,ip,decision,at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![entry.actor, entry.action, entry.app_id, entry.target, entry.ip, entry.decision, at],
    )
    .ok();
}

/// Serialize all DB writes through a single connection (single-writer).
/// Helper to run a closure with a transaction.
pub fn with_tx<T>(db: &Db, f: impl FnOnce(&mut rusqlite::Transaction) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    let mut conn = db.lock().unwrap();
    let mut tx = conn.transaction()?;
    let res = f(&mut tx)?;
    tx.commit()?;
    Ok(res)
}

/// Remove nonce rows older than `older_than_secs`. Nonces only need to outlive
/// the ±300s timestamp window, so 1h retention is generous.
pub fn prune_nonces(conn: &Connection, older_than_secs: i64) -> rusqlite::Result<usize> {
    let cutoff = Config::now() - older_than_secs.max(60);
    conn.execute("DELETE FROM nonces WHERE created_at < ?1", params![cutoff])
}

/// Remove audit rows older than `older_than_secs` (retention window).
pub fn prune_audit(conn: &Connection, older_than_secs: i64) -> rusqlite::Result<usize> {
    let cutoff = Config::now() - older_than_secs.max(3600);
    conn.execute("DELETE FROM audit_log WHERE at < ?1", params![cutoff])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prune_deletes_only_old_rows() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("fs.db")).unwrap();
        migrate(&conn).unwrap();
        let now = Config::now();
        conn.execute(
            "INSERT INTO nonces(nonce,app_id,created_at) VALUES('n1',1,?1)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nonces(nonce,app_id,created_at) VALUES('n2',1,?1)",
            params![now - 7200],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log(actor,action,app_id,target,ip,decision,at) VALUES('a','x',NULL,'t','1','allow',?1)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log(actor,action,app_id,target,ip,decision,at) VALUES('b','y',NULL,'t','1','allow',?1)",
            params![now - 90 * 86400],
        )
        .unwrap();

        assert_eq!(prune_nonces(&conn, 3600).unwrap(), 1);
        assert_eq!(prune_audit(&conn, 30 * 86400).unwrap(), 1);

        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let a: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(a, 1);
    }
}
