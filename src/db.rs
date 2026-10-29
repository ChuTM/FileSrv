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

        -- Chunked / resumable upload sessions (API layer). The staged partial
        -- blob lives at `path`; rows expire (and are swept) after chunk_ttl.
        CREATE TABLE IF NOT EXISTS upload_jobs(
          upload_id TEXT PRIMARY KEY,
          app_id INTEGER NOT NULL,
          user_id TEXT NOT NULL,
          folder_id INTEGER,
          total_size INTEGER,
          received_size INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,
          path TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );

        -- Operational settings (backup schedule/target/retention) that the
        -- operator can toggle at runtime via PATCH /admin/v1/backups/config.
        CREATE TABLE IF NOT EXISTS backup_settings(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        -- Backup artifact metadata (the artifacts themselves live on disk
        -- under the configured backup root; no key material is ever stored).
        CREATE TABLE IF NOT EXISTS backups(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          backup_id TEXT NOT NULL UNIQUE,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          finished_at INTEGER,
          size INTEGER,
          target_path TEXT,
          manifest TEXT,
          error TEXT
        );

        -- User groups per tenant (admin-managed). ACL rules may reference a
        -- group as "g:<name>" instead of listing each user_id; members is a
        -- JSON array of user_id strings. Decided in Rust (no SQLite JSON1
        -- dependency).
        CREATE TABLE IF NOT EXISTS app_groups(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          app_id INTEGER NOT NULL REFERENCES apps(id),
          name TEXT NOT NULL,
          members TEXT NOT NULL DEFAULT '[]',
          created_at INTEGER NOT NULL,
          UNIQUE(app_id, name)
        );
        "#,
    )?;

    // Column migration: files.name holds the original upload filename so
    // downloads can echo it in Content-Disposition. Added after v1; DBs created
    // before this change lack the column, so add it when missing.
    {
        let mut stmt = conn.prepare("PRAGMA table_info(files)")?;
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?;
        if !cols.iter().any(|c| c == "name") {
            conn.execute_batch("ALTER TABLE files ADD COLUMN name TEXT;")?;
        }
    }
    Ok(())
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

pub struct GroupRow {
    pub id: i64,
    pub app_id: i64,
    pub name: String,
    pub members: Vec<String>,
    pub created_at: i64,
}

fn group_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<GroupRow> {
    let members: String = r.get(3)?;
    let members: Vec<String> = serde_json::from_str(&members).unwrap_or_default();
    Ok(GroupRow {
        id: r.get(0)?,
        app_id: r.get(1)?,
        name: r.get(2)?,
        members,
        created_at: r.get(4)?,
    })
}

const GROUP_SELECT: &str =
    "SELECT id,app_id,name,members,created_at FROM app_groups";

pub fn group_by_name(conn: &Connection, app_id: i64, name: &str) -> rusqlite::Result<Option<GroupRow>> {
    let mut stmt = conn.prepare(&format!("{GROUP_SELECT} WHERE app_id=?1 AND name=?2"))?;
    let mut rows = stmt.query_map(params![app_id, name], group_from_row)?;
    rows.next().transpose()
}

pub fn list_groups(conn: &Connection, app_id: i64) -> rusqlite::Result<Vec<GroupRow>> {
    let mut stmt = conn.prepare(&format!("{GROUP_SELECT} WHERE app_id=?1 ORDER BY name"))?;
    let rows = stmt.query_map(params![app_id], group_from_row)?;
    rows.collect()
}

/// Create a group (empty members). Fails with the UNIQUE constraint error if
/// a group with the same name already exists in this tenant.
pub fn create_group(conn: &Connection, app_id: i64, name: &str) -> rusqlite::Result<GroupRow> {
    conn.execute(
        "INSERT INTO app_groups(app_id,name,members,created_at) VALUES(?1,?2,'[]',?3)",
        params![app_id, name, Config::now()],
    )?;
    Ok(group_by_name(conn, app_id, name)?.expect("group just inserted"))
}

pub fn delete_group(conn: &Connection, app_id: i64, name: &str) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM app_groups WHERE app_id=?1 AND name=?2",
        params![app_id, name],
    )?;
    Ok(n > 0)
}

pub fn add_group_member(conn: &Connection, app_id: i64, name: &str, user_id: &str) -> rusqlite::Result<Option<GroupRow>> {
    let g = match group_by_name(conn, app_id, name)? {
        Some(g) => g,
        None => return Ok(None),
    };
    if !g.members.iter().any(|x| x == user_id) {
        let mut m = g.members;
        m.push(user_id.to_string());
        conn.execute(
            "UPDATE app_groups SET members=?1 WHERE app_id=?2 AND name=?3",
            params![serde_json::to_string(&m).unwrap_or_else(|_| "[]".into()), app_id, name],
        )?;
    }
    group_by_name(conn, app_id, name)
}

pub fn remove_group_member(conn: &Connection, app_id: i64, name: &str, user_id: &str) -> rusqlite::Result<Option<GroupRow>> {
    if group_by_name(conn, app_id, name)?.is_none() {
        return Ok(None);
    }
    let g = group_by_name(conn, app_id, name)?.unwrap();
    let m: Vec<String> = g.members.into_iter().filter(|x| x != user_id).collect();
    conn.execute(
        "UPDATE app_groups SET members=?1 WHERE app_id=?2 AND name=?3",
        params![serde_json::to_string(&m).unwrap_or_else(|_| "[]".into()), app_id, name],
    )?;
    group_by_name(conn, app_id, name)
}

/// All group names whose members JSON contains the given user_id.
pub fn user_group_names(conn: &Connection, app_id: i64, user_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name,members FROM app_groups WHERE app_id=?1")?;
    let rows = stmt.query_map(params![app_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (name, members) = r?;
        let m: Vec<String> = serde_json::from_str(&members).unwrap_or_default();
        if m.iter().any(|x| x == user_id) {
            out.push(name);
        }
    }
    Ok(out)
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
    pub name: Option<String>,
}

pub fn file_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<FileRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at,name
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
            name: r.get(15)?,
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

/// A tombstoned file whose grace period elapsed: the blob row is about to be
/// physically deleted, and the caller must unlink its on-disk blob.
///
/// NOTE: usage_bytes was already rolled back at DELETE time, so purging never
/// touches it again.
pub struct TombstoneFile {
    pub id: i64,
    pub app_id: i64,
    pub storage_uuid: String,
    pub blob_path: Option<String>,
}

/// Physically delete tombstones whose `deleted_at < cutoff` and return the
/// rows (so the caller can unlink their blobs). Also sweeps expired folder
/// tombstones and any tokens still pointing at purged files.
pub fn purge_expired_tombstones(conn: &Connection, cutoff: i64) -> rusqlite::Result<Vec<TombstoneFile>> {
    let rows: Vec<TombstoneFile> = {
        let mut stmt = conn.prepare(
            "SELECT id,app_id,storage_uuid,blob_path
             FROM files
             WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        )?;
        let rows = stmt.query_map(params![cutoff], |r| {
            Ok(TombstoneFile {
                id: r.get(0)?,
                app_id: r.get(1)?,
                storage_uuid: r.get(2)?,
                blob_path: r.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if rows.is_empty() {
        return Ok(rows);
    }
    conn.execute(
        "DELETE FROM tokens WHERE file_id IN (
            SELECT id FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?1
        )",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM folders WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        params![cutoff],
    )?;
    Ok(rows)
}

// ---------------- Runtime settings (backup config) ----------------

pub fn get_setting(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM backup_settings WHERE key=?1", params![key], |r| r.get(0))
        .ok()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO backup_settings(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=?2",
        params![key, value],
    )?;
    Ok(())
}

// ---------------- Backup records ----------------

pub struct BackupRow {
    pub id: i64,
    pub backup_id: String,
    pub status: String,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub size: Option<i64>,
    pub target_path: Option<String>,
    pub manifest: Option<String>,
    pub error: Option<String>,
}

fn backup_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupRow> {
    Ok(BackupRow {
        id: row.get(0)?,
        backup_id: row.get(1)?,
        status: row.get(2)?,
        created_at: row.get(3)?,
        finished_at: row.get(4)?,
        size: row.get(5)?,
        target_path: row.get(6)?,
        manifest: row.get(7)?,
        error: row.get(8)?,
    })
}

pub fn insert_backup(conn: &Connection, backup_id: &str, created_at: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO backups(backup_id,status,created_at) VALUES(?1,'running',?2)",
        params![backup_id, created_at],
    )?;
    Ok(conn.last_insert_rowid())
}

#[allow(clippy::too_many_arguments)]
pub fn finish_backup(
    conn: &Connection,
    id: i64,
    status: &str,
    size: Option<i64>,
    target_path: Option<&str>,
    manifest: Option<&str>,
    error: Option<&str>,
    finished_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE backups SET status=?1, size=?2, target_path=?3, manifest=?4, error=?5, finished_at=?6
         WHERE id=?7",
        params![status, size, target_path, manifest, error, finished_at, id],
    )?;
    Ok(())
}

const BACKUP_COLS: &str =
    "id,backup_id,status,created_at,finished_at,size,target_path,manifest,error";

pub fn list_backups(conn: &Connection) -> rusqlite::Result<Vec<BackupRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {BACKUP_COLS} FROM backups ORDER BY id DESC"))?;
    let rows = stmt.query_map(params![], backup_row_from)?;
    rows.collect()
}

pub fn backup_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<BackupRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {BACKUP_COLS} FROM backups WHERE id=?1"))?;
    let mut rows = stmt.query_map(params![id], backup_row_from)?;
    rows.next().transpose()
}

pub fn latest_backup_time(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT MAX(created_at) FROM backups", [], |r| r.get(0))
}

/// Return the (id, backup_id, target_path) of backups beyond the newest
/// `keep` copies (caller unlinks their on-disk dirs and deletes the rows).
pub fn obsolete_backups(conn: &Connection, keep: usize) -> rusqlite::Result<Vec<(i64, String, Option<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT id,backup_id,target_path FROM backups ORDER BY id DESC LIMIT -1 OFFSET ?1",
    )?;
    let rows = stmt.query_map(params![keep.max(1) as i64], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?;
    rows.collect()
}

pub fn delete_backup_row(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM backups WHERE id=?1", params![id])
}

// ---------------- Background sweeps ----------------

/// Drop expired (and revoked) capability token rows. Tokens are checked on
/// every use anyway; this just keeps the table from growing without bound.
pub fn prune_expired_tokens(conn: &Connection) -> rusqlite::Result<usize> {
    let now = Config::now();
    conn.execute(
        "DELETE FROM tokens WHERE expires_at < ?1 OR revoked=1",
        params![now],
    )
}

/// Drop finished export jobs whose artifact is older than `cutoff`; return
/// the artifact paths so the caller can unlink them outside the DB lock.
pub fn prune_expired_exports(conn: &Connection, cutoff: i64) -> rusqlite::Result<Vec<String>> {
    let rows: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT path FROM export_jobs WHERE done_at IS NOT NULL AND done_at < ?1",
        )?;
        let rows = stmt.query_map(params![cutoff], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    conn.execute(
        "DELETE FROM export_jobs WHERE done_at IS NOT NULL AND done_at < ?1",
        params![cutoff],
    )?;
    Ok(rows)
}

/// Drop unfinished chunked-upload sessions past their expiry; return the
/// staged partial paths so the caller can unlink them.
pub fn prune_expired_uploads(conn: &Connection, now: i64) -> rusqlite::Result<Vec<String>> {
    let rows: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT path FROM upload_jobs WHERE status != 'finalized' AND expires_at < ?1",
        )?;
        let rows = stmt.query_map(params![now], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    conn.execute(
        "DELETE FROM upload_jobs WHERE status != 'finalized' AND expires_at < ?1",
        params![now],
    )?;
    Ok(rows)
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

    #[test]
    fn purge_expired_tombstones_only_removes_due_rows() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("fs.db")).unwrap();
        migrate(&conn).unwrap();
        let now = Config::now();
        conn.execute(
            "INSERT INTO apps(name,app_key,secret_sealed,quota_bytes,max_payload_bytes,usage_bytes,created_at)
             VALUES('t','k','s',100,100,0,?1)",
            params![now],
        )
        .unwrap();
        // Active file (no tombstone) — must survive
        conn.execute(
            "INSERT INTO files(app_id,user_id,storage_uuid,logical_path,content_type,size,sha256,classification,owner,acl,created_at)
             VALUES(1,'u1','uuid-active','p','application/octet-stream',10,'x','internal','u1','{}',?1)",
            params![now],
        )
        .unwrap();
        // Tombstone that expired 2h ago — eligible
        conn.execute(
            "INSERT INTO files(app_id,user_id,storage_uuid,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at)
             VALUES(1,'u1','uuid-old','p','application/octet-stream',10,'x','internal','u1','{}',?1,?2)",
            params![now, now - 7200],
        )
        .unwrap();
        // Fresh tombstone (deleted 10s ago) — still inside grace
        conn.execute(
            "INSERT INTO files(app_id,user_id,storage_uuid,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at)
             VALUES(1,'u1','uuid-fresh','p','application/octet-stream',10,'x','internal','u1','{}',?1,?2)",
            params![now, now - 10],
        )
        .unwrap();

        // cutoff = now - 3600: only the old tombstone is due
        let due = purge_expired_tombstones(&conn, now - 3600).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].storage_uuid, "uuid-old");

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2, "active + fresh tombstone must remain");
        let due: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE deleted_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(due, 1, "fresh tombstone must remain");

        // Next tick (now - 0): the fresh tombstone becomes due and goes too
        let due2 = purge_expired_tombstones(&conn, now).unwrap();
        assert_eq!(due2.len(), 1);
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
        // Second tick with nothing due is a no-op
        assert!(purge_expired_tombstones(&conn, now).unwrap().is_empty());
    }
}
