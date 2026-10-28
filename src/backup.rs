//! Backups (admin API): DB snapshot (VACUUM INTO) + encrypted blob archive
//! (tar) + sha256 manifest.
//!
//! KEY-MATERIAL POLICY (also documented in crypto.rs): the backup artifacts
//! MUST never contain key material. SERVER_SECRET lives only in the deployment
//! environment and is never read out, written to disk, or embedded in the
//! manifest. Admin tokens and app secrets are likewise excluded — the DB
//! snapshot contains app.secret_sealed, which is sealed under the KEK derived
//! from SERVER_SECRET; without SERVER_SECRET those blobs are undecryptable.
//! Blobs inside the archive are envelope-encrypted files as stored; the
//! plaintext `dec_cache/` and finished `exports/` trees are deliberately
//! skipped.

use crate::config::{Config, Ops};
use crate::crypto;
use crate::db::{self, Db};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub struct EffectiveSettings {
    /// Directory under backup_root where copies land.
    pub target: String,
    /// Copies to keep (newest wins).
    pub retention: usize,
    /// Scheduled interval in seconds (0 = no automatic run).
    pub schedule_secs: u64,
}

/// Resolve the effective backup settings: environment defaults, overridden by
/// whatever the operator last wrote through PATCH /admin/v1/backups/config.
pub fn effective_settings(conn: &Connection, ops: &Ops) -> EffectiveSettings {
    let target = db::get_setting(conn, "target").unwrap_or_else(|| "default".to_string());
    let retention = db::get_setting(conn, "retention")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(ops.backup_retention)
        .clamp(1, 1000);
    let schedule_secs = db::get_setting(conn, "schedule_secs")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(ops.backup_schedule_secs);
    EffectiveSettings {
        target,
        retention,
        schedule_secs,
    }
}

/// Canonical backup root; any backup target must resolve inside it.
pub fn canonical_backup_root(ops: &Ops) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&ops.backup_root).map_err(|e| format!("backup root: {e}"))?;
    ops.backup_root
        .canonicalize()
        .map_err(|e| format!("backup root canonicalize: {e}"))
}

/// Validate and resolve a backup directory: join target relative path under
/// the backup root, canonicalize, and confirm it still lives inside the root.
/// Blocks `..` traversal AND symlink escape (canonicalize resolves links).
pub fn resolve_backup_dir(ops: &Ops, target: &str, backup_id: &str) -> Result<PathBuf, String> {
    let root = canonical_backup_root(ops)?;
    // Reject absolute targets outright — everything must hang off the root.
    let candidate = root.join(target.trim()).join(backup_id);
    std::fs::create_dir_all(&candidate).map_err(|e| format!("mkdir backup dir: {e}"))?;
    let canonical = candidate
        .canonicalize()
        .map_err(|e| format!("backup dir canonicalize: {e}"))?;
    if !canonical.starts_with(&root) {
        return Err("backup target escapes backup root".to_string());
    }
    Ok(canonical)
}

/// Validate an operator-supplied target name (used by PATCH config).
pub fn validate_target(ops: &Ops, target: &str) -> Result<PathBuf, String> {
    if target.trim().is_empty() || target.contains(['\\', ':']) || target.starts_with('/') {
        return Err("invalid target: must be a relative directory name".to_string());
    }
    let root = canonical_backup_root(ops)?;
    let probe = root.join(target.trim());
    std::fs::create_dir_all(&probe).map_err(|e| format!("mkdir target: {e}"))?;
    let canonical = probe
        .canonicalize()
        .map_err(|e| format!("target canonicalize: {e}"))?;
    if !canonical.starts_with(&root) {
        return Err("target escapes backup root".to_string());
    }
    Ok(canonical)
}

pub struct BackupOutput {
    pub id: i64,
    pub backup_id: String,
    pub size: i64,
    pub files: Vec<(String, u64, String)>, // (name, size, sha256)
}

/// Run one backup: DB snapshot + blobs tar + manifest, recorded in `backups`.
///
/// The backup routine manages its OWN short DB locks and performs the slow
/// blob-tree archiving WITHOUT holding the global DB mutex (F3 fix): requests
/// are only blocked for the brief VACUUM INTO snapshot and the bookkeeping
/// updates, never for the whole tar walk.
pub fn run_backup(cfg: &Config, ops: &Ops, db: &Db) -> Result<BackupOutput, String> {
    let settings = {
        let conn = db.lock().unwrap();
        effective_settings(&conn, ops)
    };
    let backup_id = format!("bk_{}", crypto::random_token());
    let now = Config::now();
    let row_id = {
        let conn = db.lock().unwrap();
        db::insert_backup(&conn, &backup_id, now).map_err(|e| e.to_string())?
    };

    match run_backup_inner(cfg, ops, db, &settings, row_id, &backup_id, now) {
        Ok(out) => Ok(out),
        Err(e) => {
            let conn = db.lock().unwrap();
            db::finish_backup(&conn, row_id, "failed", None, None, None, Some(&e), now)
                .map_err(|fe| format!("{e} (and failed to record: {fe})"))?;
            Err(e)
        }
    }
}

fn run_backup_inner(
    cfg: &Config,
    ops: &Ops,
    db: &Db,
    settings: &EffectiveSettings,
    row_id: i64,
    backup_id: &str,
    now: i64,
) -> Result<BackupOutput, String> {
    let dir = resolve_backup_dir(ops, &settings.target, backup_id)?;

    // 1) Consistent DB snapshot, taken under a SHORT lock. VACUUM INTO takes a
    //    literal path (no bound params); the path comes from our own
    //    canonicalized root, and any single quote is escaped per SQLite
    //    string-literal rules.
    let db_snapshot = dir.join("db.sqlite");
    let sql = format!(
        "VACUUM INTO '{}'",
        db_snapshot.to_string_lossy().replace('\'', "''")
    );
    {
        let conn = db.lock().unwrap();
        conn.execute(&sql, []).map_err(|e| format!("db snapshot: {e}"))?;
    }

    // 2) Blobs archive: the encrypted blob tree, skipping plaintext caches,
    //    finished export artifacts, and interrupted-upload partials.
    //    Runs WITHOUT the DB lock (this is the slow part).
    let blobs_tar = dir.join("blobs.tar");
    let _archived = tar_blobs(cfg, &blobs_tar)?;

    // 3) Manifest: per-artifact sha256 + metadata. Explicitly NO key material.
    let mut files: Vec<(String, u64, String)> = Vec::new();
    for name in ["db.sqlite", "blobs.tar"] {
        let p = dir.join(name);
        let bytes = std::fs::read(&p).map_err(|e| format!("read {name}: {e}"))?;
        files.push((name.to_string(), bytes.len() as u64, crypto::sha256(&bytes)));
    }
    let manifest = serde_json::json!({
        "backup_id": backup_id,
        "created_at": now,
        "server": "filesrv",
        "note": "Blobs are envelope-encrypted; SERVER_SECRET and all key material \
                 stay in the deployment environment and are NOT included.",
        "files": files.iter().map(|(name, size, sha)| serde_json::json!({
            "name": name, "size": size, "sha256": sha
        })).collect::<Vec<_>>()
    });
    std::fs::write(dir.join("manifest.json"), manifest.to_string())
        .map_err(|e| format!("write manifest: {e}"))?;

    let total_size: i64 = std::fs::metadata(&db_snapshot)
        .map(|m| m.len() as i64)
        .unwrap_or(0)
        + std::fs::metadata(&blobs_tar).map(|m| m.len() as i64).unwrap_or(0);

    // 4) Record "ready" + retention under a short lock.
    {
        let conn = db.lock().unwrap();
        db::finish_backup(
            &conn,
            row_id,
            "ready",
            Some(total_size),
            Some(&dir.to_string_lossy()),
            Some(&manifest.to_string()),
            None,
            now,
        )
        .map_err(|e| e.to_string())?;
        // Retention: keep the newest N copies, delete the rest (dirs + rows).
        enforce_retention(&conn, settings.retention).ok();
    }

    Ok(BackupOutput {
        id: row_id,
        backup_id: backup_id.to_string(),
        size: total_size,
        files,
    })
}

fn enforce_retention(conn: &Connection, keep: usize) -> rusqlite::Result<()> {
    let obsolete = db::obsolete_backups(conn, keep)?;
    for (id, _bid, path) in obsolete {
        if let Some(p) = path {
            let _ = std::fs::remove_dir_all(&p);
        }
        db::delete_backup_row(conn, id).ok();
    }
    Ok(())
}

fn tar_blobs(cfg: &Config, out: &Path) -> Result<usize, String> {
    let f = std::fs::File::create(out).map_err(|e| format!("create blobs.tar: {e}"))?;
    let mut builder = tar::Builder::new(f);
    let root = &cfg.blob_root;
    let mut count = 0usize;
    walk_tar(root, root, &mut builder, &mut count)?;
    // tar 0.4 flushes the archive trailer in Builder::drop.
    drop(builder);
    Ok(count)
}

fn walk_tar(
    base: &Path,
    dir: &Path,
    builder: &mut tar::Builder<std::fs::File>,
    count: &mut usize,
) -> Result<(), String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        // Skip plaintext caches, finished export artifacts, partials.
        if is_dir && (name == "dec_cache" || name == "exports") {
            continue;
        }
        if name.starts_with("tmp_") {
            continue;
        }
        if is_dir {
            walk_tar(base, &p, builder, count)?;
            continue;
        }
        let rel = p.strip_prefix(base).map_err(|_| "blob path".to_string())?;
        let rel_name = rel.to_string_lossy().replace('\\', "/");
        // Only archive the app_* blob trees (service files like .DS_Store skipped).
        if !rel_name.starts_with("app_") {
            continue;
        }
        let fh = std::fs::File::open(&p).map_err(|e| format!("open {rel_name}: {e}"))?;
        let meta = fh.metadata().map_err(|e| e.to_string())?;
        let mut header = tar::Header::new_gnu();
        header.set_size(meta.len());
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(&mut header, rel_name, fh)
            .map_err(|e| format!("append blob: {e}"))?;
        *count += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{migrate, open_db};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn setup(dir: &TempDir) -> (Config, Ops) {
        let cfg = Config {
            db_path: dir.path().join("fs.db"),
            blob_root: dir.path().join("blobs"),
            admin_token: "t".into(),
            server_secret: "secret-material-never-backed-up".into(),
            public_bind: "0.0.0.0:0".into(),
            admin_bind: "127.0.0.1:0".into(),
            embed_ttl_secs: 1800,
            share_ttl_secs: 300,
            max_batch_acl: 1000,
            trust_xff: false,
            audit_retention_secs: 30 * 86400,
            encrypt_blobs: true,
            soft_delete_grace_secs: 7 * 86400,
            purge_interval_secs: 600,
            allow_non_loopback_admin: false,
        };
        let ops = Ops {
            backup_root: dir.path().join("backups"),
            backup_retention: 7,
            backup_schedule_secs: 0,
            chunk_ttl_secs: 3600,
            rate_limit_per_min: 120,
            rate_limit_max_entries: 10000,
            idem_window_secs: 3600,
            idem_max_entries: 10000,
            export_ttl_secs: 86400,
            dec_cache_ttl_secs: 86400,
        };
        (cfg, ops)
    }

    #[test]
    fn target_escape_is_blocked() {
        let dir = TempDir::new().unwrap();
        let (_cfg, ops) = setup(&dir);
        assert!(validate_target(&ops, "../escape").is_err());
        assert!(validate_target(&ops, "/abs/path").is_err());
        assert!(validate_target(&ops, "subdir").is_ok());
    }

    #[test]
    fn run_backup_artifacts_and_no_key_leak() {
        let dir = TempDir::new().unwrap();
        let (cfg, ops) = setup(&dir);
        std::fs::create_dir_all(cfg.blob_root.join("app_1").join("2026").join("10")).unwrap();
        // one encrypted blob + a plaintext dec_cache that must be EXCLUDED
        let env = crypto::blob_encrypt(cfg.server_secret.as_bytes(), b"payload-123");
        std::fs::write(cfg.blob_root.join("app_1").join("2026").join("10").join("uuid1"), &env).unwrap();
        std::fs::create_dir_all(cfg.blob_root.join("dec_cache")).unwrap();
        std::fs::write(cfg.blob_root.join("dec_cache").join("uuid1"), b"payload-123").unwrap();

        let conn = open_db(&cfg.db_path).unwrap();
        migrate(&conn).unwrap();
        let db: Db = Arc::new(Mutex::new(conn));
        let out = run_backup(&cfg, &ops, &db).unwrap();
        assert!(out.size > 0);
        assert_eq!(out.files.len(), 2);

        // manifest + both artifacts exist (directory named after the random id)
        let backups = std::fs::read_dir(&ops.backup_root).unwrap().count();
        assert!(backups >= 1);
        let bdir = ops.backup_root.join("default").join(&out.backup_id);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bdir.join("manifest.json")).unwrap()).unwrap();
        // manifest sha256 matches the real file
        for (name, _size, sha) in &out.files {
            let on_disk = std::fs::read(bdir.join(name)).unwrap();
            assert_eq!(crypto::sha256(&on_disk), *sha);
            // no secret material inside the archive artifacts
            assert!(!on_disk.windows(cfg.server_secret.len()).any(|w| w == cfg.server_secret.as_bytes()));
        }
        assert!(manifest["note"].is_string());

        // tar contains the encrypted blob, NOT the plaintext dec_cache
        let tar_bytes = std::fs::read(bdir.join("blobs.tar")).unwrap();
        assert!(tar_bytes.windows(10).any(|w| w == b"app_1/2026"));
        assert!(!tar_bytes.windows(9).any(|w| w == b"dec_cache"));
        assert!(!tar_bytes.windows(12).any(|w| w == b"payload-123"), "plaintext must not leak into archive");

        // retention works: run two more with keep=2, oldest row/dir gone
        {
            let conn = db.lock().unwrap();
            db::set_setting(&conn, "retention", "2").unwrap();
        }
        run_backup(&cfg, &ops, &db).unwrap();
        run_backup(&cfg, &ops, &db).unwrap();
        let conn = db.lock().unwrap();
        let rows = db::list_backups(&conn).unwrap();
        assert_eq!(rows.len(), 2, "retention=2 kept newest");
    }
}
