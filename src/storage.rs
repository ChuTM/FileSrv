use crate::config::Config;
use std::path::{Path, PathBuf};

pub fn app_dir(cfg: &Config, app_id: i64) -> PathBuf {
    cfg.blob_root.join(format!("app_{app_id}"))
}

/// Resolve a blob path inside an app directory, canonicalize and verify the
/// result still lives inside the app root (segment-aware, blocks `..`/symlink
/// escape).
///
/// `rel_path` (e.g. `2026/10/<uuid>`) is the direct stored path, so lookups
/// are O(1); when it is absent/empty (legacy rows), fall back to a bounded
/// recursive uuid scan for compatibility.
pub fn resolve_blob(cfg: &Config, app_id: i64, uuid: &str, rel_path: Option<&str>) -> Result<PathBuf, String> {
    let app_root = app_dir(cfg, app_id);
    let canonical_root = app_root
        .canonicalize()
        .map_err(|_| "app directory does not exist".to_string())?;
    let found = match rel_path {
        Some(rp) if !rp.trim().is_empty() => app_root.join(rp).canonicalize().ok(),
        _ => find_uuid(&app_root, uuid, 0),
    }
    .ok_or_else(|| "blob not found".to_string())?;
    let canonical = found
        .canonicalize()
        .map_err(|_| "blob not found".to_string())?;
    if canonical.starts_with(&canonical_root) {
        Ok(canonical)
    } else {
        Err("path escapes app root".to_string())
    }
}

fn find_uuid(dir: &Path, uuid: &str, depth: usize) -> Option<PathBuf> {
    if depth > 5 {
        return None;
    }
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        if e.file_name().to_string_lossy() == uuid {
            return Some(p);
        }
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(f) = find_uuid(&p, uuid, depth + 1) {
                return Some(f);
            }
        }
    }
    None
}

/// Year/month directory to keep any single directory bounded.
fn date_subdir(_cfg: &Config) -> (String, String) {
    use chrono::Datelike;
    let now = chrono::Utc::now();
    (
        format!("{:04}", now.year()),
        format!("{:02}", now.month()),
    )
}

pub fn blob_path_for_new(cfg: &Config, app_id: i64, uuid: &str) -> PathBuf {
    let (y, m) = date_subdir(cfg);
    app_dir(cfg, app_id).join(y).join(m).join(uuid)
}

/// Relative blob path (e.g. `2026/10/<uuid>`) stored in the files table so
/// downloads resolve the blob directly instead of scanning the app directory.
pub fn blob_rel_for_new(cfg: &Config, uuid: &str) -> String {
    let (y, m) = date_subdir(cfg);
    format!("{y}/{m}/{uuid}")
}

/// Persist a fully-written temp blob into its final UUID path.
pub fn commit_blob(cfg: &Config, app_id: i64, uuid: &str, tmp_path: &Path) -> Result<PathBuf, String> {
    let final_path = blob_path_for_new(cfg, app_id, uuid);
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::rename(tmp_path, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}

pub fn remove_blob(cfg: &Config, app_id: i64, uuid: &str, rel_path: Option<&str>) {
    if let Ok(p) = resolve_blob(cfg, app_id, uuid, rel_path) {
        std::fs::remove_file(p).ok();
    }
}

/// Remove leftover `tmp_*` files from interrupted uploads (run at startup).
pub fn cleanup_stale_tmp(cfg: &Config) -> usize {
    let mut removed = 0;
    if let Ok(rd) = std::fs::read_dir(&cfg.blob_root) {
        for e in rd.flatten().filter(|e| {
            e.file_name().to_string_lossy().starts_with("tmp_")
                && e.file_type().map(|t| t.is_file()).unwrap_or(false)
        }) {
            if std::fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_with(dir: &TempDir) -> Config {
        Config {
            db_path: dir.path().join("fs.db"),
            blob_root: dir.path().join("blobs"),
            admin_token: "t".into(),
            server_secret: "s".into(),
            public_bind: "0.0.0.0:0".into(),
            admin_bind: "127.0.0.1:0".into(),
            embed_ttl_secs: 1800,
            share_ttl_secs: 300,
            max_batch_acl: 1000,
            trust_xff: false,
            audit_retention_secs: 30 * 86400,
        }
    }

    #[test]
    fn path_traversal_is_blocked() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        let app_root = app_dir(&cfg, 7);
        std::fs::create_dir_all(&app_root).unwrap();
        std::fs::write(app_root.join("victim.txt"), b"secret").unwrap();
        std::fs::create_dir_all(app_root.join("2026").join("10")).unwrap();
        std::fs::write(app_root.join("2026").join("10").join("okfile"), b"x").unwrap();
        std::fs::write(dir.path().join("outside.txt"), b"escape").unwrap();

        // Blob stored in a yyyy/mm subdir: found by uuid (legacy fallback scan)
        assert!(resolve_blob(&cfg, 7, "okfile", None).is_ok());
        // A malicious uuid that points outside the root cannot be resolved
        assert!(resolve_blob(&cfg, 7, "../../outside.txt", None).is_err());
        assert!(resolve_blob(&cfg, 7, "2026/10/../../outside.txt", None).is_err());
        assert!(resolve_blob(&cfg, 7, "victim.txt", None).is_ok()); // inside root is fine
        // Missing: must fail
        assert!(resolve_blob(&cfg, 7, "does-not-exist", None).is_err());

        // Direct stored-path resolution (the O(1) lookup path, §5.5):
        assert!(resolve_blob(&cfg, 7, "okfile", Some("2026/10/okfile")).is_ok());
        // A direct path escaping the app root via `..` is still blocked:
        assert!(resolve_blob(&cfg, 7, "victim", Some("2026/10/../../../../outside.txt")).is_err());
        // A direct path pointing at a missing file fails:
        assert!(resolve_blob(&cfg, 7, "ghost", Some("2026/10/ghost")).is_err());
        // An empty rel_path falls back to the scan:
        assert!(resolve_blob(&cfg, 7, "okfile", Some("")).is_ok());
    }

    #[test]
    fn cleanup_stale_tmp_removes_leftovers_only() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        std::fs::create_dir_all(&cfg.blob_root).unwrap();
        std::fs::create_dir_all(cfg.blob_root.join("app_1").join("2026").join("10")).unwrap();
        std::fs::write(cfg.blob_root.join("tmp_abc"), b"partial").unwrap();
        std::fs::write(cfg.blob_root.join("tmp_def"), b"partial").unwrap();
        std::fs::write(cfg.blob_root.join("app_1").join("2026").join("10").join("uuid1"), b"ok").unwrap();
        std::fs::write(cfg.blob_root.join("readme.txt"), b"keep me").unwrap();

        assert_eq!(cleanup_stale_tmp(&cfg), 2);
        assert!(!cfg.blob_root.join("tmp_abc").exists());
        assert!(!cfg.blob_root.join("tmp_def").exists());
        assert!(cfg.blob_root.join("app_1").join("2026").join("10").join("uuid1").exists());
        assert!(cfg.blob_root.join("readme.txt").exists());
    }
}
