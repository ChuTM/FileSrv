use crate::config::Config;
use crate::crypto;
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
    let raw = locate_blob(cfg, app_id, uuid, rel_path)?;
    // Encrypted-at-rest read path: if the blob file carries the envelope magic,
    // materialize its decrypted plaintext into a stable per-uuid cache file and
    // hand that to the caller (download/export stream it transparently).
    // Legacy plaintext blobs (no magic) are served as-is.
    if cfg.encrypt_blobs && blob_is_encrypted(&raw) {
        let cache = dec_cache_path(cfg, uuid)?;
        if !cache.exists() {
            let blob = std::fs::read(&raw).map_err(|_| "blob unreadable".to_string())?;
            let pt = crypto::blob_decrypt(cfg.server_secret.as_bytes(), &blob)
                .ok_or_else(|| "blob authentication failed".to_string())?;
            if let Some(parent) = cache.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            // Atomic swap: write a sibling temp, then rename over the cache path.
            let tmp = cache.with_extension("part");
            std::fs::write(&tmp, &pt).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &cache).map_err(|e| e.to_string())?;
        }
        return Ok(cache);
    }
    Ok(raw)
}

/// Locate the on-disk blob path (raw bytes, as stored). Used by deletion and
/// purge so callers remove the real encrypted file, never the decrypted cache.
pub fn locate_blob(cfg: &Config, app_id: i64, uuid: &str, rel_path: Option<&str>) -> Result<PathBuf, String> {
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

/// Peek the first bytes of a blob file: does it carry the envelope magic?
fn blob_is_encrypted(path: &Path) -> bool {
    let mut head = [0u8; 5];
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    use std::io::Read;
    match f.read(&mut head) {
        Ok(n) => crypto::looks_like_encrypted_blob(&head[..n]),
        Err(_) => false,
    }
}

/// Per-uuid plaintext cache path used by the encrypted read path.
///
/// `uuid` is the server-generated storage_uuid (never client-supplied) and is
/// restricted to a safe token set before being used as a filename.
fn dec_cache_path(cfg: &Config, uuid: &str) -> Result<PathBuf, String> {
    let safe = uuid
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !safe || uuid.is_empty() {
        return Err("unsafe blob uuid".to_string());
    }
    Ok(cfg.blob_root.join("dec_cache").join(uuid))
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

/// Persist a fully-written staged blob into its final UUID path.
///
/// `staged` already holds the bytes that must end up on disk: plaintext when
/// encryption is disabled, or the envelope frame when it is enabled.
pub fn commit_blob(cfg: &Config, app_id: i64, uuid: &str, staged: &Path) -> Result<PathBuf, String> {
    let final_path = blob_path_for_new(cfg, app_id, uuid);
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::rename(staged, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}

/// Best-effort unlink of a blob file (real on-disk bytes) and its decrypted
/// cache entry. Used by purge; DELETE must NOT call this during the grace window.
pub fn remove_blob(cfg: &Config, app_id: i64, uuid: &str, rel_path: Option<&str>) {
    if let Ok(p) = locate_blob(cfg, app_id, uuid, rel_path) {
        std::fs::remove_file(p).ok();
    }
    if let Ok(cache) = dec_cache_path(cfg, uuid) {
        std::fs::remove_file(cache).ok();
    }
}

/// One-time migration for pre-encryption deployments: rewrite every on-disk
/// blob that is still plaintext into the envelope format in place.
///
/// Idempotent and safe to re-run: files already carrying the envelope magic
/// are skipped, and non-blob directories (`exports/`, `dec_cache/`) and
/// interrupted-upload leftovers (`tmp_*`) are left alone.
pub fn migrate_plaintext_blobs(cfg: &Config) -> Result<usize, String> {
    let root = cfg.blob_root.clone();
    let mut migrated = 0usize;
    visit_plaintext(&root, &root, &mut migrated, cfg)?;
    Ok(migrated)
}

fn visit_plaintext(
    dir: &Path,
    root: &Path,
    count: &mut usize,
    cfg: &Config,
) -> Result<(), String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            // Skip service directories: export artifacts, decrypted cache.
            if name == "exports" || name == "dec_cache" {
                continue;
            }
            visit_plaintext(&p, root, count, cfg)?;
            continue;
        }
        if name.starts_with("tmp_") {
            continue;
        }
        // Only blobs inside an app_* tree are migrated.
        if !p.starts_with(root) {
            continue;
        }
        if blob_is_encrypted(&p) {
            continue;
        }
        let pt = std::fs::read(&p).map_err(|e| e.to_string())?;
        let sealed = crypto::blob_encrypt(cfg.server_secret.as_bytes(), &pt);
        let tmp = p.with_extension("encpart");
        std::fs::write(&tmp, &sealed).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
        *count += 1;
    }
    Ok(())
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

/// Remove decrypted-cache files under `blob_root/dec_cache` whose mtime is
/// older than `cutoff` (unix seconds). The cache is a re-creatable plaintext
/// materialization of an envelope-encrypted blob, so it must NOT persist on
/// disk indefinitely (F2 fix); the maintenance loop sweeps it on a TTL.
/// Only files are removed; the directory itself is left in place.
pub fn sweep_dec_cache(cfg: &Config, cutoff: i64) -> usize {
    let cache_dir = cfg.blob_root.join("dec_cache");
    let rd = match std::fs::read_dir(&cache_dir) {
        Ok(rd) => rd,
        Err(_) => return 0, // no cache dir (yet) is fine
    };
    let mut removed = 0;
    for e in rd.flatten() {
        let is_file = e.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file {
            continue;
        }
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let secs = match modified.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => continue,
        };
        if secs < cutoff && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
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
            encrypt_blobs: true,
            soft_delete_grace_secs: 7 * 86400,
            purge_interval_secs: 600,
            allow_non_loopback_admin: false,
        }
    }

    #[test]
    fn path_traversal_is_blocked() {
        let dir = TempDir::new().unwrap();
        let mut cfg = cfg_with(&dir);
        cfg.encrypt_blobs = false; // plaintext files in this test
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
        let mut cfg = cfg_with(&dir);
        cfg.encrypt_blobs = false;
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

    #[test]
    fn encrypted_blob_materializes_plaintext_on_read() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        let app_root = app_dir(&cfg, 3);
        std::fs::create_dir_all(app_root.join("2026").join("10")).unwrap();
        let raw = app_root.join("2026").join("10").join("uuid-enc");
        let env = crypto::blob_encrypt(cfg.server_secret.as_bytes(), b"secret-payload");
        std::fs::write(&raw, &env).unwrap();
        assert!(blob_is_encrypted(&raw));

        // First resolve materializes the plaintext cache; bytes are readable
        let cache = resolve_blob(&cfg, 3, "uuid-enc", Some("2026/10/uuid-enc")).unwrap();
        assert_eq!(std::fs::read(&cache).unwrap(), b"secret-payload");
        // Cache path lives under dec_cache, not inside the app tree
        assert!(cache.starts_with(cfg.blob_root.join("dec_cache")));

        // Second resolve is a cache hit (no decrypt needed)
        let cache2 = resolve_blob(&cfg, 3, "uuid-enc", Some("2026/10/uuid-enc")).unwrap();
        assert_eq!(cache2, cache);

        // locate_blob still returns the raw encrypted file (purge uses it)
        let located = locate_blob(&cfg, 3, "uuid-enc", Some("2026/10/uuid-enc")).unwrap();
        assert_eq!(std::fs::read(&located).unwrap(), env);

        // remove_blob drops both the raw file and the cache entry
        remove_blob(&cfg, 3, "uuid-enc", Some("2026/10/uuid-enc"));
        assert!(!located.exists());
        assert!(!cache.exists());
    }

    #[test]
    fn legacy_plaintext_blob_is_served_untouched() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        let app_root = app_dir(&cfg, 4);
        std::fs::create_dir_all(app_root.join("2026").join("10")).unwrap();
        let raw = app_root.join("2026").join("10").join("uuid-legacy");
        std::fs::write(&raw, b"legacy-plaintext").unwrap();
        assert!(!blob_is_encrypted(&raw));

        let p = resolve_blob(&cfg, 4, "uuid-legacy", Some("2026/10/uuid-legacy")).unwrap();
        // No cache materialization: caller gets the legacy path back
        assert_eq!(p.canonicalize().unwrap(), raw.canonicalize().unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"legacy-plaintext");
        assert!(!cfg.blob_root.join("dec_cache").exists());
    }

    #[test]
    fn sweep_dec_cache_removes_only_stale_files() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        let cache_dir = cfg.blob_root.join("dec_cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let fresh = cache_dir.join("fresh");
        let stale = cache_dir.join("stale");
        std::fs::write(&fresh, b"plaintext-fresh").unwrap();
        std::fs::write(&stale, b"plaintext-stale").unwrap();

        let now = std::time::SystemTime::now();
        let stale_secs = (now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64) - 10 * 86400;
        // backdate the stale file's mtime (std::fs::File::set_times, Rust 1.75+)
        let f = std::fs::File::open(&stale).unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(stale_secs as u64);
        f.set_times(std::fs::FileTimes::new().set_modified(mtime)).unwrap();
        drop(f);

        // cutoff = now - 1 day: only the backdated file is swept
        let cutoff = crate::config::Config::now() - 86400;
        assert_eq!(sweep_dec_cache(&cfg, cutoff), 1);
        assert!(!stale.exists());
        assert!(fresh.exists());
        // second run: nothing left to sweep
        assert_eq!(sweep_dec_cache(&cfg, cutoff), 0);
    }

    #[test]
    fn migrate_plaintext_blobs_rewrites_in_place_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let cfg = cfg_with(&dir);
        let app_root = app_dir(&cfg, 5);
        std::fs::create_dir_all(app_root.join("2026").join("10")).unwrap();
        let legacy = app_root.join("2026").join("10").join("uuid-mig");
        std::fs::write(&legacy, b"to-be-encrypted").unwrap();
        // A leftover tmp file and a service dir must be skipped
        std::fs::write(cfg.blob_root.join("tmp_zzz"), b"partial").unwrap();
        std::fs::create_dir_all(cfg.blob_root.join("dec_cache")).unwrap();
        std::fs::write(cfg.blob_root.join("dec_cache").join("x"), b"cache").unwrap();

        assert_eq!(migrate_plaintext_blobs(&cfg).unwrap(), 1);
        assert!(blob_is_encrypted(&legacy));
        // Content decrypts back to the original plaintext
        let env = std::fs::read(&legacy).unwrap();
        assert_eq!(
            crypto::blob_decrypt(cfg.server_secret.as_bytes(), &env).unwrap(),
            b"to-be-encrypted"
        );
        // Idempotent: second run migrates nothing
        assert_eq!(migrate_plaintext_blobs(&cfg).unwrap(), 0);
    }
}
