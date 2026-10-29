use std::path::PathBuf;

/// Development-only default; production deployments must set
/// TENANT_FS_SERVER_SECRET explicitly (see §5.6 of the test report).
pub const DEFAULT_SERVER_SECRET: &str = "dev-server-secret-change-me";

/// Development-only default admin token; production deployments must set
/// TENANT_FS_ADMIN_TOKEN explicitly.
pub const DEFAULT_ADMIN_TOKEN: &str = "dev-admin-token";

#[derive(Clone, Debug)]
pub struct Config {
    pub db_path: PathBuf,
    pub blob_root: PathBuf,
    pub admin_token: String,
    pub server_secret: String,
    pub public_bind: String,
    pub admin_bind: String,
    pub embed_ttl_secs: i64,
    pub share_ttl_secs: i64,
    pub max_batch_acl: usize,
    /// Trust the X-Forwarded-For header for client IP (must be enabled only
    /// behind a reverse proxy that overwrites it). Default: use the socket
    /// peer IP so the header cannot be spoofed.
    pub trust_xff: bool,
    /// Audit log retention window in seconds (rows older than this are pruned).
    pub audit_retention_secs: i64,
    /// Encrypt newly written blobs at rest (envelope KEK/DEK, see crypto.rs).
    /// Default: on. Legacy plaintext blobs are still read transparently.
    pub encrypt_blobs: bool,
    /// Soft-delete grace: DELETE marks a tombstone and rolls usage back
    /// immediately; the blob file and row survive this many seconds and are
    /// then physically removed by the background purge loop. 0 = purge on
    /// the next tick (used by tests/E2E to avoid waiting days).
    pub soft_delete_grace_secs: i64,
    /// Period of the background maintenance loop (nonce/audit pruning + tombstone
    /// purge). Short for tests/E2E; 600s in production.
    pub purge_interval_secs: u64,
    /// Refuse to start when the admin bind is not loopback. The admin surface
    /// (API + console) is designed for localhost only; this is a safe default
    /// that prevents accidental exposure via misconfiguration (F6 fix).
    /// Set TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN=true to override at your own risk.
    pub allow_non_loopback_admin: bool,
}

/// Operational knobs that were added with the API layer (backup, chunked
/// upload, rate limiting, idempotency, export TTL). Kept in a separate struct
/// so the storage-layer test fixtures (which build `Config` literally) are
/// untouched. All values have safe defaults; every knob is overridable via
/// environment variable.
#[derive(Clone, Debug)]
pub struct Ops {
    /// Root directory backups are written under. Any configured backup target
    /// must canonicalize inside this root (defense against path/symlink escape).
    pub backup_root: PathBuf,
    /// Number of backup copies to retain (newest win); older ones are deleted.
    pub backup_retention: usize,
    /// Automatic scheduled-backup interval in seconds (0 = no scheduled run;
    /// the maintenance loop still honors a per-deployment override stored in
    /// the `backup_settings` DB table via PATCH /admin/v1/backups/config).
    pub backup_schedule_secs: u64,
    /// In-flight chunked uploads expire after this many seconds and are
    /// swept (staged partial files unlinked).
    pub chunk_ttl_secs: i64,
    /// Per-app request budget per 60s window, shared by generate/upload/export
    /// and chunked-upload calls. 0 = disabled.
    pub rate_limit_per_min: u32,
    /// Hard capacity of the in-memory rate-limit map (anti memory-bomb).
    pub rate_limit_max_entries: usize,
    /// Idempotency-Key cache window: a cached upload result is reused within
    /// this many seconds; after the window the key behaves as a new upload.
    pub idem_window_secs: i64,
    /// Hard capacity of the idempotency cache.
    pub idem_max_entries: usize,
    /// Export artifacts (tar/zip) and their rows are swept this many seconds
    /// after the job finished.
    pub export_ttl_secs: i64,
    /// Plaintext decrypt-cache entries (blob_root/dec_cache) older than this
    /// are swept by the maintenance loop. The cache is a re-creatable
    /// materialization of an encrypted blob, so it must not persist plaintext
    /// on disk indefinitely (F2 fix).
    pub dec_cache_ttl_secs: i64,
    /// Opt-in: record an audit row for every successful download (GET
    /// /v1/download/:token). Off by default to avoid audit volume on high-read
    /// workloads; enable it when a per-download trail is required (e.g. for
    /// sensitive files).
    pub audit_downloads: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            db_path: PathBuf::from(env_or("TENANT_FS_DB", "data/fs.db")),
            blob_root: PathBuf::from(env_or("TENANT_FS_BLOBS", "data/blobs")),
            admin_token: std::env::var("TENANT_FS_ADMIN_TOKEN")
                .unwrap_or_else(|_| DEFAULT_ADMIN_TOKEN.to_string()),
            server_secret: std::env::var("TENANT_FS_SERVER_SECRET")
                .unwrap_or_else(|_| DEFAULT_SERVER_SECRET.to_string()),
            public_bind: env_or("TENANT_FS_PUBLIC_BIND", "0.0.0.0:8080"),
            admin_bind: env_or("TENANT_FS_ADMIN_BIND", "127.0.0.1:8081"),
            embed_ttl_secs: env_or("TENANT_FS_EMBED_TTL", "1800").parse().unwrap_or(1800),
            share_ttl_secs: env_or("TENANT_FS_SHARE_TTL", "300").parse().unwrap_or(300),
            max_batch_acl: env_or("TENANT_FS_MAX_BATCH_ACL", "1000")
                .parse()
                .unwrap_or(1000),
            trust_xff: matches!(
                env_or("TENANT_FS_TRUST_XFF", "false").as_str(),
                "true" | "1" | "yes" | "on"
            ),
            audit_retention_secs: env_or("TENANT_FS_AUDIT_RETENTION_DAYS", "30")
                .parse::<i64>()
                .unwrap_or(30)
                .max(1)
                * 86400,
            encrypt_blobs: matches!(
                env_or("TENANT_FS_ENCRYPT_BLOBS", "true").as_str(),
                "true" | "1" | "yes" | "on"
            ),
            soft_delete_grace_secs: env_or("TENANT_FS_SOFT_DELETE_DAYS", "7")
                .parse::<i64>()
                .unwrap_or(7)
                .max(0)
                * 86400,
            purge_interval_secs: env_or("TENANT_FS_PURGE_INTERVAL_SECS", "600")
                .parse::<u64>()
                .unwrap_or(600)
                .clamp(1, 86400),
            allow_non_loopback_admin: matches!(
                env_or("TENANT_FS_ALLOW_NON_LOOPBACK_ADMIN", "false").as_str(),
                "true" | "1" | "yes" | "on"
            ),
        }
    }

    pub fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }
}

impl Ops {
    pub fn from_env() -> Self {
        Ops {
            backup_root: PathBuf::from(env_or("TENANT_FS_BACKUP_ROOT", "data/backups")),
            backup_retention: env_or("TENANT_FS_BACKUP_RETENTION", "7")
                .parse::<usize>()
                .unwrap_or(7)
                .clamp(1, 1000),
            backup_schedule_secs: env_or("TENANT_FS_BACKUP_SCHEDULE_SECS", "0")
                .parse::<u64>()
                .unwrap_or(0),
            chunk_ttl_secs: env_or("TENANT_FS_UPLOAD_TTL_SECS", "86400")
                .parse::<i64>()
                .unwrap_or(86400)
                .max(60),
            rate_limit_per_min: env_or("TENANT_FS_RATE_LIMIT_PER_MIN", "120")
                .parse::<u32>()
                .unwrap_or(120),
            rate_limit_max_entries: env_or("TENANT_FS_RATE_LIMIT_MAX_ENTRIES", "10000")
                .parse::<usize>()
                .unwrap_or(10000),
            idem_window_secs: env_or("TENANT_FS_IDEMPOTENCY_WINDOW_SECS", "3600")
                .parse::<i64>()
                .unwrap_or(3600)
                .max(60),
            idem_max_entries: env_or("TENANT_FS_IDEMPOTENCY_MAX_ENTRIES", "10000")
                .parse::<usize>()
                .unwrap_or(10000),
            // Floor of 1s only guards against 0/negative; E2E uses a short TTL.
            export_ttl_secs: env_or("TENANT_FS_EXPORT_TTL_SECS", "86400")
                .parse::<i64>()
                .unwrap_or(86400)
                .max(1),
            dec_cache_ttl_secs: env_or("TENANT_FS_DEC_CACHE_TTL_SECS", "86400")
                .parse::<i64>()
                .unwrap_or(86400)
                .max(60),
            audit_downloads: matches!(
                env_or("TENANT_FS_AUDIT_DOWNLOADS", "false").as_str(),
                "true" | "1" | "yes" | "on"
            ),
        }
    }
}
