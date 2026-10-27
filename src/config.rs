use std::path::PathBuf;

/// Development-only default; production deployments must set
/// TENANT_FS_SERVER_SECRET explicitly (see §5.6 of the test report).
pub const DEFAULT_SERVER_SECRET: &str = "dev-server-secret-change-me";

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
                .unwrap_or_else(|_| "dev-admin-token".to_string()),
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
        }
    }

    pub fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }
}
