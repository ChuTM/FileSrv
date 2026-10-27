use crate::crypto::random_token;
use crate::db::Db;
use crate::config::Config;
use rusqlite::params;

pub struct Grant {
    pub app_id: i64,
    pub file_id: i64,
    pub user_id: String,
    pub scope: String,
}

/// Idempotent fixed-window embed token:
/// same (app_id, file_id, user_id, scope) returns the SAME token within the
/// window (no TTL extension); once expired or revoked, a new token is minted.
pub fn generate_embed(
    db: &Db,
    _cfg: &Config,
    app_id: i64,
    file_id: i64,
    user_id: &str,
    ttl_secs: i64,
) -> (String, bool) {
    let embed_key = format!("app:{app_id}:embed:{file_id}:{user_id}:embed");
    let now = Config::now();
    let conn = db.lock().unwrap();

    // Existing, active, not revoked -> reuse without extending.
    let existing = conn
        .query_row(
            "SELECT token FROM tokens WHERE embed_key=?1 AND revoked=0 AND expires_at>?2",
            params![embed_key, now],
            |r| r.get::<_, String>(0),
        )
        .ok();
    if let Some(tok) = existing {
        return (tok, true);
    }

    // Mint (or re-mint after expiry/revoke).
    let token = random_token();
    let expires = now + ttl_secs.clamp(60, 86400);
    conn.execute(
        "DELETE FROM tokens WHERE embed_key=?1",
        params![embed_key],
    )
    .ok();
    conn.execute(
        "INSERT INTO tokens(token,app_id,file_id,user_id,scope,embed_key,allowed_ip,created_at,expires_at,revoked)
         VALUES(?1,?2,?3,?4,'embed',?5,NULL,?6,?7,0)",
        params![token, app_id, file_id, user_id, embed_key, now, expires],
    )
    .ok();
    (token, false)
}

/// One-time share token; IP binding optional.
pub fn generate_share(
    db: &Db,
    app_id: i64,
    file_id: i64,
    user_id: &str,
    ttl_secs: i64,
    allowed_ip: Option<&str>,
) -> String {
    let token = random_token();
    let now = Config::now();
    let expires = now + ttl_secs.clamp(60, 86400);
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO tokens(token,app_id,file_id,user_id,scope,embed_key,allowed_ip,created_at,expires_at,revoked)
         VALUES(?1,?2,?3,?4,'share',NULL,?5,?6,?7,0)",
        params![token, app_id, file_id, user_id, allowed_ip, now, expires],
    )
    .ok();
    token
}

/// Verify a capability token: exists, not revoked, not expired. Returns grant.
pub fn verify(db: &Db, token: &str, client_ip: &str) -> Option<Grant> {
    let now = Config::now();
    let conn = db.lock().unwrap();
    let row: Option<(i64, i64, String, String, Option<String>)> = conn
        .query_row(
            "SELECT app_id,file_id,user_id,scope,allowed_ip FROM tokens
             WHERE token=?1 AND revoked=0 AND expires_at>?2",
            params![token, now],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .ok();
    let (app_id, file_id, user_id, scope, allowed_ip) = row?;
    if let Some(ip) = allowed_ip {
        if ip != client_ip {
            return None; // IP mismatch -> denied
        }
    }
    Some(Grant {
        app_id,
        file_id,
        user_id,
        scope,
    })
}

/// Revoke a token: immediately invalid, and the embed slot is freed so the next
/// generate mints a brand-new token.
pub fn revoke(db: &Db, token: &str) -> bool {
    let now = Config::now();
    let conn = db.lock().unwrap();
    let embed_key: Option<String> = conn
        .query_row(
            "SELECT embed_key FROM tokens WHERE token=?1 AND revoked=0 AND expires_at>?2",
            params![token, now],
            |r| r.get(0),
        )
        .ok();
    if let Some(ek) = embed_key {
        // "DEL tok + DEL embed": clears every token bound to the slot.
        conn.execute("DELETE FROM tokens WHERE embed_key=?1", params![ek])
            .ok();
        return true;
    }
    let affected = conn
        .execute(
            "UPDATE tokens SET revoked=1 WHERE token=?1 AND revoked=0 AND expires_at>?2",
            params![token, now],
        )
        .unwrap_or(0);
    affected > 0
}

/// Drop all tokens bound to a file (on delete).
pub fn revoke_file_tokens(db: &Db, file_id: i64) {
    let conn = db.lock().unwrap();
    conn.execute("DELETE FROM tokens WHERE file_id=?1", params![file_id])
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_db, migrate};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Config, Db) {
        let dir = TempDir::new().unwrap();
        let cfg = Config {
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
        };
        let conn = open_db(&cfg.db_path).unwrap();
        migrate(&conn).unwrap();
        (dir, cfg, std::sync::Arc::new(std::sync::Mutex::new(conn)))
    }

    #[test]
    fn embed_is_idempotent_within_window() {
        let (_d, cfg, db) = setup();
        let (t1, reused1) = generate_embed(&db, &cfg, 1, 10, "u_1", 1800);
        assert!(!reused1);
        let (t2, reused2) = generate_embed(&db, &cfg, 1, 10, "u_1", 1800);
        assert!(reused2);
        assert_eq!(t1, t2);

        // Different user -> different token
        let (t3, _) = generate_embed(&db, &cfg, 1, 10, "u_2", 1800);
        assert_ne!(t1, t3);

        // verify works
        let g = verify(&db, &t1, "1.2.3.4").unwrap();
        assert_eq!(g.file_id, 10);
        assert_eq!(g.user_id, "u_1");
    }

    #[test]
    fn revoke_immediately_invalidates_and_next_generate_mints_new() {
        let (_d, cfg, db) = setup();
        let (t1, _) = generate_embed(&db, &cfg, 1, 10, "u_1", 1800);
        assert!(verify(&db, &t1, "ip").is_some());

        assert!(revoke(&db, &t1));
        assert!(verify(&db, &t1, "ip").is_none()); // immediately invalid

        let (t2, reused) = generate_embed(&db, &cfg, 1, 10, "u_1", 1800);
        assert!(!reused); // minted new
        assert_ne!(t1, t2);
        assert!(verify(&db, &t2, "ip").is_some());
    }

    #[test]
    fn share_token_respects_allowed_ip() {
        let (_d, _cfg, db) = setup();
        let t = generate_share(&db, 1, 10, "u_1", 300, Some("203.0.113.45"));
        assert!(verify(&db, &t, "203.0.113.45").is_some());
        assert!(verify(&db, &t, "6.6.6.6").is_none());
    }

    #[test]
    fn expired_token_denied() {
        let (_d, cfg, db) = setup();
        let (t1, _) = generate_embed(&db, &cfg, 1, 10, "u_1", 60);
        // force expiry
        let conn = db.lock().unwrap();
        conn.execute("UPDATE tokens SET expires_at=?1 WHERE token=?2", params![Config::now() - 1, t1]).unwrap();
        drop(conn);
        assert!(verify(&db, &t1, "ip").is_none());
    }
}
