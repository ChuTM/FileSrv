use crate::authz::Identity;
use crate::crypto;
use crate::db::{self, Db};
use rusqlite::params;

pub enum AuthError {
    Missing,
    Invalid,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            AuthError::Missing => "Authentication required.",
            AuthError::Invalid => "Invalid credentials.",
        })
    }
}

/// Request components that enter the HMAC canonical string, bundled to keep
/// `verify_app_signature` signature manageable (clippy too_many_arguments).
pub struct SignatureParts<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub body_hash: &'a str,
    pub client_ip: &'a str,
}

/// Verify X-App-Key + HMAC request signature (with timestamp window + nonce).
/// `body_hash` must be the sha256 of the request body ("" for empty).
pub fn verify_app_signature(
    db: &Db,
    server_secret: &[u8],
    app_key: &str,
    signature: &str,
    ts: &str,
    nonce: &str,
    parts: &SignatureParts,
) -> Result<i64, AuthError> {
    let now = crate::config::Config::now();
    let ts_val: i64 = ts.parse().map_err(|_| AuthError::Invalid)?;
    // Timestamp window: ±300s to block replay.
    if (now - ts_val).abs() > 300 {
        return Err(AuthError::Invalid);
    }

    let conn = db.lock().unwrap();
    let app = db::app_by_key(&conn, app_key).map_err(|_| AuthError::Invalid)?;
    let app = match app {
        Some(a) if a.enabled && a.deleted_at.is_none() => a,
        _ => return Err(AuthError::Invalid),
    };
    let secret = crypto::open(server_secret, &app.secret_sealed).ok_or(AuthError::Invalid)?;

    // Replay protection: nonce must be unique (per app).
    let inserted = conn
        .execute(
            "INSERT INTO nonces(nonce,app_id,created_at) VALUES(?1,?2,?3) ON CONFLICT(nonce) DO NOTHING",
            params![nonce, app.id, now],
        )
        .map_err(|_| AuthError::Invalid)?;
    if inserted == 0 {
        return Err(AuthError::Invalid); // nonce seen before -> replay
    }

    let canonical = crypto::app_canonical(parts.method, parts.path, parts.query, parts.body_hash, ts, nonce);
    let expect = crypto::app_signature(&secret, &canonical);
    if !crypto::constant_time_eq(expect.as_bytes(), signature.as_bytes()) {
        return Err(AuthError::Invalid);
    }
    db::audit(&conn, &db::AuditEntry { actor: &format!("app:{}", app.id), action: "auth.app", app_id: Some(app.id), target: parts.path, ip: parts.client_ip, decision: "allow" }, now);
    Ok(app.id)
}

/// Verify a user-context JWT (HS256 signed with the App's secret).
/// Header: Authorization: Bearer <jwt>
pub fn verify_user_jwt(db: &Db, server_secret: &[u8], token: &str) -> Result<Identity, AuthError> {
    let claims = crypto::jwt_decode_public(token).ok_or(AuthError::Invalid)?;
    // iss must be "app:{id}"
    let app_id: i64 = claims
        .iss
        .strip_prefix("app:")
        .and_then(|s| s.parse().ok())
        .ok_or(AuthError::Invalid)?;
    if claims.exp <= crate::config::Config::now() {
        return Err(AuthError::Invalid);
    }
    let conn = db.lock().unwrap();
    let app = db::app_by_id(&conn, app_id).map_err(|_| AuthError::Invalid)?;
    let app = match app {
        Some(a) if a.enabled && a.deleted_at.is_none() => a,
        _ => return Err(AuthError::Invalid),
    };
    let secret = crypto::open(server_secret, &app.secret_sealed).ok_or(AuthError::Invalid)?;
    if !crypto::jwt_verify_signature(&secret, token) {
        return Err(AuthError::Invalid);
    }
    // user must exist inside the app (UNIQUE(app_id,user_id)); register is only
    // allowed through app-level identity, so an unknown user here is denied.
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM app_users WHERE app_id=?1 AND user_id=?2",
            params![app_id, claims.sub],
            |r| r.get::<_, i64>(0).map(|c| c > 0),
        )
        .map_err(|_| AuthError::Invalid)?;
    if !exists {
        return Err(AuthError::Invalid);
    }
    Ok(Identity::User {
        app_id,
        user_id: claims.sub,
    })
}

/// Admin: constant-time Bearer token check (bound to localhost by the router).
pub fn verify_admin(admin_token: &str, provided: &str) -> Result<(), AuthError> {
    if crypto::constant_time_eq(admin_token.as_bytes(), provided.as_bytes()) {
        Ok(())
    } else {
        Err(AuthError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{migrate, open_db};
    use crate::crypto;
    use tempfile::TempDir;

    fn setup_app_row(db: &Db) -> i64 {
        let conn = db.lock().unwrap();
        let secret = "app-secret-001";
        let sealed = crypto::seal(b"server-secret", secret.as_bytes());
        conn.execute(
            "INSERT INTO apps(name,app_key,secret_sealed,quota_bytes,max_payload_bytes,created_at)
             VALUES('TestApp','app_key_1',?1,1000000,1024,0)",
            params![sealed],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn app_hmac_roundtrip_and_replay_blocked() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("fs.db")).unwrap();
        migrate(&conn).unwrap();
        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let app_id = setup_app_row(&db);
        let _ = app_id;

        let secret = b"app-secret-001";
        let now = crate::config::Config::now();
        let nonce = "n1";
        let canonical = crypto::app_canonical("POST", "/v1/upload", "", "hash", &now.to_string(), nonce);
        let sig = crypto::app_signature(secret, &canonical);
        fn sp<'a>(method: &'a str, path: &'a str, query: &'a str, body_hash: &'a str, client_ip: &'a str) -> SignatureParts<'a> {
            SignatureParts {
                method,
                path,
                query,
                body_hash,
                client_ip,
            }
        }

        let ok = verify_app_signature(&db, b"server-secret", "app_key_1", &sig, &now.to_string(), nonce, &sp("POST", "/v1/upload", "", "hash", "1.1.1.1"));
        assert!(ok.is_ok());

        // replay same nonce -> denied
        let again = verify_app_signature(&db, b"server-secret", "app_key_1", &sig, &now.to_string(), nonce, &sp("POST", "/v1/upload", "", "hash", "1.1.1.1"));
        assert!(again.is_err());

        // stale timestamp -> denied
        let stale = (now - 9999).to_string();
        let sig2 = crypto::app_signature(secret, &crypto::app_canonical("POST", "/v1/upload", "", "hash", &stale, "n2"));
        assert!(verify_app_signature(&db, b"server-secret", "app_key_1", &sig2, &stale, "n2", &sp("POST", "/v1/upload", "", "hash", "1.1.1.1")).is_err());

        // wrong signature -> denied
        assert!(verify_app_signature(&db, b"server-secret", "app_key_1", "deadbeef", &now.to_string(), "n3", &sp("POST", "/v1/upload", "", "hash", "1.1.1.1")).is_err());
    }

    #[test]
    fn jwt_only_valid_for_registered_users() {
        let dir = TempDir::new().unwrap();
        let conn = open_db(&dir.path().join("fs.db")).unwrap();
        migrate(&conn).unwrap();
        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let app_id = setup_app_row(&db);
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO app_users(app_id,user_id,created_at) VALUES(?1,'u_known',0)",
                params![app_id],
            )
            .unwrap();
        }
        let secret = b"app-secret-001";
        let jwt = crypto::jwt_encode(secret, &format!("app:{app_id}"), "u_known", crate::config::Config::now() + 3600);
        assert!(verify_user_jwt(&db, b"server-secret", &jwt).is_ok());

        // unknown user -> denied (fail-closed)
        let jwt_unknown = crypto::jwt_encode(secret, &format!("app:{app_id}"), "u_stranger", crate::config::Config::now() + 3600);
        assert!(verify_user_jwt(&db, b"server-secret", &jwt_unknown).is_err());

        // forged with wrong secret -> denied
        let jwt_forged = crypto::jwt_encode(b"wrong-secret", &format!("app:{app_id}"), "u_known", crate::config::Config::now() + 3600);
        assert!(verify_user_jwt(&db, b"server-secret", &jwt_forged).is_err());
    }
}
