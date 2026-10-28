use crate::authz::{Acl, Identity};
use crate::crypto::{self, sha256};
use crate::db::{self};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;
use crate::routes::common::{
    actor_label, app_identity_id, bytes_ctx, json_response, validate_user_id,
};
use crate::routes::{extract_identity, ReqCtx};
use crate::state::AppState;
use crate::storage;
use crate::upload;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::Request;
use futures_util::StreamExt;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// RAII guard for in-flight upload temp blobs: removes `tmp_*` on drop unless
/// disarmed after a successful commit, so interrupted uploads never leak files.
struct TempBlobGuard(std::path::PathBuf, bool);
impl Drop for TempBlobGuard {
    fn drop(&mut self) {
        if !self.1 {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

// ---------------- Upload ----------------

pub async fn upload(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let uri = req.uri();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let method = req.method().as_str().to_string();
    let headers = req.headers().clone();
    // Client IP for the audit record: socket peer by default, XFF only when
    // trusted-proxy mode is explicitly enabled (see ReqCtx::client_ip).
    let peer = crate::routes::peer_ip_of(&req);
    let ip = if st.cfg.trust_xff {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
            .unwrap_or_else(|| peer.clone())
    } else {
        peer.clone()
    };

    // Reject obviously-invalid app-level requests BEFORE streaming the body:
    // a request claiming app identity but missing the signature/timestamp/nonce
    // headers can never verify, so do not make the server buffer its body to a
    // temp file first (test report §5.3).
    if headers.contains_key("x-app-key") {
        let missing: Vec<&str> = [
            ("x-app-signature", headers.contains_key("x-app-signature")),
            ("x-timestamp", headers.contains_key("x-timestamp")),
            ("x-nonce", headers.contains_key("x-nonce")),
        ]
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(name, _)| *name)
        .collect();
        if !missing.is_empty() {
            return Err(ApiError::unauthorized(format!(
                "Missing signature header(s): {}.",
                missing.join(", ")
            )));
        }
    }

    // Identify: App-level (HMAC, verified after streaming) or user JWT.
    let identity: Identity = if headers.contains_key("x-app-key") {
        let app_key = headers
            .get("x-app-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let conn = st.db.lock().unwrap();
        let app = db::app_by_key(&conn, &app_key)
            .ok()
            .flatten()
            .filter(|a| a.enabled && a.deleted_at.is_none())
            .ok_or_else(|| ApiError::unauthorized("Invalid app credentials."))?;
        Identity::App(app.id)
    } else if let Some(bearer) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|b| b.strip_prefix("Bearer ").map(|s| s.to_string()))
    {
        crate::auth::verify_user_jwt(&st.db, st.cfg.server_secret.as_bytes(), &bearer)
            .map_err(|e| match e {
                crate::auth::AuthError::Missing => {
                    ApiError::unauthorized("Authentication required.")
                }
                crate::auth::AuthError::Invalid => {
                    ApiError::unauthorized("Invalid credentials.")
                }
            })?
    } else {
        return Err(ApiError::unauthorized("Authentication required."));
    };

    let app_id = app_identity_id(&identity);
    let app = {
        let conn = st.db.lock().unwrap();
        db::app_by_id(&conn, app_id)?.filter(|a| a.deleted_at.is_none())
    };
    let app = match app {
        Some(a) if a.enabled => a,
        _ => return Err(ApiError::unauthorized("App not found or disabled.")),
    };
    let max_payload = app.max_payload_bytes;

    // Optional Idempotency-Key: a retried upload within the window returns the
    // original file metadata instead of writing a second blob.
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty() && s.len() <= 128);

    // user_id: from JWT, or App vouches via X-User-Id header.
    let user_id = match &identity {
        Identity::User { user_id, .. } => user_id.clone(),
        Identity::App(_) => headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::bad_request("X-User-Id header required for app-level upload.")
            })?
            .to_string(),
        _ => return Err(ApiError::forbidden("Upload not allowed for this identity.")),
    };
    validate_user_id(&user_id)?;

    // Optional folder target (must belong to the app).
    let folder_id = {
        let q = url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "folder_id")
            .map(|(_, v)| v.into_owned());
        match q {
            Some(fid) => {
                let fid: i64 = fid
                    .parse()
                    .map_err(|_| ApiError::bad_request("Invalid folder_id."))?;
                let conn = st.db.lock().unwrap();
                match db::folder_by_id(&conn, fid)? {
                    Some(f) if f.app_id == app_id && f.deleted_at.is_none() => Some(fid),
                    _ => return Err(ApiError::not_found("Folder not found.")),
                }
            }
            None => None,
        }
    };

    // Stream body to a temp file, enforcing max payload incrementally.
    let uuid = crypto::new_uuid();
    let tmp_path = st.cfg.blob_root.join(format!("tmp_{uuid}"));
    if let Some(parent) = tmp_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // RAII: the temp file is removed on ANY error path (including client
    // disconnect mid-stream), and only kept once committed below.
    let mut guard = TempBlobGuard(tmp_path.clone(), false);
    let body = req.into_body();
    let mut stream = http_body_util::BodyStream::new(body);
    let mut file = tokio::fs::File::create(&tmp_path).await?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    while let Some(frame) = stream.next().await {
        let frame = frame.map_err(|_| ApiError::internal())?;
        if let Some(data) = frame.data_ref() {
            size += data.len() as u64;
            if size > max_payload as u64 {
                return Err(ApiError::too_large(format!(
                    "Payload exceeds app limit of {max_payload} bytes."
                )));
            }
            hasher.update(data);
            file.write_all(data).await?;
        }
    }
    file.flush().await?;
    drop(file);
    let body_hash = hex::encode(hasher.finalize());

    // Verify app HMAC now that body hash is known (JWT path skips this).
    if let Identity::App(_) = &identity {
        let ctx = ReqCtx {
            method,
            path,
            query,
            headers,
            body_hash: body_hash.clone(),
            peer_ip: peer.clone(),
            trust_xff: st.cfg.trust_xff,
        };
        extract_identity(&st, &ctx)
            .map_err(|_| ApiError::unauthorized("Invalid app signature."))?
            .app_id()
            .map_or(Err(ApiError::unauthorized("Invalid app signature.")), |id| {
                if id == app_id {
                    Ok(())
                } else {
                    Err(ApiError::unauthorized("Invalid app signature."))
                }
            })?;
    }

    // Per-app rate-limit gate (generate/upload/export share one bucket, §11).
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    // Idempotency retry: a cached, in-window result is returned as-is. The temp
    // file from this request is dropped by the RAII guard on the way out.
    if let Some(key) = &idem_key {
        if let Some(cached) = st.idem.get(app_id, key) {
            return Ok(json_response(cached));
        }
    }

    // Atomically: quota check + file insert + usage increment + register user.
    let file_id: i64 = {
        let mut conn = st.db.lock().unwrap();
        let tx = conn.transaction().map_err(ApiError::from)?;
        let usage: i64 = tx
            .query_row(
                "SELECT usage_bytes FROM apps WHERE id=?1",
                params![app_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if usage.saturating_add(size as i64) > app.quota_bytes {
            return Err(ApiError::quota("App storage quota exceeded."));
        }
        tx.execute(
            "INSERT OR IGNORE INTO app_users(app_id,user_id,created_at) VALUES(?1,?2,?3)",
            params![app_id, user_id, crate::config::Config::now()],
        )?;
        let owner = user_id.clone();
        let acl = Acl {
            owner: owner.clone(),
            ..Default::default()
        }
        .to_json();
        let blob_rel = storage::blob_rel_for_new(&st.cfg, &uuid);
        tx.execute(
            "INSERT INTO files(app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'internal',?10,?11,?12)",
            params![
                app_id,
                user_id,
                folder_id,
                uuid,
                blob_rel,
                uuid.clone(),
                "application/octet-stream",
                size as i64,
                body_hash,
                owner,
                acl,
                crate::config::Config::now()
            ],
        )?;
        let fid = tx.last_insert_rowid();
        tx.execute(
            "UPDATE apps SET usage_bytes = usage_bytes + ?1 WHERE id=?2",
            params![size as i64, app_id],
        )?;
        tx.commit().map_err(ApiError::from)?;
        fid
    };

    // Stage the bytes that will be committed to disk. With at-rest encryption
    // enabled (default) the streamed plaintext temp file is sealed into an
    // envelope frame (crypto::blob_encrypt, per-blob DEK); the DB row keeps
    // plaintext size/sha256, so downloads, ranges and quota are unchanged.
    // KEK = SHA-256(SERVER_SECRET); SERVER_SECRET is never backed up, so a
    // stolen blob archive without it is undecryptable (see crypto.rs).
    let staged: std::path::PathBuf = if st.cfg.encrypt_blobs {
        let plaintext = std::fs::read(&tmp_path).map_err(|_| ApiError::internal())?;
        let sealed = crypto::blob_encrypt(st.cfg.server_secret.as_bytes(), &plaintext);
        let enc_path = st.cfg.blob_root.join(format!("tmp_enc_{uuid}"));
        if let Err(e) = std::fs::write(&enc_path, &sealed) {
            let _ = std::fs::remove_file(&enc_path);
            return Err(ApiError::internal_msg(format!("Blob encryption failed: {e}")));
        }
        let _ = std::fs::remove_file(&tmp_path);
        guard.0 = enc_path.clone(); // RAII now guards the staged envelope file
        enc_path
    } else {
        tmp_path.clone()
    };

    // Commit staged blob into app dir; on failure roll back DB row + usage.
    if let Err(e) = storage::commit_blob(&st.cfg, app_id, &uuid, &staged) {
        let conn = st.db.lock().unwrap();
        conn.execute("DELETE FROM files WHERE id=?1", params![file_id]).ok();
        conn.execute(
            "UPDATE apps SET usage_bytes = MAX(0, usage_bytes - ?1) WHERE id=?2",
            params![size as i64, app_id],
        )
        .ok();
        return Err(ApiError::internal_msg(format!("Blob commit failed: {e}")));
    }
    guard.1 = true; // blob committed; keep the staged file.

    {
        let conn = st.db.lock().unwrap();
        db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "upload", app_id: Some(app_id), target: &uuid, ip: &ip, decision: "allow" }, crate::config::Config::now());
    }

    let response = json!({
        "file_id": file_id,
        "app_id": format!("app_{app_id}"),
        "owner": user_id,
        "storage_uuid": uuid,
        "size": size,
        "sha256": body_hash,
        "classification": "internal",
        "content_type": "application/octet-stream"
    });
    if let Some(key) = &idem_key {
        st.idem.put(app_id, key, response.clone());
    }
    Ok(json_response(response))
}

// ---------------- Chunked / resumable upload (§4) ----------------

/// POST /v1/upload/init — open a resumable upload session.
pub async fn upload_init(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    let body: Value = serde_json::from_slice(&ctx.body).unwrap_or(Value::Null);
    let total_size: Option<i64> = body.get("total_size").and_then(|v| v.as_i64());
    if let Some(ts) = total_size {
        if ts < 0 {
            return Err(ApiError::bad_request("total_size must be >= 0."));
        }
    }

    let app = {
        let conn = st.db.lock().unwrap();
        db::app_by_id(&conn, app_id)?.filter(|a| a.enabled && a.deleted_at.is_none())
    };
    let app = match app {
        Some(a) => a,
        _ => return Err(ApiError::unauthorized("App not found or disabled.")),
    };
    if let Some(ts) = total_size {
        if ts > app.max_payload_bytes {
            return Err(ApiError::too_large(format!(
                "total_size exceeds app limit of {} bytes.",
                app.max_payload_bytes
            )));
        }
    }

    let user_id = match &identity {
        Identity::User { user_id, .. } => user_id.clone(),
        Identity::App(_) => ctx
            .header("x-user-id")
            .ok_or_else(|| ApiError::bad_request("X-User-Id header required for app-level upload."))?,
        _ => return Err(ApiError::forbidden("Upload not allowed for this identity.")),
    };
    validate_user_id(&user_id)?;

    let folder_id: Option<i64> = body.get("folder_id").and_then(|v| v.as_i64());
    if let Some(fid) = folder_id {
        let conn = st.db.lock().unwrap();
        match db::folder_by_id(&conn, fid)? {
            Some(f) if f.app_id == app_id && f.deleted_at.is_none() => {}
            _ => return Err(ApiError::not_found("Folder not found.")),
        }
    }

    let upload_id = format!("up_{}", crypto::random_token());
    let staged = upload::staged_path(&st.cfg, &upload_id);
    {
        let conn = st.db.lock().unwrap();
        upload::create(
            &conn,
            &upload_id,
            app_id,
            &user_id,
            folder_id,
            total_size,
            staged.to_string_lossy().as_ref(),
            st.ops.chunk_ttl_secs,
        )?;
    }

    Ok(json_response(json!({
        "upload_id": upload_id,
        "status": "open",
        "total_size": total_size,
        "received_size": 0,
        "chunk_ttl_secs": st.ops.chunk_ttl_secs,
        "max_payload_bytes": app.max_payload_bytes
    })))
}

/// PUT /v1/upload/{upload_id} — append one chunk (raw bytes, offset via
/// X-Chunk-Offset header). Chunks must arrive contiguously; a gap returns 409
/// with the current received_size so the client can resume.
pub async fn upload_chunk(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let uri = req.uri();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let method = req.method().as_str().to_string();
    let headers = req.headers().clone();
    let upload_id = uri.path().split('/').nth(3).unwrap_or("").to_string();
    if upload_id.is_empty() {
        return Err(ApiError::bad_request("upload_id is required."));
    }

    // Reject obviously-invalid app-level requests BEFORE streaming (same
    // pre-check as the plain upload handler, §5.3).
    if headers.contains_key("x-app-key") {
        let missing: Vec<&str> = [
            ("x-app-signature", headers.contains_key("x-app-signature")),
            ("x-timestamp", headers.contains_key("x-timestamp")),
            ("x-nonce", headers.contains_key("x-nonce")),
        ]
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(name, _)| *name)
        .collect();
        if !missing.is_empty() {
            return Err(ApiError::unauthorized(format!(
                "Missing signature header(s): {}.",
                missing.join(", ")
            )));
        }
    }

    let offset: u64 = headers
        .get("x-chunk-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| ApiError::bad_request("X-Chunk-Offset header is required."))?;

    let peer = crate::routes::peer_ip_of(&req);
    let identity: Identity = if headers.contains_key("x-app-key") {
        let app_key = headers
            .get("x-app-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let conn = st.db.lock().unwrap();
        let app = db::app_by_key(&conn, &app_key)
            .ok()
            .flatten()
            .filter(|a| a.enabled && a.deleted_at.is_none())
            .ok_or_else(|| ApiError::unauthorized("Invalid app credentials."))?;
        Identity::App(app.id)
    } else if let Some(bearer) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|b| b.strip_prefix("Bearer ").map(|s| s.to_string()))
    {
        crate::auth::verify_user_jwt(&st.db, st.cfg.server_secret.as_bytes(), &bearer)
            .map_err(|_| ApiError::unauthorized("Invalid credentials."))?
    } else {
        return Err(ApiError::unauthorized("Authentication required."));
    };
    let app_id = app_identity_id(&identity);
    let app = {
        let conn = st.db.lock().unwrap();
        db::app_by_id(&conn, app_id)?.filter(|a| a.enabled && a.deleted_at.is_none())
    };
    let app = match app {
        Some(a) => a,
        _ => return Err(ApiError::unauthorized("App not found or disabled.")),
    };

    // Resolve the session up front (unknown / expired / cross-tenant -> 404).
    let (job_received, job_total, job_path) = {
        let conn = st.db.lock().unwrap();
        let job = upload::get(&conn, &upload_id)?;
        let job = match job {
            Some(j)
                if j.app_id == app_id && j.expires_at >= crate::config::Config::now() =>
            {
                j
            }
            _ => return Err(ApiError::not_found("Upload session not found.")),
        };
        if offset != job.received_size as u64 {
            return Err(ApiError::conflict(format!(
                "Unexpected chunk offset; resume at {}.",
                job.received_size
            )));
        }
        (job.received_size, job.total_size, job.path)
    };

    // Stream the chunk into the staged file at the given offset.
    let staged = std::path::PathBuf::from(&job_path);
    if let Some(parent) = staged.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // create(true) but NOT truncate: previous chunks must survive a retry of
    // this very chunk (set_len below rewinds the file back to `offset`).
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&staged)
        .await?;
    file.set_len(offset).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut stream = http_body_util::BodyStream::new(req.into_body());
    while let Some(frame) = stream.next().await {
        let frame = frame.map_err(|_| ApiError::internal())?;
        if let Some(data) = frame.data_ref() {
            size += data.len() as u64;
            let projected = job_received as u64 + size;
            if projected > app.max_payload_bytes as u64 {
                return Err(ApiError::too_large(format!(
                    "Payload exceeds app limit of {} bytes.",
                    app.max_payload_bytes
                )));
            }
            if let Some(ts) = job_total {
                if projected > ts as u64 {
                    return Err(ApiError::too_large(
                        "Chunk exceeds the declared total size.",
                    ));
                }
            }
            hasher.update(data);
            file.write_all(data).await?;
        }
    }
    file.flush().await?;
    drop(file);
    let body_hash = hex::encode(hasher.finalize());

    // App HMAC verified now that the chunk body hash is known.
    if let Identity::App(_) = &identity {
        let ctx = ReqCtx {
            method,
            path,
            query,
            headers,
            body_hash,
            peer_ip: peer.clone(),
            trust_xff: st.cfg.trust_xff,
        };
        extract_identity(&st, &ctx)
            .map_err(|_| ApiError::unauthorized("Invalid app signature."))?;
    }
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    let received = job_received + size as i64;
    {
        let conn = st.db.lock().unwrap();
        upload::set_received(&conn, &upload_id, received)?;
    }
    Ok(json_response(json!({
        "upload_id": upload_id,
        "received_size": received,
        "status": "open"
    })))
}

/// POST /v1/upload/{upload_id}/finalize — verify size, hash the staged file,
/// enforce quota, encrypt-write the blob through the storage layer and record
/// the file metadata.
pub async fn upload_finalize(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    let upload_id = ctx
        .path_segment(3)
        .ok_or_else(|| ApiError::bad_request("Invalid upload id."))?;

    let app = {
        let conn = st.db.lock().unwrap();
        db::app_by_id(&conn, app_id)?.filter(|a| a.enabled && a.deleted_at.is_none())
    };
    let app = match app {
        Some(a) => a,
        _ => return Err(ApiError::unauthorized("App not found or disabled.")),
    };

    let (user_id, folder_id, total_size, received, staged_path) = {
        let conn = st.db.lock().unwrap();
        let job = upload::get(&conn, &upload_id)?;
        let job = match job {
            Some(j) if j.app_id == app_id => j,
            _ => return Err(ApiError::not_found("Upload session not found.")),
        };
        if let Some(ts) = job.total_size {
            if job.received_size != ts {
                return Err(ApiError::conflict(format!(
                    "Upload incomplete: received {} of {} bytes.",
                    job.received_size, ts
                )));
            }
        }
        (job.user_id, job.folder_id, job.total_size, job.received_size, job.path)
    };
    if received > app.max_payload_bytes {
        return Err(ApiError::too_large(format!(
            "Payload exceeds app limit of {} bytes.",
            app.max_payload_bytes
        )));
    }

    let staged = std::path::PathBuf::from(&staged_path);
    let bytes = std::fs::read(&staged).map_err(|_| ApiError::internal_msg("Staged upload unreadable."))?;
    let digest = sha256(&bytes);
    let uuid = crypto::new_uuid();
    let blob_rel = storage::blob_rel_for_new(&st.cfg, &uuid);

    // Atomic: quota check + register user + file insert + usage increment.
    let file_id: i64 = {
        let mut conn = st.db.lock().unwrap();
        let tx = conn.transaction().map_err(ApiError::from)?;
        let usage: i64 = tx
            .query_row(
                "SELECT usage_bytes FROM apps WHERE id=?1",
                params![app_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if usage.saturating_add(received) > app.quota_bytes {
            return Err(ApiError::quota("App storage quota exceeded."));
        }
        tx.execute(
            "INSERT OR IGNORE INTO app_users(app_id,user_id,created_at) VALUES(?1,?2,?3)",
            params![app_id, user_id, crate::config::Config::now()],
        )?;
        let acl = Acl {
            owner: user_id.clone(),
            ..Default::default()
        }
        .to_json();
        tx.execute(
            "INSERT INTO files(app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'internal',?10,?11,?12)",
            params![
                app_id,
                user_id,
                folder_id,
                uuid,
                blob_rel,
                uuid,
                "application/octet-stream",
                received,
                digest,
                user_id,
                acl,
                crate::config::Config::now()
            ],
        )?;
        let fid = tx.last_insert_rowid();
        tx.execute(
            "UPDATE apps SET usage_bytes = usage_bytes + ?1 WHERE id=?2",
            params![received, app_id],
        )?;
        tx.commit().map_err(ApiError::from)?;
        fid
    };

    // At-rest encryption: stage the sealed envelope, then commit_blob renames
    // it into the final UUID path (same contract as plain upload).
    let staged_for_commit: std::path::PathBuf = if st.cfg.encrypt_blobs {
        let sealed = crypto::blob_encrypt(st.cfg.server_secret.as_bytes(), &bytes);
        let enc_path = st.cfg.blob_root.join(format!("tmp_enc_{upload_id}"));
        if let Err(e) = std::fs::write(&enc_path, &sealed) {
            let _ = std::fs::remove_file(&enc_path);
            return Err(ApiError::internal_msg(format!("Blob encryption failed: {e}")));
        }
        let _ = std::fs::remove_file(&staged);
        enc_path
    } else {
        staged.clone()
    };

    if let Err(e) = storage::commit_blob(&st.cfg, app_id, &uuid, &staged_for_commit) {
        let conn = st.db.lock().unwrap();
        conn.execute("DELETE FROM files WHERE id=?1", params![file_id]).ok();
        conn.execute(
            "UPDATE apps SET usage_bytes = MAX(0, usage_bytes - ?1) WHERE id=?2",
            params![received, app_id],
        )
        .ok();
        let _ = std::fs::remove_file(&staged_for_commit);
        return Err(ApiError::internal_msg(format!("Blob commit failed: {e}")));
    }
    // Session done: drop the job row (staged file is already renamed away).
    {
        let conn = st.db.lock().unwrap();
        upload::finish(&conn, &upload_id).ok();
    }

    {
        let conn = st.db.lock().unwrap();
        db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "upload_chunk", app_id: Some(app_id), target: &uuid, ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    }

    Ok(json_response(json!({
        "file_id": file_id,
        "app_id": format!("app_{app_id}"),
        "owner": user_id,
        "storage_uuid": uuid,
        "size": received,
        "sha256": digest,
        "classification": "internal",
        "content_type": "application/octet-stream",
        "total_size": total_size
    })))
}
