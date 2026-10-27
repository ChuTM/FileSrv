use crate::authz::{self, Acl, Action, Identity};
use crate::crypto::{self, sha256};
use crate::db::{self, FileRow};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;
use crate::routes::{extract_identity, ReqCtx};
use crate::state::AppState;
use crate::storage;
use crate::tokens;
use crate::upload;
use axum::body::{to_bytes, Body};
use axum::extract::State as AxState;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub async fn healthz() -> &'static str {
    "OK"
}

fn app_identity_id(identity: &Identity) -> i64 {
    identity.app_id().expect("app identity required")
}

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

fn json_response(v: Value) -> Response {
    Json(v).into_response()
}

fn actor_label(identity: &Identity) -> String {
    match identity {
        Identity::App(id) => format!("app:{id}"),
        Identity::User { app_id, user_id } => format!("app:{app_id}:user:{user_id}"),
        Identity::Token(_) => "token".into(),
        Identity::Admin => "admin".into(),
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
    use tokio::io::AsyncSeekExt;
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

fn load_app_file(st: &AppState, file_id: i64, app_id: i64) -> Result<FileRow, ApiError> {
    let conn = st.db.lock().unwrap();
    let f = db::file_by_id(&conn, file_id)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("File not found."))?;
    Ok(f)
}

fn file_meta_json(f: &FileRow) -> Value {
    json!({
        "file_id": f.id,
        "app_id": format!("app_{}", f.app_id),
        "owner": f.owner,
        "user_id": f.user_id,
        "folder_id": f.folder_id,
        "storage_uuid": f.storage_uuid,
        "logical_path": f.logical_path,
        "content_type": f.content_type,
        "size": f.size,
        "sha256": f.sha256,
        "classification": f.classification,
        "created_at": f.created_at
    })
}

// ---------------- Generate link ----------------

pub async fn generate_link(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let file_id: i64 = body
        .get("file_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ApiError::bad_request("file_id is required."))?;
    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("embed");
    let ttl = body
        .get("ttl_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(st.cfg.embed_ttl_secs)
        .clamp(60, 86400);
    let allowed_ip = body
        .get("allowed_ip")
        .and_then(|v| v.as_str())
        .map(String::from);

    let file = load_app_file(&st, file_id, app_id)?;

    // Permission: App identity (tenant) or user with Read on the file.
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let conn = st.db.lock().unwrap();
            if !authz::can_user_access_file(&conn, &file, user_id, Action::Read) {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Token generation not allowed.")),
    }

    // Embed tokens are idempotent per (file, user, scope): key them on the
    // requesting user (JWT) so two readers of the same file don't collide on
    // one token; app-level identity has no user context, so fall back to the
    // file owner (spec §5.8 of the test report).
    let embed_user = match &identity {
        Identity::User { user_id, .. } => user_id.clone(),
        _ => file.owner.clone(),
    };
    let (token, reused) = match scope {
        "embed" => tokens::generate_embed(&st.db, &st.cfg, app_id, file_id, &embed_user, ttl),
        "share" => (
            tokens::generate_share(
                &st.db,
                app_id,
                file_id,
                &file.owner,
                ttl,
                allowed_ip.as_deref(),
            ),
            false,
        ),
        _ => return Err(ApiError::bad_request("scope must be embed or share.")),
    };

    {
        let conn = st.db.lock().unwrap();
        db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "generate_link", app_id: Some(app_id), target: &format!("file:{file_id}"), ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    }

    Ok(json_response(json!({
        "token": token,
        "url": format!("/v1/download/{token}"),
        "scope": scope,
        "reused": reused,
        "expires_at": crate::config::Config::now() + ttl
    })))
}

// ---------------- Revoke ----------------

pub async fn revoke_token(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("token is required."))?;

    // Token must belong to this app.
    let owned = {
        let conn = st.db.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM tokens WHERE token=?1 AND app_id=?2",
            params![token, app_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
            > 0
    };
    if !owned {
        return Err(ApiError::not_found("Token not found."));
    }

    let revoked = tokens::revoke(&st.db, token);
    {
        let conn = st.db.lock().unwrap();
        db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "revoke_token", app_id: Some(app_id), target: token, ip: &ctx.client_ip(), decision: if revoked { "allow" } else { "deny" } }, crate::config::Config::now());
    }
    Ok(json_response(json!({ "revoked": revoked })))
}

// ---------------- Files ----------------

pub async fn list_files(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);

    let cursor: i64 = ctx
        .query_param("cursor")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let folder_id: Option<i64> = ctx.query_param("folder_id").and_then(|v| v.parse().ok());
    let limit = 100;

    let conn = st.db.lock().unwrap();
    let mut sql = String::from(
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at
         FROM files WHERE app_id=?1 AND deleted_at IS NULL AND id>?2",
    );
    let mut args: Vec<rusqlite::types::Value> = vec![
        rusqlite::types::Value::Integer(app_id),
        rusqlite::types::Value::Integer(cursor),
    ];
    if let Some(fid) = folder_id {
        let folder = db::folder_by_id(&conn, fid)?;
        if folder.map(|f| f.app_id != app_id).unwrap_or(true) {
            return Err(ApiError::not_found("Folder not found."));
        }
        sql.push_str(" AND folder_id=?3");
        args.push(rusqlite::types::Value::Integer(fid));
    }
    sql.push_str(" ORDER BY id ASC LIMIT ?");
    args.push(rusqlite::types::Value::Integer(limit + 1));

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    let mut next_cursor: Option<i64> = None;
    let mut count = 0;
    while let Some(r) = rows.next()? {
        let f = FileRow {
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
        };
        count += 1;
        if count > limit {
            next_cursor = Some(f.id);
            break;
        }
        if let Identity::User { user_id, .. } = &identity {
            if !authz::can_user_access_file(&conn, &f, user_id, Action::List)
                && !authz::can_user_access_file(&conn, &f, user_id, Action::Read)
            {
                continue;
            }
        }
        out.push(file_meta_json(&f));
    }

    Ok(json_response(json!({ "files": out, "next_cursor": next_cursor })))
}

pub async fn get_file(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let file_id: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid file id."))?;

    let file = load_app_file(&st, file_id, app_id)?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let conn = st.db.lock().unwrap();
            if !authz::can_user_access_file(&conn, &file, user_id, Action::Read)
                && !authz::can_user_access_file(&conn, &file, user_id, Action::List)
            {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }
    Ok(json_response(file_meta_json(&file)))
}

pub async fn delete_file(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let file_id: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid file id."))?;

    let file = load_app_file(&st, file_id, app_id)?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let conn = st.db.lock().unwrap();
            if !authz::can_user_access_file(&conn, &file, user_id, Action::Delete) {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }

    let size = file.size;
    {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "UPDATE files SET deleted_at=?1 WHERE id=?2",
            params![crate::config::Config::now(), file_id],
        )?;
        conn.execute("DELETE FROM tokens WHERE file_id=?1", params![file_id])?;
        conn.execute(
            "UPDATE apps SET usage_bytes = MAX(0, usage_bytes - ?1) WHERE id=?2",
            params![size, app_id],
        )?;
        db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "delete_file", app_id: Some(app_id), target: &file.storage_uuid, ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    }
    // Soft-delete: the blob file is intentionally NOT removed here. It stays
    // on disk for the grace window (TENANT_FS_SOFT_DELETE_DAYS) and is purged
    // physically by the background maintenance loop; usage was already rolled
    // back above and every read/list path excludes tombstones.
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------- ACL (file) ----------------

pub async fn patch_file_acl(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let file_id: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid file id."))?;

    let file = load_app_file(&st, file_id, app_id)?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } if *user_id == file.owner => {}
        _ => return Err(ApiError::forbidden(
            "Only the owner or app admin can manage ACL.",
        )),
    }

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let new_acl = merge_acl(&file.acl, &body)?;
    let conn = st.db.lock().unwrap();
    conn.execute(
        "UPDATE files SET acl=?1 WHERE id=?2",
        params![new_acl.to_json(), file_id],
    )?;
    db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "acl.update", app_id: Some(app_id), target: &format!("file:{file_id}"), ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    Ok(json_response(json!({ "acl": new_acl })))
}

// ---------------- Batch ACL ----------------

pub async fn batch_acl(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => {
            return Err(ApiError::forbidden(
                "Batch ACL requires app-level credentials.",
            ))
        }
    };

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let file_ids: Vec<i64> = body
        .get("file_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError::bad_request("file_ids array is required."))?
        .iter()
        .map(|v| {
            v.as_i64()
                .ok_or_else(|| ApiError::bad_request("Invalid file_ids."))
        })
        .collect::<Result<_, _>>()?;
    if file_ids.is_empty() {
        return Err(ApiError::bad_request("file_ids must not be empty."));
    }
    if file_ids.len() > st.cfg.max_batch_acl {
        return Err(ApiError::bad_request(format!(
            "Batch limited to {} files per request.",
            st.cfg.max_batch_acl
        )));
    }
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("action is required."))?;
    if !matches!(action, "read" | "write" | "delete" | "list" | "export") {
        return Err(ApiError::bad_request(
            "action must be read/write/delete/list/export.",
        ));
    }

    let conn = st.db.lock().unwrap();
    let mut updated = 0usize;
    for fid in &file_ids {
        let file = match db::file_by_id(&conn, *fid)? {
            Some(f) if f.app_id == app_id && f.deleted_at.is_none() => f,
            _ => continue,
        };
        let new_acl = merge_acl(&file.acl, &body)?;
        conn.execute(
            "UPDATE files SET acl=?1 WHERE id=?2",
            params![new_acl.to_json(), fid],
        )?;
        updated += 1;
    }
    db::audit(&conn, &db::AuditEntry { actor: &actor_label(&Identity::App(app_id)), action: "acl.batch", app_id: Some(app_id), target: &format!("files:{}", file_ids.len()), ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    Ok(json_response(json!({ "updated": updated, "total": file_ids.len() })))
}

// ---------------- Folders ----------------

pub async fn create_folder(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("name is required."))?;
    let parent_id: Option<i64> = body.get("parent_id").and_then(|v| v.as_i64());

    let conn = st.db.lock().unwrap();
    if let Some(pid) = parent_id {
        match db::folder_by_id(&conn, pid)? {
            Some(f) if f.app_id == app_id && f.deleted_at.is_none() => {}
            _ => return Err(ApiError::not_found("Parent folder not found.")),
        }
    }
    conn.execute(
        "INSERT INTO folders(app_id,parent_id,name,acl,created_at) VALUES(?1,?2,?3,'{}',?4)",
        params![app_id, parent_id, name, crate::config::Config::now()],
    )?;
    let fid = conn.last_insert_rowid();
    db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "folder.create", app_id: Some(app_id), target: &format!("folder:{fid}"), ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    Ok(json_response(json!({ "folder_id": fid })))
}

pub async fn get_folder(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let fid: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid folder id."))?;

    let conn = st.db.lock().unwrap();
    let folder = db::folder_by_id(&conn, fid)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("Folder not found."))?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let fa = Acl::from_json(&folder.acl);
            if !authz::evaluate_acl(&fa, user_id, Action::List)
                && !authz::evaluate_acl(&fa, user_id, Action::Read)
            {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }
    Ok(json_response(json!({
        "folder_id": folder.id,
        "name": folder.name,
        "parent_id": folder.parent_id,
        "acl": Acl::from_json(&folder.acl)
    })))
}

pub async fn patch_folder(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let fid: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid folder id."))?;

    let conn = st.db.lock().unwrap();
    let folder = db::folder_by_id(&conn, fid)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("Folder not found."))?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let fa = Acl::from_json(&folder.acl);
            if !authz::evaluate_acl(&fa, user_id, Action::Write) {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }

    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        conn.execute(
            "UPDATE folders SET name=?1 WHERE id=?2",
            params![name, fid],
        )?;
    }
    if let Some(pid) = body.get("parent_id") {
        let pid = pid.as_i64();
        if let Some(p) = pid {
            match db::folder_by_id(&conn, p)? {
                Some(par) if par.app_id == app_id && par.deleted_at.is_none() && par.id != fid => {}
                _ => return Err(ApiError::bad_request("Invalid parent folder.")),
            }
        }
        conn.execute(
            "UPDATE folders SET parent_id=?1 WHERE id=?2",
            params![pid, fid],
        )?;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn delete_folder(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let fid: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid folder id."))?;

    let conn = st.db.lock().unwrap();
    let folder = db::folder_by_id(&conn, fid)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("Folder not found."))?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let fa = Acl::from_json(&folder.acl);
            if !authz::evaluate_acl(&fa, user_id, Action::Delete) {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }

    let now = crate::config::Config::now();
    // Collect the whole subtree (folder ids).
    let mut seen = vec![folder.id];
    let mut stack = vec![folder.id];
    while let Some(cur) = stack.pop() {
        let children: Vec<i64> = conn
            .prepare("SELECT id FROM folders WHERE parent_id=?1 AND deleted_at IS NULL")?
            .query_map(params![cur], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for c in children {
            if !seen.contains(&c) {
                seen.push(c);
                stack.push(c);
            }
        }
    }
    // Soft-delete folders and their files; free usage; drop tokens. Blob files
    // are NOT unlinked here — they outlive the grace window and are physically
    // purged by the background maintenance loop (same contract as DELETE file).
    for f_ in &seen {
        conn.execute(
            "UPDATE folders SET deleted_at=?1 WHERE id=?2",
            params![now, f_],
        )?;
        let file_ids: Vec<i64> = conn
            .prepare("SELECT id FROM files WHERE folder_id=?1 AND deleted_at IS NULL")?
            .query_map(params![f_], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for fid_ in file_ids {
            let f = db::file_by_id(&conn, fid_)?;
            if let Some(f) = f {
                conn.execute(
                    "UPDATE files SET deleted_at=?1 WHERE id=?2",
                    params![now, fid_],
                )?;
                conn.execute("DELETE FROM tokens WHERE file_id=?1", params![fid_])?;
                conn.execute(
                    "UPDATE apps SET usage_bytes = MAX(0, usage_bytes - ?1) WHERE id=?2",
                    params![f.size, app_id],
                )?;
            }
        }
    }
    db::audit(&conn, &db::AuditEntry { actor: &actor_label(&identity), action: "folder.delete", app_id: Some(app_id), target: &format!("folder:{fid}"), ip: &ctx.client_ip(), decision: "allow" }, now);
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_folder_files(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_identity_id(&identity);
    let fid: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid folder id."))?;

    let conn = st.db.lock().unwrap();
    let folder = db::folder_by_id(&conn, fid)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("Folder not found."))?;
    match &identity {
        Identity::App(_) => {}
        Identity::User { user_id, .. } => {
            let fa = Acl::from_json(&folder.acl);
            if !authz::evaluate_acl(&fa, user_id, Action::List)
                && !authz::evaluate_acl(&fa, user_id, Action::Read)
            {
                return Err(ApiError::forbidden("Permission denied."));
            }
        }
        _ => return Err(ApiError::forbidden("Permission denied.")),
    }

    let mut stmt = conn.prepare(
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at
         FROM files WHERE app_id=?1 AND folder_id=?2 AND deleted_at IS NULL ORDER BY id",
    )?;
    let rows = stmt.query_map(params![app_id, fid], |r| {
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
    let mut out = Vec::new();
    for f in rows {
        let f = f?;
        if let Identity::User { user_id, .. } = &identity {
            if !authz::can_user_access_file(&conn, &f, user_id, Action::List)
                && !authz::can_user_access_file(&conn, &f, user_id, Action::Read)
            {
                continue;
            }
        }
        out.push(file_meta_json(&f));
    }
    Ok(json_response(json!({ "files": out })))
}

pub async fn patch_folder_acl(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => {
            return Err(ApiError::forbidden(
                "Folder ACL management requires app-level credentials.",
            ))
        }
    };
    let fid: i64 = ctx
        .path_segment(3)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid folder id."))?;

    let conn = st.db.lock().unwrap();
    let folder = db::folder_by_id(&conn, fid)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("Folder not found."))?;
    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let new_acl = merge_acl(&folder.acl, &body)?;
    conn.execute(
        "UPDATE folders SET acl=?1 WHERE id=?2",
        params![new_acl.to_json(), fid],
    )?;

    if body
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let mut stack = vec![fid];
        let mut guard = 0;
        while let Some(cur) = stack.pop() {
            guard += 1;
            if guard > 1000 {
                break;
            }
            let children: Vec<i64> = conn
                .prepare("SELECT id FROM folders WHERE parent_id=?1 AND deleted_at IS NULL")?
                .query_map(params![cur], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            for c in children {
                if let Some(f) = db::folder_by_id(&conn, c)? {
                    if Acl::from_json(&f.acl).owner.is_empty() {
                        conn.execute(
                            "UPDATE folders SET acl=?1 WHERE id=?2",
                            params![new_acl.to_json(), c],
                        )?;
                    }
                }
                stack.push(c);
            }
        }
    }
    db::audit(&conn, &db::AuditEntry { actor: &actor_label(&Identity::App(app_id)), action: "acl.folder", app_id: Some(app_id), target: &format!("folder:{fid}"), ip: &ctx.client_ip(), decision: "allow" }, crate::config::Config::now());
    Ok(json_response(json!({ "acl": new_acl })))
}

// ---------------- Export ----------------

pub async fn export_files(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    // Optional format: "tar" (default, back-compatible) or "zip" (§9: the
    // export is organized by user_id either way).
    let body: Value = serde_json::from_slice(&ctx.body).unwrap_or(Value::Null);
    let format = body
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("tar");
    if !matches!(format, "tar" | "zip") {
        return Err(ApiError::bad_request("format must be 'tar' or 'zip'."));
    }

    let job_id = {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "INSERT INTO export_jobs(app_id,status,created_at) VALUES(?1,'pending',?2)",
            params![app_id, crate::config::Config::now()],
        )?;
        conn.last_insert_rowid()
    };

    let st = Arc::new(st);
    let job_id_c = job_id;
    let app_id_c = app_id;
    let format = format.to_string();
    tokio::spawn(async move {
        let _ = run_export(&st, app_id_c, job_id_c, &format).await;
    });

    Ok(json_response(json!({ "job_id": job_id, "status": "pending" })))
}

async fn run_export(st: &Arc<AppState>, app_id: i64, job_id: i64, format: &str) -> Result<(), ApiError> {
    let file_rows = {
        let conn = st.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at
             FROM files WHERE app_id=?1 AND deleted_at IS NULL",
        )?;
        let rows = stmt.query_map(params![app_id], |r| {
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
        let mut v = Vec::new();
        for r in rows {
            v.push(r?);
        }
        v
    };

    let export_dir = st
        .cfg
        .blob_root
        .join("exports")
        .join(format!("app_{app_id}"));
    std::fs::create_dir_all(&export_dir).ok();
    let path = export_dir.join(match format {
        "zip" => format!("job_{job_id}.zip"),
        _ => format!("job_{job_id}.tar"),
    });
    let mut total: i64 = 0;
    let archiving_ok = if format == "zip" {
        build_zip_archive(st, app_id, &file_rows, &path, &mut total)
    } else {
        build_tar_archive(st, app_id, &file_rows, &path, &mut total)
    };
    if !archiving_ok {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "UPDATE export_jobs SET status='failed', done_at=?1 WHERE id=?2",
            params![crate::config::Config::now(), job_id],
        )
        .ok();
        return Ok(());
    }

    let size = std::fs::metadata(&path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let conn = st.db.lock().unwrap();
    conn.execute(
        "UPDATE export_jobs SET status='ready', done_at=?1, size=?2, path=?3 WHERE id=?4",
        params![
            crate::config::Config::now(),
            size,
            path.to_string_lossy().to_string(),
            job_id
        ],
    )
    .ok();
    db::audit(&conn, &db::AuditEntry { actor: &format!("app:{app_id}"), action: "export.run", app_id: Some(app_id), target: &format!("job:{job_id}"), ip: "", decision: "allow" }, crate::config::Config::now());
    let _ = total;
    Ok(())
}

fn blob_bytes_for_export(
    st: &AppState,
    app_id: i64,
    fr: &FileRow,
) -> Option<Vec<u8>> {
    let src = storage::resolve_blob(&st.cfg, app_id, &fr.storage_uuid, fr.blob_path.as_deref()).ok()?;
    std::fs::read(&src).ok()
}

fn build_tar_archive(
    st: &AppState,
    app_id: i64,
    file_rows: &[FileRow],
    path: &std::path::Path,
    total: &mut i64,
) -> bool {
    let f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut builder = tar::Builder::new(f);
    for fr in file_rows {
        let src = match storage::resolve_blob(&st.cfg, app_id, &fr.storage_uuid, fr.blob_path.as_deref()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(fh) = std::fs::File::open(&src) {
            let mut header = tar::Header::new_gnu();
            header.set_size(fr.size as u64);
            header.set_mode(0o600);
            header.set_cksum();
            let entry_name = format!("files/{}/{}", fr.user_id, fr.storage_uuid);
            if builder.append_data(&mut header, entry_name, fh).is_ok() {
                *total += fr.size;
            }
        }
    }
    // Builder::drop flushes the tar trailer (tar 0.4 Drop impl).
    drop(builder);
    true
}

/// Zip archive organized by user_id (§9): entries are `files/<user_id>/<uuid>`.
fn build_zip_archive(
    st: &AppState,
    app_id: i64,
    file_rows: &[FileRow],
    path: &std::path::Path,
    total: &mut i64,
) -> bool {
    use std::io::Write;
    let f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut zip = zip::ZipWriter::new(f);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for fr in file_rows {
        let Some(bytes) = blob_bytes_for_export(st, app_id, fr) else {
            continue;
        };
        let entry_name = format!("files/{}/{}", fr.user_id, fr.storage_uuid);
        if zip.start_file(&entry_name, options).is_ok() && zip.write_all(&bytes).is_ok() {
            *total += fr.size;
        }
    }
    zip.finish().is_ok()
}

pub async fn export_status(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    let job_id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid job id."))?;
    let conn = st.db.lock().unwrap();
    let (status, size): (String, Option<i64>) = conn
        .query_row(
            "SELECT status, size FROM export_jobs WHERE id=?1 AND app_id=?2",
            params![job_id, app_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
        .ok_or_else(|| ApiError::not_found("Export job not found."))?;
    Ok(json_response(json!({
        "job_id": job_id,
        "status": status,
        "size": size,
        "download_url": format!("/v1/apps/exports/{job_id}/download")
    })))
}

pub async fn export_download(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    let job_id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid job id."))?;
    let (status, path) = {
        let conn = st.db.lock().unwrap();
        conn.query_row(
            "SELECT status, COALESCE(path,'') FROM export_jobs WHERE id=?1 AND app_id=?2",
            params![job_id, app_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
        .ok_or_else(|| ApiError::not_found("Export job not found."))?
    };
    if status != "ready" {
        return Err(ApiError::conflict("Export job is not ready."));
    }
    let p = std::path::PathBuf::from(&path);
    if !p.starts_with(st.cfg.blob_root.join("exports")) {
        return Err(ApiError::forbidden("Invalid export path."));
    }
    let f = tokio::fs::File::open(&p).await?;
    let stream = tokio_util::io::ReaderStream::new(f);
    let body = Body::from_stream(stream);
    let (content_type, filename) = match p.extension().and_then(|e| e.to_str()) {
        Some("zip") => ("application/zip", format!("job_{job_id}.zip")),
        _ => ("application/x-tar", format!("job_{job_id}.tar")),
    };
    Ok(Response::builder()
        .header("Content-Type", content_type)
        .header("Content-Disposition", format!("attachment; filename=\"{filename}\""))
        .body(body)
        .unwrap())
}

// ---------------- Shared helpers ----------------

pub struct BytesCtx {
    pub ctx: ReqCtx,
    pub body: Vec<u8>,
}

impl std::ops::Deref for BytesCtx {
    type Target = ReqCtx;
    fn deref(&self) -> &ReqCtx {
        &self.ctx
    }
}

pub async fn bytes_ctx(st: &AppState, req: Request<Body>) -> Result<BytesCtx, ApiError> {
    let (method, path, query, headers) = req_headers_path(&req);
    let peer_ip = crate::routes::peer_ip_of(&req);
    let body = to_bytes(req.into_body(), 2 * 1024 * 1024)
        .await
        .map_err(|_| ApiError::too_large("Request body too large."))?
        .to_vec();
    let ctx = ReqCtx {
        method,
        path,
        query,
        headers,
        body_hash: sha256(&body),
        peer_ip,
        trust_xff: st.cfg.trust_xff,
    };
    Ok(BytesCtx { ctx, body })
}

fn req_headers_path(req: &Request<Body>) -> (String, String, String, axum::http::HeaderMap) {
    (
        req.method().as_str().to_string(),
        req.uri().path().to_string(),
        req.uri().query().unwrap_or("").to_string(),
        req.headers().clone(),
    )
}

pub async fn query_ctx(st: &AppState, req: Request<Body>) -> Result<ReqCtx, ApiError> {
    let (method, path, query, headers) = req_headers_path(&req);
    let peer_ip = crate::routes::peer_ip_of(&req);
    Ok(ReqCtx {
        method,
        path,
        query,
        headers,
        body_hash: sha256(&[]),
        peer_ip,
        trust_xff: st.cfg.trust_xff,
    })
}

/// Merge an ACL patch into an existing ACL JSON.
fn merge_acl(existing: &str, body: &Value) -> Result<Acl, ApiError> {
    let mut acl = Acl::from_json(existing);
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let add: Vec<String> = body
        .get("add")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let remove: Vec<String> = body
        .get("remove")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let deny: Vec<String> = body
        .get("deny")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();

    fn apply(list: &mut Vec<String>, add: &[String], remove: &[String], deny: &[String]) {
        for d in deny {
            list.retain(|s| s != d);
        }
        for r in remove {
            list.retain(|s| s != r);
        }
        for a in add {
            if !list.contains(a) {
                list.push(a.clone());
            }
        }
    }

    let target: &mut Vec<String> = match action {
        "read" => &mut acl.read,
        "write" => &mut acl.write,
        "delete" => &mut acl.delete,
        "list" => &mut acl.list,
        "export" => &mut acl.export,
        _ => {
            return Err(ApiError::bad_request(
                "action must be read/write/delete/list/export.",
            ))
        }
    };
    apply(target, &add, &remove, &deny);
    for d in &deny {
        if !acl.deny.contains(d) {
            acl.deny.push(d.clone());
        }
    }
    Ok(acl)
}
