use crate::config::Config;
use crate::crypto;
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::routes::{require_admin, ReqCtx};
use crate::state::AppState;
use axum::body::{to_bytes, Body};
use axum::extract::State as AxState;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::Json;
use rusqlite::params;
use serde_json::{json, Value};

async fn body_ctx(st: &AppState, req: Request<Body>) -> Result<(ReqCtx, Vec<u8>), ApiError> {
    let (method, path, query, headers) = {
        (
            req.method().as_str().to_string(),
            req.uri().path().to_string(),
            req.uri().query().unwrap_or("").to_string(),
            req.headers().clone(),
        )
    };
    let peer_ip = crate::routes::peer_ip_of(&req);
    let body = to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| ApiError::too_large("Request body too large."))?
        .to_vec();
    let ctx = ReqCtx {
        method,
        path,
        query,
        headers,
        body_hash: crypto::sha256(&body),
        peer_ip,
        trust_xff: st.cfg.trust_xff,
    };
    Ok((ctx, body))
}

async fn query_ctx(st: &AppState, req: Request<Body>) -> Result<ReqCtx, ApiError> {
    let (method, path, query, headers) = {
        (
            req.method().as_str().to_string(),
            req.uri().path().to_string(),
            req.uri().query().unwrap_or("").to_string(),
            req.headers().clone(),
        )
    };
    let peer_ip = crate::routes::peer_ip_of(&req);
    Ok(ReqCtx {
        method,
        path,
        query,
        headers,
        body_hash: crypto::sha256(&[]),
        peer_ip,
        trust_xff: st.cfg.trust_xff,
    })
}

fn app_json(a: &db::AppRow) -> Value {
    json!({
        "app_id": a.id,
        "name": a.name,
        "app_key": a.app_key,
        "quota_bytes": a.quota_bytes,
        "max_payload_bytes": a.max_payload_bytes,
        "usage_bytes": a.usage_bytes,
        "enabled": a.enabled,
        "created_at": a.created_at,
        "deleted_at": a.deleted_at
    })
}

// POST /admin/v1/apps
pub async fn create_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;

    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("name is required."))?;
    let quota: i64 = body.get("quota_bytes").and_then(|v| v.as_i64()).unwrap_or(10 * 1024 * 1024 * 1024);
    let max_payload: i64 = body.get("max_payload_bytes").and_then(|v| v.as_i64()).unwrap_or(100 * 1024 * 1024);
    if quota <= 0 || max_payload <= 0 || max_payload > quota {
        return Err(ApiError::bad_request("Invalid quota/max_payload."));
    }

    let app_key = format!("app_{}", crypto::random_token().chars().take(16).collect::<String>());
    let secret = crypto::random_secret();
    let sealed = crypto::seal(st.cfg.server_secret.as_bytes(), secret.as_bytes());

    let app_id = {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "INSERT INTO apps(name,app_key,secret_sealed,quota_bytes,max_payload_bytes,created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![name, app_key, sealed, quota, max_payload, Config::now()],
        )?;
        let id = conn.last_insert_rowid();
        db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.create", app_id: Some(id), target: name, ip: &ctx.client_ip(), decision: "allow" }, Config::now());
        id
    };

    Ok(Json(json!({
        "app_id": app_id,
        "name": name,
        "app_key": app_key,
        "app_secret": secret,
        "quota_bytes": quota,
        "max_payload_bytes": max_payload,
        "enabled": true
    }))
    .into_response())
}

// GET /admin/v1/apps
pub async fn list_apps(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let conn = st.db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id,name,app_key,secret_sealed,quota_bytes,max_payload_bytes,usage_bytes,enabled,created_at,deleted_at FROM apps ORDER BY id",
    )?;
    let rows = stmt.query_map(params![], |r| {
        Ok(db::AppRow {
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
    let mut out = Vec::new();
    for r in rows {
        out.push(app_json(&r?));
    }
    Ok(Json(json!({ "apps": out })).into_response())
}

// GET /admin/v1/apps/:id
pub async fn get_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    Ok(Json(app_json(&app)).into_response())
}

// PATCH /admin/v1/apps/:id
pub async fn patch_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;

    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        conn.execute("UPDATE apps SET name=?1 WHERE id=?2", params![name, id])?;
    }
    if let Some(q) = body.get("quota_bytes").and_then(|v| v.as_i64()) {
        if q <= 0 || q < app.usage_bytes {
            return Err(ApiError::bad_request("Quota must be positive and >= current usage."));
        }
        conn.execute("UPDATE apps SET quota_bytes=?1 WHERE id=?2", params![q, id])?;
    }
    if let Some(m) = body.get("max_payload_bytes").and_then(|v| v.as_i64()) {
        if m <= 0 {
            return Err(ApiError::bad_request("max_payload_bytes must be positive."));
        }
        conn.execute("UPDATE apps SET max_payload_bytes=?1 WHERE id=?2", params![m, id])?;
    }
    if let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) {
        conn.execute("UPDATE apps SET enabled=?1 WHERE id=?2", params![enabled as i64, id])?;
    }
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.update", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(StatusCode::NO_CONTENT.into_response())
}

// POST /admin/v1/apps/:id/secret/rotate
pub async fn rotate_secret(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let _app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    let secret = crypto::random_secret();
    let sealed = crypto::seal(st.cfg.server_secret.as_bytes(), secret.as_bytes());
    conn.execute("UPDATE apps SET secret_sealed=?1 WHERE id=?2", params![sealed, id])?;
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.secret_rotate", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(Json(json!({ "app_id": id, "app_secret": secret })).into_response())
}

// DELETE /admin/v1/apps/:id  (soft delete)
pub async fn delete_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let _app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    conn.execute(
        "UPDATE apps SET deleted_at=?1, enabled=0 WHERE id=?2",
        params![Config::now(), id],
    )?;
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.delete", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(StatusCode::NO_CONTENT.into_response())
}

// POST /admin/v1/apps/:id/archive  (soft-delete / move to archive)
// Archives an app: marks deleted_at and disables it. It is moved out of the
// main Apps list into the "Archive" view, from where it can be unarchived
// (restored) or wiped (permanently deleted).
pub async fn archive_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    conn.execute(
        "UPDATE apps SET deleted_at=?1, enabled=0 WHERE id=?2",
        params![Config::now(), id],
    )?;
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.archive", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(Json(json!({ "app_id": id, "archived": true, "enabled": false })).into_response())
}

// POST /admin/v1/apps/:id/unarchive  (restore an archived app)
pub async fn unarchive_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    if app.deleted_at.is_none() {
        return Err(ApiError::bad_request("App is not archived."));
    }
    conn.execute(
        "UPDATE apps SET deleted_at=NULL, enabled=1 WHERE id=?1",
        params![id],
    )?;
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.unarchive", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(Json(json!({ "app_id": id, "unarchived": true, "enabled": true })).into_response())
}

// POST /admin/v1/apps/:id/wipe  (PERMANENT delete — not recoverable)
// Same as purge: removes the app record and all children metadata (files,
// folders, tokens, users, groups) and physically deletes the app's blob
// directory on disk. Frees the storage the app actually used.
pub async fn wipe_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    conn.execute("DELETE FROM files WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM folders WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM tokens WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM app_users WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM app_groups WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM apps WHERE id=?1", params![id])?;
    let blob_dir = st.cfg.blob_root.join(format!("app_{id}"));
    if blob_dir.exists() {
        std::fs::remove_dir_all(&blob_dir)
            .map_err(|_| ApiError::bad_request("App record removed but failed to delete blob dir on disk."))?;
    }
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.wipe", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(StatusCode::NO_CONTENT.into_response())
}

// POST /admin/v1/apps/:id/restore  (undelete a soft-deleted app)
// Reverts soft-delete: clears deleted_at and re-enables the app so its records
// (users, groups, tokens) become usable again. Note: file CONTENT may already
// be gone if the operator physically purged the blobs; the metadata is restored.
pub async fn restore_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    if app.deleted_at.is_none() {
        return Err(ApiError::bad_request("App is not deleted."));
    }
    conn.execute(
        "UPDATE apps SET deleted_at=NULL, enabled=1 WHERE id=?1",
        params![id],
    )?;
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.restore", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(Json(json!({ "app_id": id, "restored": true, "enabled": true })).into_response())
}

// POST /admin/v1/apps/:id/purge  (PERMANENT delete — not recoverable)
// Removes the app record and all its children (files, folders, tokens, users,
// groups) and physically deletes the app's blob directory on disk. This frees
// the storage the app's files actually occupied.
pub async fn purge_app(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;

    // children metadata (no FK cascade is relied on; delete explicitly)
    conn.execute("DELETE FROM files WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM folders WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM tokens WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM app_users WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM app_groups WHERE app_id=?1", params![id])?;
    conn.execute("DELETE FROM apps WHERE id=?1", params![id])?;

    // physically delete the app's blob tree on disk
    let blob_dir = st.cfg.blob_root.join(format!("app_{id}"));
    if blob_dir.exists() {
        std::fs::remove_dir_all(&blob_dir)
            .map_err(|_| ApiError::bad_request("App record removed but failed to delete blob dir on disk."))?;
    }

    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "app.purge", app_id: Some(id), target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(StatusCode::NO_CONTENT.into_response())
}

// GET /admin/v1/apps/:id/usage
pub async fn app_usage(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    let file_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE app_id=?1 AND deleted_at IS NULL",
            params![id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let token_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tokens WHERE app_id=?1 AND expires_at>?2 AND revoked=0",
            params![id, Config::now()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(Json(json!({
        "app_id": id,
        "usage_bytes": app.usage_bytes,
        "quota_bytes": app.quota_bytes,
        "file_count": file_count,
        "active_token_count": token_count
    }))
    .into_response())
}

// POST /admin/v1/storage/recompute — recompute usage_bytes for every app from
// its live (non-deleted) file rows. Useful after a restore, import, or archive
// when the stored counter may have drifted from the real data on disk.
pub async fn recompute_usage(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let conn = st.db.lock().unwrap();
    conn.execute(
        "UPDATE apps SET usage_bytes = COALESCE((SELECT SUM(size) FROM files WHERE app_id=apps.id AND deleted_at IS NULL), 0)",
        params![],
    )?;
    let rows: Vec<(i64, String, i64)> = {
        let mut stmt = conn.prepare("SELECT id,name,usage_bytes FROM apps ORDER BY id")?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        mapped
    };
    let apps: Vec<Value> = rows
        .iter()
        .map(|(id, name, u)| json!({"app_id": id, "name": name, "usage_bytes": u}))
        .collect();
    Ok(Json(json!({ "recomputed": rows.len(), "apps": apps })).into_response())
}

// POST /admin/v1/storage/audit — walk every live file record and verify the
// blob actually exists on disk with the recorded size and SHA-256. Returns a
// summary plus samples of anything broken (missing / size mismatch / SHA
// mismatch). Reading the file for SHA can be slow on huge datasets; the size
// check alone is done first and fast.
pub async fn audit_storage(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let conn = st.db.lock().unwrap();
    let files: Vec<(i64, i64, String, i64, Option<String>)> = {
        let mut stmt = conn.prepare(
            "SELECT id, app_id, blob_path, size, sha256 FROM files \
             WHERE deleted_at IS NULL AND blob_path IS NOT NULL ORDER BY id",
        )?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        mapped
    };
    let root = st.cfg.blob_root.clone();
    drop(conn);

    let mut ok = 0usize;
    let mut missing = 0usize;
    let mut size_mismatch = 0usize;
    let mut sha_mismatch = 0usize;
    let mut bytes_ok = 0i64;
    let mut missing_sample: Vec<String> = Vec::new();
    let mut size_sample: Vec<String> = Vec::new();
    let mut sha_sample: Vec<String> = Vec::new();

    for (id, _app, blob_path, size, sha) in &files {
        let p = root.join(blob_path);
        match std::fs::metadata(&p) {
            Ok(m) if m.is_file() => {
                if m.len() != *size as u64 {
                    size_mismatch += 1;
                    if size_sample.len() < 10 {
                        size_sample.push(format!("#{} {} expected={} actual={}", id, p.display(), size, m.len()));
                    }
                    continue;
                }
                let sha_ok = match sha {
                    Some(expected) => match std::fs::read(&p) {
                        Ok(bytes) => crate::crypto::sha256(&bytes) == *expected,
                        Err(_) => {
                            missing += 1;
                            false
                        }
                    },
                    None => true,
                };
                if sha_ok {
                    ok += 1;
                    bytes_ok += *size;
                } else {
                    sha_mismatch += 1;
                    if sha_sample.len() < 10 {
                        sha_sample.push(format!("#{} {}", id, p.display()));
                    }
                }
            }
            _ => {
                missing += 1;
                if missing_sample.len() < 10 {
                    missing_sample.push(format!("#{} {}", id, p.display()));
                }
            }
        }
    }

    Ok(Json(json!({
        "checked": files.len(),
        "ok": ok,
        "missing": missing,
        "size_mismatch": size_mismatch,
        "sha_mismatch": sha_mismatch,
        "bytes_ok": bytes_ok,
        "missing_sample": missing_sample,
        "size_sample": size_sample,
        "sha_sample": sha_sample
    }))
    .into_response())
}

// GET /admin/v1/storage/info — storage & backup dashboard details (apps by
// status, file counts, usage vs quota, DB/blob/backup sizes, backup times,
// maintenance settings). Meant to back a "Settings → Storage" view.
pub async fn storage_info(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let conn = st.db.lock().unwrap();
    let apps_total: i64 = conn.query_row("SELECT COUNT(*) FROM apps", [], |r| r.get(0)).unwrap_or(0);
    let apps_active: i64 = conn
        .query_row("SELECT COUNT(*) FROM apps WHERE deleted_at IS NULL AND enabled=1", [], |r| r.get(0))
        .unwrap_or(0);
    let apps_disabled: i64 = conn
        .query_row("SELECT COUNT(*) FROM apps WHERE deleted_at IS NULL AND enabled=0", [], |r| r.get(0))
        .unwrap_or(0);
    let apps_archived: i64 = conn
        .query_row("SELECT COUNT(*) FROM apps WHERE deleted_at IS NOT NULL", [], |r| r.get(0))
        .unwrap_or(0);
    let files_live: i64 = conn.query_row("SELECT COUNT(*) FROM files WHERE deleted_at IS NULL", [], |r| r.get(0)).unwrap_or(0);
    let files_total: i64 = conn.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0)).unwrap_or(0);
    let usage_bytes: i64 = conn
        .query_row("SELECT COALESCE(SUM(size),0) FROM files WHERE deleted_at IS NULL", [], |r| r.get(0))
        .unwrap_or(0);
    let quota_bytes: i64 = conn
        .query_row("SELECT COALESCE(SUM(quota_bytes),0) FROM apps", [], |r| r.get(0))
        .unwrap_or(0);
    let backups = db::list_backups(&conn).unwrap_or_default();
    drop(conn);

    let blob_bytes = dir_size(&st.cfg.blob_root);
    let db_bytes = std::fs::metadata(&st.cfg.db_path).map(|m| m.len()).unwrap_or(0);
    let backup_bytes = dir_size(&st.ops.backup_root);
    let last_backup = backups.first().map(|b| b.created_at);
    let last_backup_id = backups.first().map(|b| b.backup_id.clone());
    let last_backup_status = backups.first().map(|b| b.status.clone());

    Ok(Json(json!({
        "apps": { "total": apps_total, "active": apps_active, "disabled": apps_disabled, "archived": apps_archived },
        "files": { "live": files_live, "total": files_total },
        "usage_bytes": usage_bytes,
        "quota_bytes": quota_bytes,
        "db": { "path": st.cfg.db_path.to_string_lossy(), "bytes": db_bytes },
        "blobs": { "path": st.cfg.blob_root.to_string_lossy(), "bytes": blob_bytes },
        "backup": {
            "root": st.ops.backup_root.to_string_lossy(),
            "count": backups.len(),
            "bytes": backup_bytes,
            "retention": st.ops.backup_retention,
            "last_id": last_backup_id,
            "last_status": last_backup_status,
            "last_created_at": last_backup
        },
        "maintenance": {
            "soft_delete_grace_secs": st.cfg.soft_delete_grace_secs,
            "purge_interval_secs": st.cfg.purge_interval_secs,
            "audit_retention_secs": st.cfg.audit_retention_secs
        }
    }))
    .into_response())
}

/// Recursively sum the on-disk byte size of a directory tree (for storage info).
fn dir_size(dir: &std::path::Path) -> i64 {
    fn walk(d: &std::path::Path, acc: &mut i64) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if let Ok(m) = std::fs::metadata(&p) {
                    if m.is_dir() {
                        walk(&p, acc);
                    } else {
                        *acc += m.len() as i64;
                    }
                }
            }
        }
    }
    let mut total = 0i64;
    walk(dir, &mut total);
    total
}

// POST /admin/v1/apps/:id/users
// Admin-managed user directory: the operator pre-provisions users for an app
// here (the app can also still vouch for users at upload time). The user_id is
// validated with the same rules as the upload path so exported archive entry
// names can never contain traversal sequences.
pub async fn add_user(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;
    let user_id = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("user_id is required."))?;
    crate::routes::common::validate_user_id(user_id)
        .map_err(|_| ApiError::bad_request("Invalid user_id."))?;

    let conn = st.db.lock().unwrap();
    let app = db::app_by_id(&conn, id)?
        .filter(|a| a.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    let created = conn.execute(
        "INSERT OR IGNORE INTO app_users(app_id,user_id,created_at) VALUES(?1,?2,?3)",
        params![id, user_id, Config::now()],
    )?;
    db::audit(
        &conn,
        &db::AuditEntry {
            actor: "admin",
            action: "app.user_add",
            app_id: Some(id),
            target: user_id,
            ip: &ctx.client_ip(),
            decision: "allow",
        },
        Config::now(),
    );
    Ok(Json(json!({
        "app_id": id,
        "app_name": app.name,
        "user_id": user_id,
        "created": created == 1
    }))
    .into_response())
}

// GET /admin/v1/apps/:id/users — list the admin-provisioned user directory.
pub async fn list_users(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))?;
    let conn = st.db.lock().unwrap();
    let _app = db::app_by_id(&conn, id)?
        .filter(|a| a.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    let mut stmt = conn
        .prepare(
            "SELECT user_id, created_at FROM app_users WHERE app_id=?1
             ORDER BY created_at DESC, user_id ASC",
        )
        .map_err(ApiError::from)?;
    let rows = stmt
        .query_map(params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(ApiError::from)?;
    let mut users: Vec<Value> = Vec::new();
    for r in rows {
        let (uid, at) = r.map_err(ApiError::from)?;
        users.push(json!({ "user_id": uid, "created_at": at }));
    }
    Ok(Json(json!({ "app_id": id, "users": users })).into_response())
}

// ---------------- User groups ----------------

fn app_id_from_path(ctx: &ReqCtx) -> Result<i64, ApiError> {
    ctx.path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid app id."))
}

fn ensure_app_exists(st: &AppState, id: i64) -> Result<(), ApiError> {
    let conn = st.db.lock().unwrap();
    let _app = db::app_by_id(&conn, id)?
        .filter(|a| a.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("App not found."))?;
    Ok(())
}

fn parse_group_name(ctx: &ReqCtx, idx: usize) -> Result<String, ApiError> {
    let name = ctx
        .path_segment(idx)
        .ok_or_else(|| ApiError::bad_request("Missing group name."))?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad_request("Invalid group name: must be 1..=64 characters."));
    }
    if name.contains('/') || name.contains('\\') || name.contains(' ') {
        return Err(ApiError::bad_request("Invalid group name: no '/', '\\' or spaces."));
    }
    Ok(name.to_string())
}

// GET /admin/v1/apps/{id}/groups
pub async fn list_groups(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    ensure_app_exists(&st, id)?;
    let conn = st.db.lock().unwrap();
    let groups = db::list_groups(&conn, id)?;
    let items: Vec<Value> = groups
        .iter()
        .map(|g| json!({ "name": g.name, "members": g.members, "created_at": g.created_at }))
        .collect();
    Ok(Json(json!({ "app_id": id, "groups": items })).into_response())
}

// POST /admin/v1/apps/{id}/groups   {"name": "engineers"}
pub async fn create_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    ensure_app_exists(&st, id)?;
    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("name is required."))?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad_request("Invalid group name: must be 1..=64 characters."));
    }
    if name.contains('/') || name.contains('\\') || name.contains(' ') {
        return Err(ApiError::bad_request("Invalid group name: no '/', '\\' or spaces."));
    }
    let conn = st.db.lock().unwrap();
    let g = match db::create_group(&conn, id, name) {
        Ok(g) => g,
        Err(_) => return Err(ApiError::bad_request("Group name already exists.")),
    };
    db::audit(
        &conn,
        &db::AuditEntry { actor: "admin", action: "group.create", app_id: Some(id), target: name, ip: &ctx.client_ip(), decision: "allow" },
        Config::now(),
    );
    Ok(Json(json!({ "name": g.name, "members": g.members, "created_at": g.created_at })).into_response())
}

// GET /admin/v1/apps/{id}/groups/{name}
pub async fn get_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    let name = parse_group_name(&ctx, 6)?;
    let conn = st.db.lock().unwrap();
    let g = db::group_by_name(&conn, id, &name)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    Ok(Json(json!({ "name": g.name, "members": g.members, "created_at": g.created_at })).into_response())
}

// DELETE /admin/v1/apps/{id}/groups/{name}
pub async fn delete_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    let name = parse_group_name(&ctx, 6)?;
    let conn = st.db.lock().unwrap();
    if !db::delete_group(&conn, id, &name)? {
        return Err(ApiError::not_found("Group not found."));
    }
    db::audit(
        &conn,
        &db::AuditEntry { actor: "admin", action: "group.delete", app_id: Some(id), target: &name, ip: &ctx.client_ip(), decision: "allow" },
        Config::now(),
    );
    Ok(Json(json!({ "deleted": name })).into_response())
}

// POST /admin/v1/apps/{id}/groups/{name}/members   {"user_id": "alice"}
pub async fn add_group_member(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    let name = parse_group_name(&ctx, 6)?;
    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;
    let user_id = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("user_id is required."))?;
    crate::routes::common::validate_user_id(user_id)
        .map_err(|_| ApiError::bad_request("Invalid user_id."))?;
    let conn = st.db.lock().unwrap();
    let g = db::add_group_member(&conn, id, &name, user_id)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    db::audit(
        &conn,
        &db::AuditEntry { actor: "admin", action: "group.member_add", app_id: Some(id), target: &format!("{name}:{user_id}"), ip: &ctx.client_ip(), decision: "allow" },
        Config::now(),
    );
    Ok(Json(json!({ "name": g.name, "members": g.members })).into_response())
}

// DELETE /admin/v1/apps/{id}/groups/{name}/members/{user_id}
pub async fn remove_group_member(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id = app_id_from_path(&ctx)?;
    let name = parse_group_name(&ctx, 6)?;
    let user_id = ctx
        .path_segment(8)
        .ok_or_else(|| ApiError::bad_request("Missing user_id."))?;
    let conn = st.db.lock().unwrap();
    let g = db::remove_group_member(&conn, id, &name, &user_id)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    db::audit(
        &conn,
        &db::AuditEntry { actor: "admin", action: "group.member_remove", app_id: Some(id), target: &format!("{name}:{user_id}"), ip: &ctx.client_ip(), decision: "allow" },
        Config::now(),
    );
    Ok(Json(json!({ "name": g.name, "members": g.members })).into_response())
}

// GET /admin/v1/audit
pub async fn list_audit(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let app_id: Option<i64> = ctx.query_param("app_id").and_then(|v| v.parse().ok());
    let since: i64 = ctx
        .query_param("since")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let conn = st.db.lock().unwrap();
    let mut sql = String::from(
        "SELECT id,actor,action,app_id,target,ip,decision,at FROM audit_log WHERE at>=?1",
    );
    let mut args: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(since)];
    if let Some(aid) = app_id {
        sql.push_str(" AND app_id=?2");
        args.push(rusqlite::types::Value::Integer(aid));
    }
    sql.push_str(" ORDER BY id DESC LIMIT 200");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(json!({
            "id": r.get::<_, i64>(0)?,
            "actor": r.get::<_, String>(1)?,
            "action": r.get::<_, String>(2)?,
            "app_id": r.get::<_, Option<i64>>(3)?,
            "target": r.get::<_, String>(4)?,
            "ip": r.get::<_, String>(5)?,
            "decision": r.get::<_, String>(6)?,
            "at": r.get::<_, i64>(7)?
        }));
    }
    Ok(Json(json!({ "entries": out })).into_response())
}

use axum::http::StatusCode;

// ---------------- Backups (§10) ----------------

/// POST /admin/v1/backups/run — immediately snapshot the DB + archive the
/// encrypted blob tree + write a sha256 manifest. No key material (server
/// secret, admin token, app secrets) ever leaves the environment; see
/// backup.rs for the key-management policy.
pub async fn backup_run(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    // run_backup manages its own short locks internally (F3 fix); the admin
    // handler must NOT hold the global DB mutex while the slow blob-tree
    // archive is written.
    let out = crate::backup::run_backup(&st.cfg, &st.ops, &st.db)
        .map_err(|e| ApiError::internal_msg(format!("Backup failed: {e}")))?;
    {
        let conn = st.db.lock().unwrap();
        db::audit(&conn, &db::AuditEntry { actor: "admin", action: "backup.run", app_id: None, target: &out.backup_id, ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    }
    Ok(Json(json!({
        "backup_id": out.backup_id,
        "id": out.id,
        "status": "ready",
        "size": out.size,
        "files": out.files.iter().map(|(n, s, sha)| json!({
            "name": n, "size": s, "sha256": sha
        })).collect::<Vec<_>>()
    }))
    .into_response())
}

/// GET /admin/v1/backups — list known backups (newest first).
pub async fn backup_list(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let conn = st.db.lock().unwrap();
    let rows = db::list_backups(&conn)?;
    let out: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "backup_id": r.backup_id,
                "status": r.status,
                "created_at": r.created_at,
                "finished_at": r.finished_at,
                "size": r.size,
                "path": r.target_path
            })
        })
        .collect();
    Ok(Json(json!({ "backups": out })).into_response())
}

/// GET /admin/v1/backups/{id} — detail incl. the manifest. Unknown ids return
/// the unified 404 (existence is hidden).
pub async fn backup_detail(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid backup id."))?;
    let conn = st.db.lock().unwrap();
    let row = db::backup_by_id(&conn, id)?
        .ok_or_else(|| ApiError::not_found("Backup not found."))?;
    Ok(Json(json!({
        "id": row.id,
        "backup_id": row.backup_id,
        "status": row.status,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "size": row.size,
        "target_path": row.target_path,
        "manifest": row.manifest.and_then(|m| serde_json::from_str::<Value>(&m).ok()),
        "error": row.error
    }))
    .into_response())
}

/// PATCH /admin/v1/backups/config — {schedule?, target?, retention?}.
/// target must resolve inside the configured backup root (path/symlink escape
/// blocked); retention keeps the newest N copies.
pub async fn backup_config(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let (ctx, body) = body_ctx(&st, req).await?;
    require_admin(&st, &ctx)?;
    let body: Value = serde_json::from_slice(&body).map_err(ApiError::from)?;

    let conn = st.db.lock().unwrap();
    if let Some(schedule) = body.get("schedule").and_then(|v| v.as_i64()) {
        if schedule < 0 {
            return Err(ApiError::bad_request("schedule must be >= 0 seconds."));
        }
        db::set_setting(&conn, "schedule_secs", &schedule.to_string())?;
    }
    if let Some(target) = body.get("target").and_then(|v| v.as_str()) {
        crate::backup::validate_target(&st.ops, target).map_err(ApiError::bad_request)?;
        db::set_setting(&conn, "target", target)?;
    }
    if let Some(retention) = body.get("retention").and_then(|v| v.as_u64()) {
        if !(1..=1000).contains(&retention) {
            return Err(ApiError::bad_request("retention must be between 1 and 1000."));
        }
        db::set_setting(&conn, "retention", &retention.to_string())?;
    }
    let eff = crate::backup::effective_settings(&conn, &st.ops);
    db::audit(&conn, &db::AuditEntry { actor: "admin", action: "backup.config", app_id: None, target: "", ip: &ctx.client_ip(), decision: "allow" }, Config::now());
    Ok(Json(json!({
        "schedule_secs": eff.schedule_secs,
        "target": eff.target,
        "retention": eff.retention
    }))
    .into_response())
}
