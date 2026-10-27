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
    let out = {
        let conn = st.db.lock().unwrap();
        crate::backup::run_backup(&st.cfg, &st.ops, &conn)
            .map_err(|e| ApiError::internal_msg(format!("Backup failed: {e}")))
    }?;
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
                "size": r.size
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
