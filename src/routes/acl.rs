use crate::authz::Identity;
use crate::db::{self};
use crate::error::{ApiError, ApiResult};
use crate::routes::common::{
    actor_label, app_identity_id, bytes_ctx, json_response, load_app_file, merge_acl,
};
use crate::routes::extract_identity;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::Request;
use rusqlite::params;
use serde_json::{json, Value};

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
