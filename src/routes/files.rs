use crate::authz::{self, Action, Identity};
use crate::db::{self, FileRow};
use crate::error::{ApiError, ApiResult};
use crate::routes::common::{
    actor_label, app_identity_id, file_meta_json, json_response, load_app_file, query_ctx,
};
use crate::routes::extract_identity;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use rusqlite::params;
use serde_json::json;

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
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at,name
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
            name: r.get(15)?,
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
