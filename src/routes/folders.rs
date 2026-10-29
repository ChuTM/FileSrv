use crate::authz::{self, Acl, Action, Identity};
use crate::db::{self, FileRow};
use crate::error::{ApiError, ApiResult};
use crate::routes::common::{
    actor_label, app_identity_id, bytes_ctx, file_meta_json, json_response, merge_acl, query_ctx,
};
use crate::routes::extract_identity;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use rusqlite::params;
use serde_json::{json, Value};

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
            // F5 fix: reject a parent that would create a folder cycle.
            // Walk the chain from the NEW parent towards the root; if the
            // folder being moved is reached, the update would form a loop.
            // The guard (100) mirrors the depth guard used elsewhere and is
            // only a safety net against pathological pre-existing data.
            let mut cur = p;
            let mut guard = 0;
            while guard < 100 {
                let par = match db::folder_by_id(&conn, cur)? {
                    Some(f) => f,
                    None => break,
                };
                if par.id == fid {
                    return Err(ApiError::bad_request(
                        "Parent would create a folder cycle.",
                    ));
                }
                match par.parent_id {
                    Some(next) => cur = next,
                    None => break,
                }
                guard += 1;
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
        "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at,name
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
            name: r.get(15)?,
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
