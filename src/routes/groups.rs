use crate::authz::Identity;
use crate::db::{self};
use crate::error::{ApiError, ApiResult};
use crate::routes::common::{actor_label, bytes_ctx, json_response, query_ctx};
use crate::routes::extract_identity;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::Request;
use serde_json::{json, Value};

/// Groups are managed with APP-level credentials (X-App-Key + HMAC): the app
/// owns its groups absolutely. User JWTs are not allowed to manage groups.
fn app_id_of(identity: &Identity) -> Result<i64, ApiError> {
    match identity {
        Identity::App(id) => Ok(*id),
        _ => Err(ApiError::forbidden(
            "Group management requires app-level credentials.",
        )),
    }
}

fn parse_group_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad_request("Invalid group name: must be 1..=64 characters."));
    }
    if name.contains('/') || name.contains('\\') || name.contains(' ') {
        return Err(ApiError::bad_request("Invalid group name: no '/', '\\' or spaces."));
    }
    Ok(name)
}

// GET /v1/groups
pub async fn list_groups(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let conn = st.db.lock().unwrap();
    let groups = db::list_groups(&conn, app_id)?;
    let items: Vec<Value> = groups
        .iter()
        .map(|g| json!({ "name": g.name, "members": g.members, "created_at": g.created_at }))
        .collect();
    Ok(json_response(json!({ "app_id": app_id, "groups": items })))
}

// POST /v1/groups   {"name": "engineers"}
pub async fn create_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("name is required."))?;
    let name = parse_group_name(name)?;
    let conn = st.db.lock().unwrap();
    let g = match db::create_group(&conn, app_id, name) {
        Ok(g) => g,
        Err(_) => return Err(ApiError::bad_request("Group name already exists.")),
    };
    db::audit(
        &conn,
        &db::AuditEntry { actor: &actor_label(&identity), action: "group.create", app_id: Some(app_id), target: name, ip: &ctx.client_ip(), decision: "allow" },
        crate::config::Config::now(),
    );
    Ok(json_response(json!({ "name": g.name, "members": g.members, "created_at": g.created_at })))
}

// GET /v1/groups/{name}
pub async fn get_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let name = ctx
        .path_segment(3)
        .ok_or_else(|| ApiError::bad_request("Missing group name."))?;
    let conn = st.db.lock().unwrap();
    let g = db::group_by_name(&conn, app_id, &name)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    Ok(json_response(json!({ "name": g.name, "members": g.members, "created_at": g.created_at })))
}

// DELETE /v1/groups/{name}
pub async fn delete_group(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let name = ctx
        .path_segment(3)
        .ok_or_else(|| ApiError::bad_request("Missing group name."))?;
    let conn = st.db.lock().unwrap();
    if !db::delete_group(&conn, app_id, &name)? {
        return Err(ApiError::not_found("Group not found."));
    }
    db::audit(
        &conn,
        &db::AuditEntry { actor: &actor_label(&identity), action: "group.delete", app_id: Some(app_id), target: &name, ip: &ctx.client_ip(), decision: "allow" },
        crate::config::Config::now(),
    );
    Ok(json_response(json!({ "deleted": name })))
}

// POST /v1/groups/{name}/members   {"user_id": "alice"}
pub async fn add_group_member(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let name = ctx
        .path_segment(3)
        .ok_or_else(|| ApiError::bad_request("Missing group name."))?;
    let body: Value = serde_json::from_slice(&ctx.body).map_err(ApiError::from)?;
    let user_id = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("user_id is required."))?;
    crate::routes::common::validate_user_id(user_id)
        .map_err(|_| ApiError::bad_request("Invalid user_id."))?;
    let conn = st.db.lock().unwrap();
    let g = db::add_group_member(&conn, app_id, &name, user_id)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    db::audit(
        &conn,
        &db::AuditEntry { actor: &actor_label(&identity), action: "group.member_add", app_id: Some(app_id), target: &format!("{name}:{user_id}"), ip: &ctx.client_ip(), decision: "allow" },
        crate::config::Config::now(),
    );
    Ok(json_response(json!({ "name": g.name, "members": g.members })))
}

// DELETE /v1/groups/{name}/members/{user_id}
pub async fn remove_group_member(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let identity = extract_identity(&st, &ctx)?;
    let app_id = app_id_of(&identity)?;
    let name = ctx
        .path_segment(3)
        .ok_or_else(|| ApiError::bad_request("Missing group name."))?;
    let user_id = ctx
        .path_segment(5)
        .ok_or_else(|| ApiError::bad_request("Missing user_id."))?;
    let conn = st.db.lock().unwrap();
    let g = db::remove_group_member(&conn, app_id, &name, &user_id)?
        .ok_or_else(|| ApiError::not_found("Group not found."))?;
    db::audit(
        &conn,
        &db::AuditEntry { actor: &actor_label(&identity), action: "group.member_remove", app_id: Some(app_id), target: &format!("{name}:{user_id}"), ip: &ctx.client_ip(), decision: "allow" },
        crate::config::Config::now(),
    );
    Ok(json_response(json!({ "name": g.name, "members": g.members })))
}
