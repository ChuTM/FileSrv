use crate::authz::{Acl, Identity};
use crate::crypto::sha256;
use crate::db::{self, FileRow};
use crate::error::ApiError;
use crate::routes::ReqCtx;
use crate::state::AppState;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

pub(crate) fn app_identity_id(identity: &Identity) -> i64 {
    identity.app_id().expect("app identity required")
}

pub(crate) fn json_response(v: Value) -> Response {
    Json(v).into_response()
}

pub(crate) fn actor_label(identity: &Identity) -> String {
    match identity {
        Identity::App(id) => format!("app:{id}"),
        Identity::User { app_id, user_id } => format!("app:{app_id}:user:{user_id}"),
        Identity::Token(_) => "token".into(),
        Identity::Admin => "admin".into(),
    }
}

/// Validate a client-supplied user_id BEFORE it is persisted. user_id flows
/// into export archive entry names (files/<user_id>/<uuid>) and tenant
/// bookkeeping, so path separators, traversal sequences and control
/// characters are rejected up front (F4 fix: prevents zip-slip-style archive
/// entries and garbled tenant keys). Also used by the admin "add user" API.
pub(crate) fn validate_user_id(user_id: &str) -> Result<(), ApiError> {
    if user_id.is_empty() || user_id.len() > 128 {
        return Err(ApiError::bad_request(
            "Invalid user_id: must be 1..=128 characters.",
        ));
    }
    if user_id.contains('/') || user_id.contains('\\') || user_id.contains("..") {
        return Err(ApiError::bad_request(
            "Invalid user_id: must not contain '/', '\\' or '..'.",
        ));
    }
    if user_id.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request(
            "Invalid user_id: control characters are not allowed.",
        ));
    }
    Ok(())
}

pub(crate) fn load_app_file(st: &AppState, file_id: i64, app_id: i64) -> Result<FileRow, ApiError> {
    let conn = st.db.lock().unwrap();
    let f = db::file_by_id(&conn, file_id)?
        .filter(|f| f.app_id == app_id && f.deleted_at.is_none())
        .ok_or_else(|| ApiError::not_found("File not found."))?;
    Ok(f)
}

pub(crate) fn file_meta_json(f: &FileRow) -> Value {
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

pub(crate) async fn bytes_ctx(st: &AppState, req: Request<Body>) -> Result<BytesCtx, ApiError> {
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

pub(crate) async fn query_ctx(st: &AppState, req: Request<Body>) -> Result<ReqCtx, ApiError> {
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
pub(crate) fn merge_acl(existing: &str, body: &Value) -> Result<Acl, ApiError> {
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
