use crate::authz::{self, Action, Identity};
use crate::crypto;
use crate::db::{self};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;
use crate::routes::common::{
    actor_label, app_identity_id, bytes_ctx, json_response, load_app_file,
};
use crate::routes::extract_identity;
use crate::state::AppState;
use crate::tokens;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::Request;
use rusqlite::params;
use serde_json::{json, Value};

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

    // Acting user for link generation. App identity MUST carry an explicit
    // user context (body `user_id` or `X-User-Id`) so every link is attributed
    // and checked against the file ACL — a defense-in-depth layer even though
    // the app is trusted. The reserved authority marker grants full tenant
    // control for genuinely system-level operations; routine per-user access
    // should always pass a real user_id instead (see docs).
    let acting_user: Option<String> = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            ctx.headers
                .get("x-user-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .filter(|s| !s.is_empty());

    // Authority marker `#Authority-<sha256(app_secret)>`: recognized only for
    // app identity and verified against the app's own secret, so an arbitrary
    // user_id string can never masquerade as the app. Bypasses the per-user
    // ACL check; the token binds to the file owner.
    let authority = match &identity {
        Identity::App(_) => match acting_user.as_deref().and_then(|s| s.strip_prefix("#Authority-")) {
            Some(marker) => {
                let conn = st.db.lock().unwrap();
                let app = db::app_by_id(&conn, app_id)?
                    .ok_or_else(|| ApiError::not_found("App not found."))?;
                let secret = crypto::open(st.cfg.server_secret.as_bytes(), &app.secret_sealed)
                    .ok_or_else(|| ApiError::forbidden("Invalid authority marker."))?;
                marker == crypto::sha256(&secret)
            }
            None => false,
        },
        _ => false,
    };

    // Permission: the acting user needs Read on the file (downloads are a read
    // capability; write/other grants never suffice). Authority bypasses.
    let grant_user: String = match &identity {
        Identity::App(_) => {
            let user = acting_user.clone().ok_or_else(|| {
                ApiError::bad_request(
                    "user_id (or X-User-Id header) is required for app-scoped link generation.",
                )
            })?;
            if authority {
                file.owner.clone()
            } else {
                let conn = st.db.lock().unwrap();
                if !authz::can_user_access_file(&conn, &file, &user, Action::Read) {
                    return Err(ApiError::forbidden("Permission denied."));
                }
                user
            }
        }
        Identity::User { user_id, .. } => {
            let conn = st.db.lock().unwrap();
            if !authz::can_user_access_file(&conn, &file, user_id, Action::Read) {
                return Err(ApiError::forbidden("Permission denied."));
            }
            user_id.clone()
        }
        _ => return Err(ApiError::forbidden("Token generation not allowed.")),
    };
    let embed_user = grant_user.clone();
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
