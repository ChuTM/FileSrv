pub mod admin;
pub mod app;
pub mod download;

use crate::auth::{self, AuthError};
use crate::authz::Identity;
use crate::error::ApiError;
use crate::state::AppState;
use axum::http::HeaderMap;
use axum::Router;

/// Shared request-parsing helpers for handlers that need raw bytes (for
/// HMAC body-hash) and manual path segments (uniform identity extraction).
pub struct ReqCtx {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body_hash: String,
    /// Real socket peer IP ("" when unavailable, e.g. test one-shot calls).
    pub peer_ip: String,
    /// Whether X-Forwarded-For may be trusted (see Config::trust_xff).
    pub trust_xff: bool,
}

impl ReqCtx {
    pub fn from_request(req: &axum::http::Request<axum::body::Body>, body: &[u8], trust_xff: bool) -> Self {
        let uri = req.uri();
        ReqCtx {
            method: req.method().as_str().to_string(),
            path: uri.path().to_string(),
            query: uri.query().unwrap_or("").to_string(),
            headers: req.headers().clone(),
            body_hash: crate::crypto::sha256(body),
            peer_ip: peer_ip_of(req),
            trust_xff,
        }
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Client IP used for IP-bound share tokens and audit logs.
    ///
    /// Security (see test report §5.2): by default this is the TCP peer IP,
    /// which a client cannot spoof. X-Forwarded-For is only parsed when the
    /// deployment explicitly enables trusted-proxy mode (Config::trust_xff);
    /// otherwise the header is ignored entirely.
    pub fn client_ip(&self) -> String {
        if self.trust_xff {
            self.header("x-forwarded-for")
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
                .unwrap_or_default()
        } else {
            self.peer_ip.clone()
        }
    }

    pub fn path_segment(&self, idx: usize) -> Option<String> {
        self.path.split('/').nth(idx).map(|s| s.to_string())
    }

    pub fn query_param(&self, key: &str) -> Option<String> {
        use url::form_urlencoded;
        form_urlencoded::parse(self.query.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

/// Best-effort extraction of the TCP peer IP from the request extensions
/// (requires the server to be served with connect info, see main.rs).
pub fn peer_ip_of(req: &axum::http::Request<axum::body::Body>) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_default()
}

pub fn extract_identity(state: &AppState, ctx: &ReqCtx) -> Result<Identity, ApiError> {
    if let Some(app_key) = ctx.header("x-app-key") {
        let sig = ctx
            .header("x-app-signature")
            .ok_or_else(|| ApiError::unauthorized("Missing X-App-Signature."))?;
        let ts = ctx
            .header("x-timestamp")
            .ok_or_else(|| ApiError::unauthorized("Missing X-Timestamp."))?;
        let nonce = ctx
            .header("x-nonce")
            .ok_or_else(|| ApiError::unauthorized("Missing X-Nonce."))?;
        let id = auth::verify_app_signature(
            &state.db,
            state.cfg.server_secret.as_bytes(),
            &app_key,
            &sig,
            &ts,
            &nonce,
            &auth::SignatureParts {
                method: &ctx.method,
                path: &ctx.path,
                query: &ctx.query,
                body_hash: &ctx.body_hash,
                client_ip: &ctx.client_ip(),
            },
        )
        .map_err(auth_err_to_api)?;
        return Ok(Identity::App(id));
    }
    if let Some(bearer) = ctx.header("authorization") {
        if let Some(jwt) = bearer.strip_prefix("Bearer ") {
            return auth::verify_user_jwt(&state.db, state.cfg.server_secret.as_bytes(), jwt)
                .map_err(auth_err_to_api);
        }
    }
    Err(ApiError::unauthorized("Authentication required."))
}

pub fn require_admin(state: &AppState, ctx: &ReqCtx) -> Result<(), ApiError> {
    let provided = ctx
        .header("authorization")
        .and_then(|b| b.strip_prefix("Bearer ").map(str::to_string))
        .ok_or_else(|| ApiError::unauthorized("Admin authentication required."))?;
    auth::verify_admin(&state.cfg.admin_token, &provided).map_err(auth_err_to_api)
}

fn auth_err_to_api(e: AuthError) -> ApiError {
    match e {
        AuthError::Missing => ApiError::unauthorized("Authentication required."),
        AuthError::Invalid => ApiError::unauthorized(e.to_string()),
    }
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(app::healthz))
        .route("/v1/upload", axum::routing::post(app::upload))
        .route("/v1/links/generate", axum::routing::post(app::generate_link))
        .route("/v1/tokens/revoke", axum::routing::post(app::revoke_token))
        .route("/v1/files", axum::routing::get(app::list_files))
        .route("/v1/files/{id}", axum::routing::get(app::get_file).delete(app::delete_file))
        .route("/v1/files/{id}/acl", axum::routing::patch(app::patch_file_acl))
        .route("/v1/files/batch/acl", axum::routing::post(app::batch_acl))
        .route("/v1/folders", axum::routing::post(app::create_folder))
        .route(
            "/v1/folders/{id}",
            axum::routing::get(app::get_folder)
                .patch(app::patch_folder)
                .delete(app::delete_folder),
        )
        .route("/v1/folders/{id}/files", axum::routing::get(app::list_folder_files))
        .route("/v1/folders/{id}/acl", axum::routing::patch(app::patch_folder_acl))
        .route("/v1/apps/export", axum::routing::post(app::export_files))
        .route("/v1/apps/exports/{id}", axum::routing::get(app::export_status))
        .route(
            "/v1/apps/exports/{id}/download",
            axum::routing::get(app::export_download),
        )
        .route("/v1/upload/init", axum::routing::post(app::upload_init))
        .route("/v1/upload/{upload_id}", axum::routing::put(app::upload_chunk))
        .route(
            "/v1/upload/{upload_id}/finalize",
            axum::routing::post(app::upload_finalize),
        )
        .route(
            "/v1/download/{token}",
            axum::routing::get(download::download).head(download::download_head),
        )
        .with_state(state)
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        // Admin console static assets — embedded at compile time, loopback only.
        // No data ships here; the app itself calls bearer-authenticated /admin/v1/*.
        .route("/admin", axum::routing::get(crate::admin_ui::index_html))
        .route("/admin/", axum::routing::get(crate::admin_ui::index_html))
        .route("/admin/index.html", axum::routing::get(crate::admin_ui::index_html))
        .route("/admin/app.js", axum::routing::get(crate::admin_ui::app_js))
        .route("/admin/style.css", axum::routing::get(crate::admin_ui::style_css))
        .route("/admin/v1/apps", axum::routing::post(admin::create_app).get(admin::list_apps))
        .route(
            "/admin/v1/apps/{id}",
            axum::routing::get(admin::get_app)
                .patch(admin::patch_app)
                .delete(admin::delete_app),
        )
        .route(
            "/admin/v1/apps/{id}/secret/rotate",
            axum::routing::post(admin::rotate_secret),
        )
        .route("/admin/v1/apps/{id}/usage", axum::routing::get(admin::app_usage))
        .route("/admin/v1/audit", axum::routing::get(admin::list_audit))
        .route("/admin/v1/backups/run", axum::routing::post(admin::backup_run))
        .route("/admin/v1/backups", axum::routing::get(admin::backup_list))
        .route("/admin/v1/backups/{id}", axum::routing::get(admin::backup_detail))
        .route(
            "/admin/v1/backups/config",
            axum::routing::patch(admin::backup_config),
        )
        .with_state(state)
}
