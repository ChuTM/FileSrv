//! Admin console static assets (`index.html` / `app.js` / `style.css`), embedded
//! at compile time with `include_str!` and served ONLY on the loopback admin
//! bind (`ADMIN_BIND`). The public router must never reference this module.
//!
//! Security posture:
//! - The handlers serve pure static bytes — no secrets, no per-request data.
//! - The browser navigation itself cannot carry an `Authorization` header, so
//!   these routes are intentionally unauthenticated; they sit behind the
//!   loopback-only admin bind and ship nothing sensitive. The app's real API
//!   (`/admin/v1/*`) remains bearer-authenticated.
//! - Every response carries hardening headers (CSP, frame deny, nosniff,
//!   no-store, no-referrer).

use axum::http::{HeaderMap, HeaderValue};

const INDEX_HTML: &str = include_str!("admin_ui/static/index.html");
const APP_JS: &str = include_str!("admin_ui/static/app.js");
const STYLE_CSS: &str = include_str!("admin_ui/static/style.css");

const CSP: &str = concat!(
    "default-src 'self'; ",
    "style-src 'unsafe-inline'; ",
    "script-src 'self'; ",
    "img-src 'self'; ",
    "base-uri 'none'; ",
    "form-action 'none'; ",
    "frame-ancestors 'none'"
);

fn security_headers(content_type: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(axum::http::header::HeaderName::from_static("content-security-policy"), HeaderValue::from_static(CSP));
    h.insert(axum::http::header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(axum::http::header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h
}

pub async fn index_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), INDEX_HTML)
}

pub async fn app_js() -> (HeaderMap, &'static str) {
    (security_headers("application/javascript; charset=utf-8"), APP_JS)
}

pub async fn style_css() -> (HeaderMap, &'static str) {
    (security_headers("text/css; charset=utf-8"), STYLE_CSS)
}
