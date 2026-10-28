//! Admin console static assets (`login.html` / `apps.html` / `audit.html` /
//! `backup.html` / `archive.html` / `settings.html` / `app.js` / `style.css`),
//! embedded at compile time with `include_str!` and served ONLY on the loopback
//! admin bind (`ADMIN_BIND`). The public router must never reference this
//! module — with ONE deliberate exception: `security.txt` (RFC 9116). It is a
//! public disclosure file with no secrets and, by spec, must be reachable from
//! the public origin, so `public_router` serves `/.well-known/security.txt`
//! from here. Everything else in this module stays loopback-only.
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

const LOGIN_HTML: &str = include_str!("admin_ui/static/login.html");
const DASHBOARD_APPS_HTML: &str = include_str!("admin_ui/static/dashboard/apps.html");
const DASHBOARD_AUDIT_HTML: &str = include_str!("admin_ui/static/dashboard/audit.html");
const DASHBOARD_BACKUP_HTML: &str = include_str!("admin_ui/static/dashboard/backup.html");
const DASHBOARD_ARCHIVE_HTML: &str = include_str!("admin_ui/static/dashboard/archive.html");
const DASHBOARD_SETTINGS_HTML: &str = include_str!("admin_ui/static/dashboard/settings.html");
const DASHBOARD_CSS: &str = include_str!("admin_ui/static/dashboard/dashboard.css");
const APP_JS: &str = include_str!("admin_ui/static/app.js");
const STYLE_CSS: &str = include_str!("admin_ui/static/style.css");
const GSAP_JS: &str = include_str!("admin_ui/static/gsap.min.js");
const SECURITY_TXT: &str = include_str!("admin_ui/static/.well-known/security.txt");

const CSP: &str = concat!(
    "default-src 'self'; ",
    // Allow same-origin stylesheet AND inline styles (app.js sets styles via
    // the CSSOM). Omitting 'self' here blocks style.css entirely — a real bug.
    "style-src 'self' 'unsafe-inline'; ",
    // 'unsafe-eval' is scoped to this loopback-only admin console. It lets the
    // front-end bootstrap GSAP from the self-hosted gsap.min.js even in
    // sandboxed webviews where an external <script> runs in an isolated global.
    "script-src 'self' 'unsafe-eval'; ",
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

pub async fn login_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), LOGIN_HTML)
}

pub async fn apps_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), DASHBOARD_APPS_HTML)
}

pub async fn audit_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), DASHBOARD_AUDIT_HTML)
}

pub async fn backup_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), DASHBOARD_BACKUP_HTML)
}

pub async fn archive_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), DASHBOARD_ARCHIVE_HTML)
}

pub async fn settings_html() -> (HeaderMap, &'static str) {
    (security_headers("text/html; charset=utf-8"), DASHBOARD_SETTINGS_HTML)
}

pub async fn dashboard_css() -> (HeaderMap, &'static str) {
    (security_headers("text/css; charset=utf-8"), DASHBOARD_CSS)
}

pub async fn app_js() -> (HeaderMap, &'static str) {
    (security_headers("application/javascript; charset=utf-8"), APP_JS)
}

pub async fn style_css() -> (HeaderMap, &'static str) {
    (security_headers("text/css; charset=utf-8"), STYLE_CSS)
}

pub async fn gsap_js() -> (HeaderMap, &'static str) {
    (security_headers("application/javascript; charset=utf-8"), GSAP_JS)
}

/// RFC 9116 security.txt — the only asset referenced by the public router.
/// Pure static text, no secrets, served with the same hardening headers.
pub async fn security_txt() -> (HeaderMap, &'static str) {
    (security_headers("text/plain; charset=utf-8"), SECURITY_TXT)
}
