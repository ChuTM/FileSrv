use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", msg)
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", msg)
    }
    pub fn too_large(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", msg)
    }
    pub fn quota(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "quota_exceeded", msg)
    }
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal server error.",
        )
    }
    pub fn internal_msg(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_e: rusqlite::Error) -> Self {
        ApiError::internal()
    }
}

impl From<tokio::io::Error> for ApiError {
    fn from(_e: tokio::io::Error) -> Self {
        ApiError::internal()
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_e: serde_json::Error) -> Self {
        ApiError::bad_request("Malformed JSON body.")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let rid: String = crate::crypto::random_token().chars().take(12).collect();
        let body = json!({
            "error": {
                "code": self.code,
                "message": self.message,
                "request_id": rid
            }
        });
        (self.status, axum::Json(body)).into_response()
    }
}

pub type ApiResult = Result<axum::response::Response, ApiError>;
