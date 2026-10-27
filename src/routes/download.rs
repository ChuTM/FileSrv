use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::storage;
use crate::tokens;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub async fn download(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let uri = req.uri();
    let token = uri.path().split('/').nth(3).unwrap_or("").to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("Token is required."));
    }
    // Client IP for IP-bound share tokens: socket peer by default; the
    // X-Forwarded-For header is only consulted in trusted-proxy mode (test
    // report §5.2), otherwise a spoofed header has no effect.
    let ip = {
        let peer = crate::routes::peer_ip_of(&req);
        if st.cfg.trust_xff {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
                .unwrap_or(peer)
        } else {
            peer
        }
    };

    // Capability check: valid, unexpired, unrevoked token (+ IP binding).
    let grant = tokens::verify(&st.db, &token, &ip)
        .ok_or_else(|| ApiError::not_found("Token not found or expired."))?;

    let (file, path) = {
        let conn = st.db.lock().unwrap();
        let file = db::file_by_id(&conn, grant.file_id)?
            .filter(|f| f.app_id == grant.app_id && f.deleted_at.is_none())
            .ok_or_else(|| ApiError::not_found("File not found."))?;
        let app = db::app_by_id(&conn, grant.app_id)?;
        if !app.map(|a| a.enabled && a.deleted_at.is_none()).unwrap_or(false) {
            return Err(ApiError::not_found("File not found."));
        }
        let p = storage::resolve_blob(&st.cfg, grant.app_id, &file.storage_uuid, file.blob_path.as_deref())
            .map_err(|_| ApiError::not_found("File content missing."))?;
        (file, p)
    };

    serve_file(&file, &path, req.headers()).await
}

fn parse_range(spec: &str, size: u64) -> Option<(u64, u64)> {
    let spec = spec.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let end = if end.is_empty() { None } else { end.parse::<u64>().ok() };
    match (start.parse::<u64>().ok(), end) {
        (Some(s), Some(e)) if s <= e && s < size => Some((s, (e - s + 1).min(size - s))),
        (Some(s), None) if s < size => Some((s, size - s)),
        (None, Some(suffix)) if suffix > 0 => {
            let start = size.saturating_sub(suffix);
            Some((start, size - start))
        }
        _ => None,
    }
}

async fn serve_file(
    file: &db::FileRow,
    path: &std::path::Path,
    headers: &axum::http::HeaderMap,
) -> ApiResult {
    let size = file.size.max(0) as u64;
    let etag = format!("\"sha256-{}\"", file.sha256);

    // Conditional GET: If-None-Match
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim() == etag {
            return Ok(Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, &etag)
                .header(header::CACHE_CONTROL, "private, max-age=1500")
                .body(Body::empty())
                .unwrap());
        }
    }

    // Range support (bytes=start-end / start- / -suffix)
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|v| parse_range(v, size));

    let (start, len) = match range {
        Some(Some((s, l))) => (s, l),
        Some(None) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                .body(Body::empty())
                .unwrap())
        }
        None => (0, size),
    };

    let mut f = tokio::fs::File::open(path).await?;
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let limited = f.take(len);
    let stream = tokio_util::io::ReaderStream::new(limited);
    let body = Body::from_stream(stream);

    let mut b = Response::builder()
        .status(if start != 0 || len != size {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, "private, max-age=1500")
        .header(header::CONTENT_TYPE, &file.content_type)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file.storage_uuid),
        );
    if start != 0 || len != size {
        b = b
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, start + len - 1, size),
            )
            .header(header::CONTENT_LENGTH, len);
    } else {
        b = b.header(header::CONTENT_LENGTH, size);
    }
    Ok(b.body(body).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("bytes=0-4", 100), Some((0, 5)));
        assert_eq!(parse_range("bytes=10-", 100), Some((10, 90)));
        assert_eq!(parse_range("bytes=-20", 100), Some((80, 20)));
        assert_eq!(parse_range("bytes=99-99", 100), Some((99, 1)));
        assert_eq!(parse_range("bytes=5-2", 100), None);
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(parse_range("bytes=-0", 100), None);
        assert_eq!(parse_range("bytes=x-y", 100), None);
    }
}
