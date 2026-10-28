use crate::authz::Identity;
use crate::db::{self, FileRow};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit;
use crate::routes::common::{bytes_ctx, json_response, query_ctx};
use crate::routes::extract_identity;
use crate::state::AppState;
use crate::storage;
use axum::body::Body;
use axum::extract::State as AxState;
use axum::http::Request;
use axum::response::Response;
use rusqlite::params;
use serde_json::{json, Value};
use std::sync::Arc;

// ---------------- Export ----------------

pub async fn export_files(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = bytes_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    if let Err(resp) = ratelimit::gate(&st, app_id) {
        return Ok(*resp);
    }

    // Optional format: "tar" (default, back-compatible) or "zip" (§9: the
    // export is organized by user_id either way).
    let body: Value = serde_json::from_slice(&ctx.body).unwrap_or(Value::Null);
    let format = body
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("tar");
    if !matches!(format, "tar" | "zip") {
        return Err(ApiError::bad_request("format must be 'tar' or 'zip'."));
    }

    let job_id = {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "INSERT INTO export_jobs(app_id,status,created_at) VALUES(?1,'pending',?2)",
            params![app_id, crate::config::Config::now()],
        )?;
        conn.last_insert_rowid()
    };

    let st = Arc::new(st);
    let job_id_c = job_id;
    let app_id_c = app_id;
    let format = format.to_string();
    tokio::spawn(async move {
        let _ = run_export(&st, app_id_c, job_id_c, &format).await;
    });

    Ok(json_response(json!({ "job_id": job_id, "status": "pending" })))
}

async fn run_export(st: &Arc<AppState>, app_id: i64, job_id: i64, format: &str) -> Result<(), ApiError> {
    let file_rows = {
        let conn = st.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,app_id,user_id,folder_id,storage_uuid,blob_path,logical_path,content_type,size,sha256,classification,owner,acl,created_at,deleted_at
             FROM files WHERE app_id=?1 AND deleted_at IS NULL",
        )?;
        let rows = stmt.query_map(params![app_id], |r| {
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
            })
        })?;
        let mut v = Vec::new();
        for r in rows {
            v.push(r?);
        }
        v
    };

    let export_dir = st
        .cfg
        .blob_root
        .join("exports")
        .join(format!("app_{app_id}"));
    std::fs::create_dir_all(&export_dir).ok();
    let path = export_dir.join(match format {
        "zip" => format!("job_{job_id}.zip"),
        _ => format!("job_{job_id}.tar"),
    });
    let mut total: i64 = 0;
    let archiving_ok = if format == "zip" {
        build_zip_archive(st, app_id, &file_rows, &path, &mut total)
    } else {
        build_tar_archive(st, app_id, &file_rows, &path, &mut total)
    };
    if !archiving_ok {
        let conn = st.db.lock().unwrap();
        conn.execute(
            "UPDATE export_jobs SET status='failed', done_at=?1 WHERE id=?2",
            params![crate::config::Config::now(), job_id],
        )
        .ok();
        return Ok(());
    }

    let size = std::fs::metadata(&path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let conn = st.db.lock().unwrap();
    conn.execute(
        "UPDATE export_jobs SET status='ready', done_at=?1, size=?2, path=?3 WHERE id=?4",
        params![
            crate::config::Config::now(),
            size,
            path.to_string_lossy().to_string(),
            job_id
        ],
    )
    .ok();
    db::audit(&conn, &db::AuditEntry { actor: &format!("app:{app_id}"), action: "export.run", app_id: Some(app_id), target: &format!("job:{job_id}"), ip: "", decision: "allow" }, crate::config::Config::now());
    let _ = total;
    Ok(())
}

fn blob_bytes_for_export(
    st: &AppState,
    app_id: i64,
    fr: &FileRow,
) -> Option<Vec<u8>> {
    let src = storage::resolve_blob(&st.cfg, app_id, &fr.storage_uuid, fr.blob_path.as_deref()).ok()?;
    std::fs::read(&src).ok()
}

fn build_tar_archive(
    st: &AppState,
    app_id: i64,
    file_rows: &[FileRow],
    path: &std::path::Path,
    total: &mut i64,
) -> bool {
    let f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut builder = tar::Builder::new(f);
    for fr in file_rows {
        let src = match storage::resolve_blob(&st.cfg, app_id, &fr.storage_uuid, fr.blob_path.as_deref()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(fh) = std::fs::File::open(&src) {
            let mut header = tar::Header::new_gnu();
            header.set_size(fr.size as u64);
            header.set_mode(0o600);
            header.set_cksum();
            let entry_name = format!("files/{}/{}", fr.user_id, fr.storage_uuid);
            if builder.append_data(&mut header, entry_name, fh).is_ok() {
                *total += fr.size;
            }
        }
    }
    // Builder::drop flushes the tar trailer (tar 0.4 Drop impl).
    drop(builder);
    true
}

/// Zip archive organized by user_id (§9): entries are `files/<user_id>/<uuid>`.
fn build_zip_archive(
    st: &AppState,
    app_id: i64,
    file_rows: &[FileRow],
    path: &std::path::Path,
    total: &mut i64,
) -> bool {
    use std::io::Write;
    let f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut zip = zip::ZipWriter::new(f);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for fr in file_rows {
        let Some(bytes) = blob_bytes_for_export(st, app_id, fr) else {
            continue;
        };
        let entry_name = format!("files/{}/{}", fr.user_id, fr.storage_uuid);
        if zip.start_file(&entry_name, options).is_ok() && zip.write_all(&bytes).is_ok() {
            *total += fr.size;
        }
    }
    zip.finish().is_ok()
}

pub async fn export_status(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    let job_id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid job id."))?;
    let conn = st.db.lock().unwrap();
    let (status, size): (String, Option<i64>) = conn
        .query_row(
            "SELECT status, size FROM export_jobs WHERE id=?1 AND app_id=?2",
            params![job_id, app_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
        .ok_or_else(|| ApiError::not_found("Export job not found."))?;
    Ok(json_response(json!({
        "job_id": job_id,
        "status": status,
        "size": size,
        "download_url": format!("/v1/apps/exports/{job_id}/download")
    })))
}

pub async fn export_download(AxState(st): AxState<AppState>, req: Request<Body>) -> ApiResult {
    let ctx = query_ctx(&st, req).await?;
    let app_id = match extract_identity(&st, &ctx)? {
        Identity::App(id) => id,
        _ => return Err(ApiError::forbidden("Export requires app-level credentials.")),
    };
    let job_id: i64 = ctx
        .path_segment(4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::bad_request("Invalid job id."))?;
    let (status, path) = {
        let conn = st.db.lock().unwrap();
        conn.query_row(
            "SELECT status, COALESCE(path,'') FROM export_jobs WHERE id=?1 AND app_id=?2",
            params![job_id, app_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
        .ok_or_else(|| ApiError::not_found("Export job not found."))?
    };
    if status != "ready" {
        return Err(ApiError::conflict("Export job is not ready."));
    }
    let p = std::path::PathBuf::from(&path);
    if !p.starts_with(st.cfg.blob_root.join("exports")) {
        return Err(ApiError::forbidden("Invalid export path."));
    }
    let f = tokio::fs::File::open(&p).await?;
    let stream = tokio_util::io::ReaderStream::new(f);
    let body = Body::from_stream(stream);
    let (content_type, filename) = match p.extension().and_then(|e| e.to_str()) {
        Some("zip") => ("application/zip", format!("job_{job_id}.zip")),
        _ => ("application/x-tar", format!("job_{job_id}.tar")),
    };
    Ok(Response::builder()
        .header("Content-Type", content_type)
        .header("Content-Disposition", format!("attachment; filename=\"{filename}\""))
        .body(body)
        .unwrap())
}
