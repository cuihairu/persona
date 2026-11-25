//! `/api/v1/backups`: custody endpoints for whole-database encrypted backups (sync phase 1).
//!
//! The server sees only ciphertext and metadata: the client gzips its VACUUM INTO physical
//! snapshot and encrypts it with PERSENC1 before uploading, which the server cannot decrypt.
//! POST writes to disk as a stream (computing sha256 as it goes, disconnecting and deleting
//! the half-written file if the limit is exceeded mid-flight); an identical sha256 for the
//! device's newest version is deduplicated (200 deduplicated); GET lists pages in reverse
//! order, GET downloads one (ETag = sha256), and DELETE removes the file before the row.
//! Attachments are not part of a v1 backup (a client-side convention, see THREAT_MODEL).
//! The backup sub-router has no decompression layer: ciphertext is not compressible, and
//! that removes one more decompression-bomb surface — the on-the-wire byte limit is the
//! on-disk limit.

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use chrono::Utc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use super::{decode_cursor, encode_cursor, ApiError, ErrorItem};
use crate::auth::DeviceName;
use crate::state::AppState;

/// Listing pagination: default / upper bound.
const DEFAULT_LIST_LIMIT: u32 = 20;
const MAX_LIST_LIMIT: u32 = 100;

/// Content-Length pre-check (on-the-wire bytes = on-disk bytes, capped at
/// AppState.max_backup_bytes). Over-limit requests go straight to 413 without reading the
/// body or entering authentication; for chunked requests without a CL, the streaming counter
/// inside the handler is the backstop.
pub async fn size_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let limit = state.max_backup_bytes;
    let too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len > limit);
    if too_large {
        ApiError::payload_too_large_with(limit).into_response()
    } else {
        next.run(req).await
    }
}

// ---- POST /api/v1/backups ----

#[derive(Serialize)]
struct UploadResult {
    id: String,
    device_name: String,
    size_bytes: i64,
    sha256: String,
    created_at: String,
    deduplicated: bool,
}

pub async fn upload(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceName>,
    req: Request,
) -> Response {
    if let Err(error) = tokio::fs::create_dir_all(&state.backup_dir).await {
        return ApiError::internal(error).into_response();
    }

    let id = Uuid::new_v4().to_string();
    let part_path = state.backup_dir.join(format!("{id}.persenc.part"));
    let final_path = state.backup_dir.join(format!("{id}.persenc"));

    let mut file = match tokio::fs::File::create(&part_path).await {
        Ok(file) => file,
        Err(error) => return ApiError::internal(error).into_response(),
    };

    // Stream, write and hash at once: land it to disk in 64 KiB chunks, accumulate sha256,
    // and cut the connection as soon as the limit is exceeded.
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut exceeded = false;
    let mut stream = req.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                discard_file(&part_path).await;
                return ApiError::rejection(
                    StatusCode::BAD_REQUEST,
                    format!("failed to read request body: {error}"),
                )
                .into_response();
            }
        };
        size += chunk.len() as u64;
        if size > state.max_backup_bytes as u64 {
            exceeded = true;
            break;
        }
        hasher.update(&chunk);
        if let Err(error) = file.write_all(&chunk).await {
            discard_file(&part_path).await;
            return ApiError::internal(error).into_response();
        }
    }
    if exceeded {
        discard_file(&part_path).await;
        return ApiError::payload_too_large_with(state.max_backup_bytes).into_response();
    }
    if let Err(error) = file.flush().await {
        discard_file(&part_path).await;
        return ApiError::internal(error).into_response();
    }
    drop(file);

    let sha256 = hex_lower(&hasher.finalize());
    let now = Utc::now();
    let created_at = now.to_rfc3339();
    let created_at_ms = now.timestamp_millis();

    // Per-device deduplication: if the sha256 matches the device's newest version,
    // nothing lands in the official store.
    const LATEST: &str = "SELECT id, device_name, size_bytes, sha256, created_at \
        FROM backups WHERE device_name = ?1 ORDER BY created_at_ms DESC, id DESC LIMIT 1";
    if let Ok(row) = sqlx::query(LATEST)
        .bind(&device.0)
        .fetch_one(&state.pool)
        .await
    {
        let existing_sha: String = row.try_get("sha256").unwrap_or_default();
        if existing_sha == sha256 {
            discard_file(&part_path).await;
            return (
                StatusCode::OK,
                axum::Json(UploadResult {
                    id: row.try_get("id").unwrap_or_default(),
                    device_name: row.try_get("device_name").unwrap_or_default(),
                    size_bytes: row.try_get("size_bytes").unwrap_or_default(),
                    sha256: existing_sha,
                    created_at: row.try_get("created_at").unwrap_or_default(),
                    deduplicated: true,
                }),
            )
                .into_response();
        }
    }

    // Promote the half-written file + persist the metadata; if the metadata write fails,
    // roll back the promoted file.
    if let Err(error) = tokio::fs::rename(&part_path, &final_path).await {
        discard_file(&part_path).await;
        return ApiError::internal(error).into_response();
    }
    const INSERT: &str = "INSERT INTO backups \
        (id, device_name, size_bytes, sha256, content_path, created_at, created_at_ms) \
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
    if let Err(error) = sqlx::query(INSERT)
        .bind(&id)
        .bind(&device.0)
        .bind(size as i64)
        .bind(&sha256)
        .bind(format!("{id}.persenc"))
        .bind(&created_at)
        .bind(created_at_ms)
        .execute(&state.pool)
        .await
    {
        discard_file(&final_path).await;
        return ApiError::internal(error).into_response();
    }
    state.metrics.add_backups_created(1);

    // Global retention policy (0 = unlimited): over the cap, the oldest versions are
    // removed, file and row together.
    if let Err(error) = enforce_retention(&state).await {
        tracing::warn!(%error, "backup retention sweep failed");
    }

    (
        StatusCode::CREATED,
        axum::Json(UploadResult {
            id,
            device_name: device.0,
            size_bytes: size as i64,
            sha256,
            created_at,
            deduplicated: false,
        }),
    )
        .into_response()
}

/// Delete the oldest versions beyond the retention cap (file first; the row is deleted even
/// if the file is already gone, to avoid orphan metadata).
async fn enforce_retention(state: &AppState) -> Result<(), sqlx::Error> {
    let max_versions = state.backup_max_versions as i64;
    if max_versions == 0 {
        return Ok(());
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backups")
        .fetch_one(&state.pool)
        .await?;
    if count <= max_versions {
        return Ok(());
    }
    const STALE: &str = "SELECT id, content_path FROM backups \
        ORDER BY created_at_ms ASC, id ASC LIMIT ?1";
    let stale = sqlx::query(STALE)
        .bind(count - max_versions)
        .fetch_all(&state.pool)
        .await?;
    for row in stale {
        let id: String = row.try_get("id")?;
        let content_path: String = row.try_get("content_path")?;
        discard_file(&state.backup_dir.join(content_path)).await;
        sqlx::query("DELETE FROM backups WHERE id = ?1")
            .bind(&id)
            .execute(&state.pool)
            .await?;
        state.metrics.add_backups_deleted(1);
    }
    Ok(())
}

// ---- GET /api/v1/backups ----

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Serialize)]
pub struct BackupMeta {
    pub id: String,
    pub device_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub created_at: String,
}

#[derive(Serialize)]
struct BackupPage {
    backups: Vec<BackupMeta>,
    next_cursor: Option<String>,
}

pub async fn list(State(state): State<AppState>, Query(params): Query<ListQuery>) -> Response {
    let limit = match params.limit {
        None => DEFAULT_LIST_LIMIT,
        Some(0) => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch("limit", "must be at least 1")],
            )
            .into_response()
        }
        Some(limit) if limit > MAX_LIST_LIMIT => {
            return ApiError::validation(
                "invalid limit",
                vec![ErrorItem::batch(
                    "limit",
                    format!("must be at most {MAX_LIST_LIMIT}"),
                )],
            )
            .into_response()
        }
        Some(limit) => limit,
    };
    let cursor = match &params.cursor {
        None => None,
        Some(raw) => match decode_cursor(raw) {
            Ok(cursor) => Some(cursor),
            Err(error) => return error.into_response(),
        },
    };

    // Reverse order (new -> old): the cursor (created_at_ms, id) is strictly below the
    // current position.
    const SELECT: &str = "SELECT id, device_name, size_bytes, sha256, created_at, created_at_ms \
        FROM backups \
        WHERE (?1 IS NULL OR (created_at_ms, id) < (?1, ?2)) \
        ORDER BY created_at_ms DESC, id DESC \
        LIMIT ?3";
    let rows = match sqlx::query(SELECT)
        .bind(cursor.as_ref().map(|(ms, _)| *ms))
        .bind(cursor.as_ref().map(|(_, id)| id.as_str()))
        .bind(i64::from(limit) + 1)
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => rows,
        Err(error) => return ApiError::internal(error).into_response(),
    };

    let has_more = rows.len() > limit as usize;
    let next_cursor = if has_more {
        let last = &rows[limit as usize - 1];
        match (
            last.try_get::<i64, _>("created_at_ms"),
            last.try_get::<String, _>("id"),
        ) {
            (Ok(ms), Ok(id)) => Some(encode_cursor(ms, &id)),
            (Err(error), _) | (_, Err(error)) => return ApiError::internal(error).into_response(),
        }
    } else {
        None
    };

    let page = &rows[..rows.len().min(limit as usize)];
    let backups = page
        .iter()
        .map(|row| BackupMeta {
            id: row.try_get("id").unwrap_or_default(),
            device_name: row.try_get("device_name").unwrap_or_default(),
            size_bytes: row.try_get("size_bytes").unwrap_or_default(),
            sha256: row.try_get("sha256").unwrap_or_default(),
            created_at: row.try_get("created_at").unwrap_or_default(),
        })
        .collect();

    (axum::Json(BackupPage {
        backups,
        next_cursor,
    }))
    .into_response()
}

// ---- GET /api/v1/backups/:id ----

pub async fn download(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    const SELECT: &str = "SELECT size_bytes, sha256, content_path FROM backups WHERE id = ?1";
    let Ok(row) = sqlx::query(SELECT).bind(&id).fetch_one(&state.pool).await else {
        return ApiError::not_found().into_response();
    };
    let size_bytes: i64 = row.try_get("size_bytes").unwrap_or_default();
    let sha256: String = row.try_get("sha256").unwrap_or_default();
    let content_path: String = row.try_get("content_path").unwrap_or_default();

    let file = match tokio::fs::File::open(state.backup_dir.join(content_path)).await {
        Ok(file) => file,
        Err(error) => {
            // The row exists but the file is gone: metadata and storage are out of sync;
            // expose a 404 and log the details.
            tracing::warn!(%error, backup_id = %id, "backup content file missing");
            return ApiError::not_found().into_response();
        }
    };

    let stream = ReaderStream::with_capacity(file, 64 * 1024);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&size_bytes.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("\"{sha256}\"")) {
        headers.insert(header::ETAG, value);
    }
    response
}

// ---- DELETE /api/v1/backups/:id ----

pub async fn delete(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    const SELECT: &str = "SELECT content_path FROM backups WHERE id = ?1";
    let Ok(row) = sqlx::query(SELECT).bind(&id).fetch_one(&state.pool).await else {
        return ApiError::not_found().into_response();
    };
    let content_path: String = row.try_get("content_path").unwrap_or_default();

    // File first (missing counts as already cleaned, so the row is still deleted; any
    // other failure keeps the row, preserving retryability).
    if let Err(error) = tokio::fs::remove_file(state.backup_dir.join(content_path)).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            return ApiError::internal(error).into_response();
        }
    }
    if let Err(error) = sqlx::query("DELETE FROM backups WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
    {
        return ApiError::internal(error).into_response();
    }
    state.metrics.add_backups_deleted(1);
    StatusCode::NO_CONTENT.into_response()
}

// ---- Utilities ----

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Delete a half-written/temporary file: NotFound is silent (idempotent); other failures
/// are only logged — every call site is already on an error-response path, so a failed
/// deletion must not mask the original error.
async fn discard_file(path: &std::path::Path) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(%error, path = ?path, "failed to discard partial backup file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hex_lower;
    use sha2::{Digest, Sha256};

    #[test]
    fn hex_lower_matches_known_digest() {
        // The first 16 hex characters of sha256("")
        assert_eq!(&hex_lower(&Sha256::digest(b""))[..16], "e3b0c44298fc1c14");
    }
}

#[cfg(test)]
mod endpoint_tests {
    use crate::test_support::{
        delete_backup, get_backup_download, get_backups, post_backup, send, send_binary,
        setup_with_backups,
    };
    use axum::http::StatusCode;

    const SPEC: &str = "laptop:laptop-tok,phone:phone-tok";
    const LAPTOP: &str = "laptop-tok";
    const PHONE: &str = "phone-tok";

    fn sha256_hex(body: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(body.as_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    async fn upload(
        router: &axum::Router,
        body: &str,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        send(router.clone(), post_backup(body, token)).await
    }

    #[tokio::test]
    async fn upload_stores_file_metadata_and_attributes_device() {
        let (router, state, _dir) = setup_with_backups(SPEC, 0, 1024).await;

        let (status, body) = upload(&router, "vault-snapshot-1", LAPTOP).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["deduplicated"], false);
        assert_eq!(body["device_name"], "laptop");
        assert_eq!(body["size_bytes"], 16);
        assert_eq!(body["sha256"], sha256_hex("vault-snapshot-1"));

        // Ownership is derived from the token: another device uploading identical content
        // still gets its own accounting
        let (status, body) = upload(&router, "vault-snapshot-2", PHONE).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["device_name"], "phone");

        // The ciphertext file lands at {backup_dir}/{id}.persenc
        let id = body["id"].as_str().unwrap().to_owned();
        let path = state.backup_dir.join(format!("{id}.persenc"));
        assert!(tokio::fs::try_exists(&path).await.unwrap());

        let (_, _, _, _, created, _) = state.metrics.snapshot();
        assert_eq!(created, 2);
    }

    #[tokio::test]
    async fn upload_deduplicates_identical_latest_version_per_device() {
        let (router, state, _dir) = setup_with_backups(SPEC, 0, 1024).await;

        let (first_status, first) = upload(&router, "same-bytes", LAPTOP).await;
        assert_eq!(first_status, StatusCode::CREATED);
        let (second_status, second) = upload(&router, "same-bytes", LAPTOP).await;
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(second["deduplicated"], true);
        assert_eq!(second["id"], first["id"]);

        // A dedup hit stores no new file and counts nothing: the directory holds only one
        // .persenc
        let files = count_persenc(&state.backup_dir).await;
        assert_eq!(files, 1);
        let (_, _, _, _, created, _) = state.metrics.snapshot();
        assert_eq!(created, 1);

        // The same content from another device is not deduplicated (the dedup key is
        // device + sha256)
        let (status, body) = upload(&router, "same-bytes", PHONE).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["deduplicated"], false);
        assert_eq!(count_persenc(&state.backup_dir).await, 2);
    }

    #[tokio::test]
    async fn upload_rejects_oversized_content_length_without_reading_body() {
        // CL pre-check: with the 416 limit set to 16, a 32-byte request with a CL is cut
        // right at size_guard
        let (router, state, _dir) = setup_with_backups(SPEC, 0, 16).await;
        let body = "0123456789abcdef0123456789abcdef"; // 32 bytes
        let (status, error) = upload(&router, body, LAPTOP).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error["error"]["code"], "payload_too_large");
        assert_eq!(count_persenc(&state.backup_dir).await, 0);
        assert_eq!(count_part_files(&state.backup_dir).await, 0);
    }

    #[tokio::test]
    async fn upload_streams_without_content_length_and_aborts_on_limit() {
        // A streaming body with no CL: size_guard lets it pass, the handler counts while
        // writing, and exceeding the limit aborts and deletes the half-written file (no
        // .part residue).
        let (router, state, _dir) = setup_with_backups(SPEC, 0, 16).await;
        let stream = futures::stream::iter(vec![
            Ok::<&[u8], std::io::Error>(b"0123456789abcdef"),
            Ok(b"0123456789abcdef"), // the 2nd chunk hits the cap
            Ok(b"tail-must-not-land"),
        ]);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/backups")
            .header("authorization", format!("Bearer {LAPTOP}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from_stream(stream))
            .unwrap();
        let (status, _, body) = send_binary(router, request).await;
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error["error"]["code"], "payload_too_large");
        assert_eq!(count_persenc(&state.backup_dir).await, 0);
        assert_eq!(count_part_files(&state.backup_dir).await, 0);
    }

    #[tokio::test]
    async fn list_pages_desc_without_gaps_or_duplicates() {
        let (router, _, _dir) = setup_with_backups(SPEC, 0, 1024).await;
        // The sort key is (created_at_ms, id): within the same millisecond the tie-breaker
        // is the random UUID (id DESC), and v2/v3 in the same ms flip the order 50% of the
        // time (batch 11's CI hit this once). A single device's real serial pushes are far
        // more than 1ms apart; here we space the milliseconds apart for determinism.
        for content in ["v1", "v2", "v3"] {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let (status, _) = upload(&router, content, LAPTOP).await;
            assert_eq!(status, StatusCode::CREATED);
        }

        // Reverse order (new -> old): v3, v2 | v1
        let (status, page1) = send(
            router.clone(),
            get_backups("/api/v1/backups?limit=2", LAPTOP),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ids1: Vec<&str> = page1["backups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids1.len(), 2);
        assert!(page1["next_cursor"].is_string());

        let cursor = page1["next_cursor"].as_str().unwrap();
        let (status, page2) = send(
            router,
            get_backups(&format!("/api/v1/backups?limit=2&cursor={cursor}"), LAPTOP),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ids2: Vec<&str> = page2["backups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids2.len(), 1);
        assert!(page2["next_cursor"].is_null());

        // No repeats, no omissions
        assert_eq!(
            ids1.iter()
                .chain(ids2.iter())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );

        // Order equals upload reverse order: sha256 comparison (v3, the newest, first)
        assert_eq!(page1["backups"][0]["sha256"], sha256_hex("v3"));
        assert_eq!(page1["backups"][1]["sha256"], sha256_hex("v2"));
        assert_eq!(page2["backups"][0]["sha256"], sha256_hex("v1"));
    }

    #[tokio::test]
    async fn list_rejects_out_of_range_limits() {
        let (router, _, _dir) = setup_with_backups(SPEC, 0, 1024).await;
        for uri in ["/api/v1/backups?limit=0", "/api/v1/backups?limit=101"] {
            let (status, body) = send(router.clone(), get_backups(uri, LAPTOP)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
            assert_eq!(body["error"]["code"], "validation");
        }
        // The boundary limit of 100 is legal
        let (status, _) = send(router, get_backups("/api/v1/backups?limit=100", LAPTOP)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn download_returns_exact_bytes_with_etag() {
        let (router, _, _dir) = setup_with_backups(SPEC, 0, 1024).await;
        let (_, uploaded) = upload(&router, "download-me", LAPTOP).await;
        let id = uploaded["id"].as_str().unwrap().to_owned();
        let sha256 = uploaded["sha256"].as_str().unwrap().to_owned();

        let (status, headers, bytes) =
            send_binary(router.clone(), get_backup_download(&id, LAPTOP)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, b"download-me".to_vec());
        assert_eq!(*headers.get("etag").unwrap(), format!("\"{sha256}\""));
        assert_eq!(
            *headers.get("content-type").unwrap(),
            "application/octet-stream"
        );
        assert_eq!(*headers.get("content-length").unwrap(), "11");

        // Unknown id -> 404 (unified error shape)
        let (status, _, body) =
            send_binary(router, get_backup_download("no-such-id", LAPTOP)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn delete_removes_file_and_row_then_404s() {
        let (router, state, _dir) = setup_with_backups(SPEC, 0, 1024).await;
        let (_, uploaded) = upload(&router, "to-be-deleted", LAPTOP).await;
        let id = uploaded["id"].as_str().unwrap().to_owned();

        let (status, _) = send(router.clone(), delete_backup(&id, LAPTOP)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(count_persenc(&state.backup_dir).await, 0);

        // The row is gone too: the list is empty and a second delete 404s
        let (status, page) = send(router.clone(), get_backups("/api/v1/backups", LAPTOP)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["backups"].as_array().unwrap().len(), 0);
        let (status, _) = send(router.clone(), delete_backup(&id, LAPTOP)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, _, _, _, _, deleted) = state.metrics.snapshot();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn retention_drops_oldest_versions_beyond_limit() {
        // max_versions=2: upload 3 versions and the oldest, v1 (file + row), is purged
        let (router, state, _dir) = setup_with_backups(SPEC, 2, 1024).await;
        // The same-millisecond tie-breaker is the random UUID (see the comment in
        // list_pages_desc) — both retention cleanup (deleting the ASC first row) and list
        // order must be deterministic, hence the spread-out milliseconds
        for content in ["v1", "v2", "v3"] {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let (status, _) = upload(&router, content, LAPTOP).await;
            assert_eq!(status, StatusCode::CREATED);
        }

        let (status, page) = send(router, get_backups("/api/v1/backups", LAPTOP)).await;
        assert_eq!(status, StatusCode::OK);
        let backups = page["backups"].as_array().unwrap();
        assert_eq!(backups.len(), 2);
        // v3, v2 remain (reverse order)
        assert_eq!(backups[0]["sha256"], sha256_hex("v3"));
        assert_eq!(backups[1]["sha256"], sha256_hex("v2"));
        assert_eq!(count_persenc(&state.backup_dir).await, 2);

        let (_, _, _, _, created, deleted) = state.metrics.snapshot();
        assert_eq!((created, deleted), (3, 1));
    }

    #[tokio::test]
    async fn every_backup_endpoint_requires_authentication() {
        let (router, _, _dir) = setup_with_backups(SPEC, 0, 1024).await;
        let (_, uploaded) = upload(&router, "seed", LAPTOP).await;
        let id = uploaded["id"].as_str().unwrap();

        // All four endpoints with no (or wrong-token) authentication 401; device tokens are
        // not interchangeable
        for (label, request) in [
            ("POST", post_backup("x", "wrong-token")),
            ("GET list", get_backups("/api/v1/backups", "wrong-token")),
            (
                "GET download",
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/backups/{id}"))
                    .header("authorization", "Bearer wrong-token")
                    .body(String::new())
                    .unwrap(),
            ),
            (
                "DELETE",
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/backups/{id}"))
                    .header("authorization", "Bearer wrong-token")
                    .body(String::new())
                    .unwrap(),
            ),
        ] {
            let (status, body) = send(router.clone(), request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}");
            assert_eq!(body["error"]["code"], "unauthorized", "{label}");
        }

        // phone cannot abuse laptop's token to claim a different owner: the upload is still
        // accounted to the token
        let (status, body) = upload(&router, "cross-device", PHONE).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["device_name"], "phone");
    }

    async fn count_persenc(dir: &std::path::Path) -> usize {
        count_with_extension(dir, "persenc").await
    }

    async fn count_part_files(dir: &std::path::Path) -> usize {
        count_with_extension(dir, "part").await
    }

    async fn count_with_extension(dir: &std::path::Path, ext: &str) -> usize {
        let mut entries = tokio::fs::read_dir(dir).await.unwrap();
        let mut count = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.path().extension().is_some_and(|e| e == ext) {
                count += 1;
            }
        }
        count
    }
}
