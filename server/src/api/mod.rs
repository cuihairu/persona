//! /api sub-routers: the unified error shape, request-body guards and the events endpoint.

mod accounts;
mod auth;
mod backups;
mod events;
mod pairing;
mod sync;

use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub use accounts::{
    account_srp_challenge, account_srp_register, account_srp_verify, authorize_device,
    create_account_session, generate_recovery_codes, list_account_devices, passkey_create_options,
    passkey_login_options, passkey_register, register_account, revoke_account_device,
    revoke_account_session, verify_recovery_code, AccountWebauthnState,
};
pub use auth::{
    challenge as auth_challenge, devices as auth_login_devices, register as auth_register,
    verify as auth_verify,
};
pub use backups::{delete, download, list, size_guard, upload};
pub use events::{ingest, query};
pub use pairing::{
    create_session as pairing_create_session, delete_session as pairing_delete_session,
    post_to_guest as pairing_post_to_guest, post_to_host as pairing_post_to_host,
    session_info as pairing_session_info, take_to_guest as pairing_take_to_guest,
    take_to_host as pairing_take_to_host,
};
pub use sync::{
    delete_device as sync_delete_device, get_group_keys as sync_get_group_keys,
    get_snapshot as sync_get_snapshot, list_devices as sync_list_devices, pull as sync_pull,
    push as sync_push, put_device_remark as sync_put_device_remark,
    put_group_key as sync_put_group_key, put_snapshot as sync_put_snapshot,
    register_device as sync_register_device, rotate_begin as sync_rotate_begin,
    status as sync_status,
};

/// Request body limit (on-the-wire bytes). Requests carrying Content-Length are
/// pre-checked by `payload_size_guard` for a deterministic 413 — this is the real limit
/// for compressed transport; `DefaultBodyLimit` applies to /events on the decompressed
/// plaintext (see [`MAX_DECOMPRESSED_BODY_BYTES`]).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Decompressed plaintext limit (decompression-bomb defense). Theoretical largest
/// legitimate batch: 500 entries x per-field limits ~= 9.5 MiB, so 10 MiB leaves headroom.
/// The `DefaultBodyLimit` nested inside `RequestDecompressionLayer` applies to the
/// decompressed body and also covers chunked requests (no Content-Length on that path, so
/// the wire pre-check is skipped).
pub const MAX_DECOMPRESSED_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Content-Length pre-check: over-limit requests get an immediate 413 without reading the
/// body and without entering authentication.
pub async fn payload_size_guard(req: Request, next: Next) -> Response {
    let too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_BODY_BYTES);
    if too_large {
        ApiError::payload_too_large().into_response()
    } else {
        next.run(req).await
    }
}

/// The peer IP as seen by the login-awareness ledger (PERSONA-DEVALERT-001):
/// the real connection address when the server was started with connect
/// info, else the reverse-proxy headers (`X-Forwarded-For` first entry /
/// `X-Real-IP`), else the literal `unknown`. Inserted as a request extension
/// by [`peer_ip_guard`] so handlers read it without failing when the server
/// runs without connect info (router.oneshot tests).
#[derive(Clone, Debug)]
pub struct PeerIp(pub std::sync::Arc<String>);

pub async fn peer_ip_guard(mut req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());
    req.extensions_mut().insert(PeerIp(std::sync::Arc::new(ip)));
    next.run(req).await
}

/// Unified error shape: `{"error":{"code","message","items":[...]}}`.
///
/// The inner `Box` keeps `Result<_, ApiError>` small (avoids clippy::result_large_err).
#[derive(Debug)]
pub struct ApiError(Box<ApiErrorInner>);

#[derive(Debug)]
struct ApiErrorInner {
    status: StatusCode,
    extra_header: Option<(HeaderName, HeaderValue)>,
    body: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    items: Vec<ErrorItem>,
}

/// Per-entry error pinpointing for batch validation.
#[derive(Debug, Serialize)]
pub(crate) struct ErrorItem {
    pub(crate) index: Option<usize>,
    pub(crate) field: String,
    pub(crate) issue: String,
}

impl ErrorItem {
    pub(crate) fn at(index: usize, field: &str, issue: impl Into<String>) -> Self {
        Self {
            index: Some(index),
            field: field.to_owned(),
            issue: issue.into(),
        }
    }

    pub(crate) fn batch(field: &str, issue: impl Into<String>) -> Self {
        Self {
            index: None,
            field: field.to_owned(),
            issue: issue.into(),
        }
    }
}

impl ApiError {
    /// 422: batch validation failed (with per-entry items).
    pub fn validation(message: impl Into<String>, items: Vec<ErrorItem>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation",
            message,
            items,
        )
    }

    /// 400/415: request-layer errors such as JSON deserialization (reuses axum
    /// rejection's status code).
    pub fn rejection(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(status, "bad_request", message, Vec::new())
    }

    /// 401: missing or wrong Bearer token (with WWW-Authenticate).
    pub fn unauthorized() -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
            Vec::new(),
        );
        error.0.extra_header = Some((header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")));
        error
    }

    /// 503: PERSONA_SERVER_TOKEN not configured, fail-closed.
    pub fn disabled() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_disabled",
            "API is disabled: PERSONA_SERVER_TOKEN is not configured",
            Vec::new(),
        )
    }

    /// 413: request body over limit (events' wire limit is [`MAX_BODY_BYTES`]; the backup
    /// limit is built by backups::size_guard from AppState.max_backup_bytes).
    pub fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            Vec::new(),
        )
    }

    /// 413: request body over limit (custom limit, used by the backup path).
    pub fn payload_too_large_with(limit_bytes: usize) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body exceeds {limit_bytes} bytes"),
            Vec::new(),
        )
    }

    /// 409: the resource already exists (e.g. a duplicate sync device name — the public
    /// key must not be silently replaced).
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message, Vec::new())
    }

    /// 404: not in the route table (the fallback).
    pub(crate) fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such route",
            Vec::new(),
        )
    }

    /// 404: the resource does not exist (the route is there but there is nothing to
    /// return yet — e.g. a library snapshot that has never been uploaded). Same status as
    /// the fallback's not_found but a different code, so clients can tell them apart.
    pub fn absent(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "absent", message, Vec::new())
    }

    /// 500: internal error; details go to the logs only and are never exposed.
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "internal server error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
            Vec::new(),
        )
    }

    fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        items: Vec<ErrorItem>,
    ) -> Self {
        Self(Box::new(ApiErrorInner {
            status,
            extra_header: None,
            body: ErrorBody {
                error: ErrorDetail {
                    code,
                    message: message.into(),
                    items,
                },
            },
        }))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let inner = self.0;
        let mut response = (inner.status, axum::Json(inner.body)).into_response();
        if let Some((name, value)) = inner.extra_header {
            response.headers_mut().insert(name, value);
        }
        response
    }
}

// ---- Stable cursor codec (shared by events/backups/oplog pagination) ----
// base64url("v1:{millisecond timestamp}:{row id}"), unpadded. The codec itself lives in
// persona_core::sync::cursor — the core engine needs to decode a local cursor back into
// a seq to get "this machine's synced water level" (sync-group-mode §II.5.5), so the
// single source of truth for the format lives in core; here we keep only the old
// ApiError-wrapped signature so the three call sites need no change.

pub(crate) fn encode_cursor(ms: i64, id: &str) -> String {
    persona_core::sync::cursor::encode_cursor(ms, id)
}

pub(crate) fn decode_cursor(raw: &str) -> Result<(i64, String), ApiError> {
    persona_core::sync::cursor::decode_cursor(raw).map_err(|_| {
        ApiError::validation(
            "invalid cursor",
            vec![ErrorItem::batch("cursor", "malformed cursor token")],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_cursor, encode_cursor};

    #[test]
    fn cursor_roundtrip() {
        let encoded = encode_cursor(1_758_182_400_123, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
        let (ms, id) = decode_cursor(&encoded).unwrap();
        assert_eq!(ms, 1_758_182_400_123);
        assert_eq!(id, "0e2c5a6b-1c2d-3e4f-5a6b-7c8d9e0f1a2b");
    }

    #[test]
    fn cursor_rejects_garbage() {
        assert!(decode_cursor("not-a-cursor").is_err());
        assert!(decode_cursor("").is_err());
        // base64url-decodable but not a v1 prefix / missing id / missing milliseconds
        assert!(decode_cursor("aXY6").is_err());
        assert!(decode_cursor("djE6MTIz").is_err()); // "v1:123" has no id segment
    }
}
