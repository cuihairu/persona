//! Local automation HTTP endpoints for Connect (CONNECT_AUTOMATION_DESIGN DR-1/DR-3/DR-4).
//!
//! A separate crate: the desktop host (DR-1 A1) and the CLI
//! `persona connect serve` (A2) host share one router / three lines of
//! defense / rate-limit implementation and the same core service layer --
//! token storage (the `connect_tokens` table in the workspace DB) is
//! inherently shared across hosts.
//! Remaining semantics are below (the module docs were migrated from desktop unchanged).
//!
//! The listener is embedded in the host process with two transports ([`ConnectTransport`]):
//! - **TCP loopback** (default): bind is hardcoded to `127.0.0.1` (port 0 = OS-assigned;
//!   there is no address configuration surface, so "reject non-loopback config" is
//!   satisfied by the hardcoding).
//! - **Unix domain socket** (`--unix-socket`, unix platforms only): socket file
//!   0600 + peer-uid verification at the accept layer (reachable != allowed; a
//!   connection with a mismatched uid is dropped immediately), no TCP port;
//!   Windows has no such transport and creation errors out.
//!
//! Off by default: not enabled = no listener created.
//!
//! Request pipeline (per request):
//! 1. Host header allowlist (`127.0.0.1`/`localhost`) -> otherwise 421 (DNS rebinding).
//!    **TCP only**: a unix socket has no name-resolution surface, DNS rebinding is
//!    unreachable, so the check is skipped (clients may send any Host, e.g. the
//!    Go ecosystem's common `http://unix/...`).
//! 2. A present `Origin` header means 403 (there is no legitimate browser
//!    cross-origin consumer of a local API; CORS is fully off)
//! 3. `/health` is unauthenticated and leaks nothing; everything else requires
//!    `Authorization: Bearer pconn_...`
//! 4. Token hash DB lookup (revoked/unknown both give an identical 401, no cache window)
//! 5. Lock gate: not unlocked -> 503 `vault_locked`, which does **not** consume
//!    quota (a lock-screen retry storm cannot lock out the token)
//! 6. Rate limit: 120 requests per token per minute (fixed window, 429 when exceeded;
//!    the limit is hardcoded)
//! 7. Data-plane scope filtering (core `connect_*`); out-of-scope / archived /
//!    nonexistent all give an identical 404
//!
//! Responses always use the `{"ok":...}` envelope (errors
//! `{"ok":false,"error":{"code","message"}}`, matching the server envelope shape) plus
//! `Cache-Control: no-store` (TOTP codes and field plaintext never reach any
//! intermediate cache). Scope decisions and token lifecycle live in core
//! (`persona_core::connect`); this module only orchestrates the HTTP surface.

use super::ConnectServerState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use persona_core::PersonaError;
use serde_json::json;

pub(super) fn ok_json<T: serde::Serialize>(data: T) -> Response {
    (
        StatusCode::OK,
        no_store_headers(),
        Json(json!({ "ok": true, "data": data })),
    )
        .into_response()
}

/// Error envelope. `message` carries only an actionable description for the
/// consumer -- internal details (DB/decryption error text) are never leaked and
/// go to the tracing log instead.
pub(super) fn err_json(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        no_store_headers(),
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
        .into_response()
}

pub(super) fn no_store_headers() -> [(&'static str, &'static str); 2] {
    [
        (header::CONTENT_TYPE.as_str(), "application/json"),
        (header::CACHE_CONTROL.as_str(), "no-store"),
    ]
}

/// Normalize framework-generated 4xx: unmatched route (404), method
/// mismatch (405), and extractor rejection (400, e.g. a malformed UUID in
/// `items/:id`) fall through to axum's default response -- no
/// `{"ok":false,"error":{...}}` envelope and no `Cache-Control: no-store`
/// (4xx is cacheable by default). This crate's own 4xx always carries no-store
/// (`err_json` is the only producer), so a "4xx missing no-store" identifies a
/// framework response: keep the status code and existing response headers
/// (the 405 `Allow` header has debugging value), add no-store, and swap in the
/// envelope body (the framework body is empty or a single line of plain text
/// and is discarded outright).
async fn normalize_framework_error(response: Response) -> Response {
    let framework = response.status().is_client_error()
        && !response.headers().contains_key(header::CACHE_CONTROL);
    if !framework {
        return response;
    }
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    // The framework body is tiny; it is consumed either way, so drop it uniformly
    let _ = axum::body::to_bytes(body, 4096).await;
    parts
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let (code, message) = match status {
        StatusCode::BAD_REQUEST => ("bad_request", "malformed request or path parameter"),
        StatusCode::NOT_FOUND => ("not_found", "route not found"),
        StatusCode::METHOD_NOT_ALLOWED => {
            ("method_not_allowed", "method not allowed for this route")
        }
        _ => (
            "error",
            status.canonical_reason().unwrap_or("request rejected"),
        ),
    };
    (
        status,
        parts.headers,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
        .into_response()
}

pub(super) fn is_vault_locked(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<PersonaError>()
            .is_some_and(|pe| matches!(pe, PersonaError::VaultLocked(_)))
    })
}

// -----------------------------------------------------------------------
// Three lines of defense + authentication + rate limiting middleware
// -----------------------------------------------------------------------

pub(super) async fn guard(
    State(state): State<ConnectServerState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Line of defense 1: Host header allowlist (loopback TCP only). Traffic reaching
    // the listener necessarily hits a local port, so the host part of Host must
    // still be a loopback name -- DNS rebinding (evil.com -> 127.0.0.1) brings a
    // malicious Host, which gets a 421. A unix socket has no name-resolution
    // surface (see the `require_loopback_host` field docs), so this is skipped.
    if state.require_loopback_host {
        let host_ok = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| {
                // Bracketed IPv6 (RFC 9110 §4.1.2) with an omitted port must not be split on
                // ':': rsplit_once would turn "[::1]" into "[::" and wrongly
                // reject ::1 from the allowlist. Only strip the port when the
                // whole value does not end in ']' (i.e. it is not a portless
                // bracketed IPv6 address).
                let authority = if h.ends_with(']') {
                    h
                } else {
                    h.rsplit_once(':').map_or(h, |(host, _)| host)
                };
                let authority = authority.trim_start_matches('[').trim_end_matches(']');
                authority == "127.0.0.1" || authority == "localhost" || authority == "::1"
            })
            .unwrap_or(false);
        if !host_ok {
            return err_json(
                StatusCode::MISDIRECTED_REQUEST,
                "bad_host",
                "host not allowed",
            );
        }
    }

    // Line of defense 2: CORS fully off. A present Origin means 403 (including
    // preflight OPTIONS -- no Access-Control-Allow-* headers are returned, so the
    // browser fails outright).
    if request.headers().contains_key(header::ORIGIN) {
        return err_json(
            StatusCode::FORBIDDEN,
            "origin_forbidden",
            "browser-originated requests are not allowed",
        );
    }

    // health is unauthenticated and leaks nothing (for liveness probes; no DB state
    // beyond the version). Normalization applies here too: the 405 from
    // POST /health should also carry the envelope (being unauthenticated does
    // not exempt routes).
    if request.uri().path() == "/api/v1/connect/health" {
        return normalize_framework_error(next.run(request).await).await;
    }

    // Line of defense 3: a token is required.
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let Some(presented) = presented else {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or malformed bearer token",
        );
    };

    // Token hash DB lookup (unknown/revoked both give the same None -> 401,
    // anti-probing).
    let auth = {
        let service_guard = state.service.lock().await;
        match service_guard.as_ref() {
            Some(service) => match service.connect_authenticate(presented).await {
                Ok(row) => row,
                Err(_) => {
                    return err_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal",
                        "authentication failed",
                    )
                }
            },
            // An uninitialized service means the DB is not ready: treat it with locked
            // semantics (503, quota not consumed)
            None => {
                return err_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "vault_locked",
                    "vault is not unlocked",
                )
            }
        }
    };
    let Some(row) = auth else {
        return err_json(StatusCode::UNAUTHORIZED, "unauthorized", "invalid token");
    };

    // The lock gate comes before rate accounting: a locked 503 does not consume
    // quota (DR-4).
    let unlocked = {
        let service_guard = state.service.lock().await;
        service_guard
            .as_ref()
            .map(|s| s.is_unlocked())
            .unwrap_or(false)
    };
    if !unlocked {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_locked",
            "vault is locked",
        );
    }

    if !state.consume_rate(row.id) {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "token rate limit exceeded (120 req/min)",
        );
    }

    // Token authenticated + vault unlocked: record this request as sensitive
    // activity -- a scoped token is re-authentication (revocable, expiring,
    // audited), so the desktop's force_lock_sensitive (sensitive timeout ->
    // lock the session and require re-authentication) must not apply to the
    // token surface, otherwise the first ciphertext read five minutes after
    // login would 500 forever with no way to re-authenticate. Opportunistic
    // refresh: on failure only debug-log; it does not change any rejection
    // semantics.
    {
        let service_guard = state.service.lock().await;
        if let Some(service) = service_guard.as_ref() {
            if let Err(e) = service.mark_authorized_request().await {
                tracing::debug!("sensitive-activity refresh skipped: {e}");
            }
        }
    }

    request.extensions_mut().insert(row);
    normalize_framework_error(next.run(request).await).await
}
