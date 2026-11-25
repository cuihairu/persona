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

use super::guard::{err_json, is_vault_locked, ok_json};
use super::ConnectServerState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use persona_core::connect::{ConnectItemType, ConnectTokenRow};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

// -----------------------------------------------------------------------
// Endpoints
// -----------------------------------------------------------------------

/// GET /api/v1/connect/health: leaks no DB information, unauthenticated.
pub(super) async fn health() -> Response {
    ok_json(json!({
        "service": "persona-connect",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(serde::Serialize)]
struct ConnectIdentityView {
    id: Uuid,
    name: String,
}

/// Unified mapping for data-plane errors: locked -> 503 vault_locked; any other
/// internal error -> 500 (details are not leaked, only logged via tracing).
pub(super) fn internal_or_locked(e: &anyhow::Error) -> Response {
    if is_vault_locked(e) {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "vault_locked",
            "vault is locked",
        );
    }
    tracing::warn!(error = %e, "connect endpoint internal error");
    err_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

pub(super) fn locked_response() -> Response {
    err_json(
        StatusCode::SERVICE_UNAVAILABLE,
        "vault_locked",
        "vault is locked",
    )
}

/// GET /api/v1/connect/identities: identities within scope (id + name).
pub(super) async fn identities(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_list_identities(&row).await {
        Ok(list) => ok_json(
            list.into_iter()
                .map(|i| ConnectIdentityView {
                    id: i.id,
                    name: i.name,
                })
                .collect::<Vec<_>>(),
        ),
        Err(e) => internal_or_locked(&e),
    }
}

#[derive(Deserialize)]
pub(super) struct ItemsQuery {
    identity: Option<Uuid>,
    #[serde(rename = "type")]
    item_type: Option<ConnectItemType>,
    title: Option<String>,
}

/// GET /api/v1/connect/items: metadata for items within scope.
pub(super) async fn items(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Query(query): Query<ItemsQuery>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service
        .connect_list_items(&row, query.identity, query.item_type, query.title)
        .await
    {
        Ok(list) => ok_json(list.iter().map(item_meta_json).collect::<Vec<_>>()),
        Err(e) => internal_or_locked(&e),
    }
}

/// Item types consistently use the scoped enum vocabulary (snake_case, e.g.
/// `password`), matching `?type=`/`item_types` -- consumers learn exactly one
/// vocabulary. Scope filtering already blocks unauthorized types; None falls back
/// to null here (should not happen).
pub(super) fn item_type_slug(c: &persona_core::Credential) -> serde_json::Value {
    ConnectItemType::from_credential_type(&c.credential_type)
        .map(|t| serde_json::to_value(t).unwrap_or_default())
        .unwrap_or(serde_json::Value::Null)
}

pub(super) fn item_meta_json(c: &persona_core::Credential) -> serde_json::Value {
    json!({
        "id": c.id,
        "title": c.name,
        "type": item_type_slug(c),
        "urls": c.url.as_deref().into_iter().collect::<Vec<_>>(),
        "updated_at": c.updated_at.to_rfc3339(),
    })
}

/// GET /api/v1/connect/items/:id: full fields for a single item (after decryption).
/// Out-of-scope / archived / nonexistent all give an identical 404 (anti-probing).
pub(super) async fn item(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_get_item_data(&row, &id).await {
        Ok(Some((cred, data))) => ok_json(json!({
            "id": cred.id,
            "title": cred.name,
            "type": item_type_slug(&cred),
            "urls": cred.url.as_deref().into_iter().collect::<Vec<_>>(),
            "username": cred.username,
            "updated_at": cred.updated_at.to_rfc3339(),
            "data": data,
        })),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "not_found", "item not found"),
        Err(e) => internal_or_locked(&e),
    }
}

/// POST /api/v1/connect/items/:id/totp: current TOTP code + remaining seconds.
pub(super) async fn item_totp(
    State(state): State<ConnectServerState>,
    axum::Extension(row): axum::Extension<ConnectTokenRow>,
    Path(id): Path<Uuid>,
) -> Response {
    let service_guard = state.service.lock().await;
    let Some(service) = service_guard.as_ref() else {
        return locked_response();
    };
    match service.connect_totp(&row, &id).await {
        Ok(Some(code)) => ok_json(json!({
            "code": code.code,
            "remaining_seconds": code.remaining_seconds,
        })),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "not_found", "item not found"),
        Err(e) => internal_or_locked(&e),
    }
}

// -----------------------------------------------------------------------
// Tests: DR-4 all-reject paths + data plane + rate limiting (driven directly with
// Router::oneshot, no network)
// -----------------------------------------------------------------------
