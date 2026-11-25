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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::middleware::{self};
use axum::routing::{get, post};
use axum::Router;
use persona_core::PersonaService;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

/// Per-token per-minute request cap (DR-3: fixed window; the limit is hardcoded
/// and not configurable -- a bigger configuration surface is a bigger misuse
/// surface).
pub const RATE_LIMIT_PER_MINUTE: u32 = 120;

const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Rate-table sweep threshold: when this many slots are present, sweep away
/// entries whose windows have expired (leftovers after token deletion/rotation,
/// capping the slow-leak upper bound, audit batch 2 #10). Triggered once per
/// this many rate accountings, so the amortized O(n) cost stays constant.
const RATE_SWEEP_THRESHOLD: usize = 16;

/// Alias for `Arc<tokio::sync::Mutex<Option<PersonaService>>>` (the same type as
/// AppState's `service` field, cloned in by the command layer).
pub type ArcTokService = Arc<TokioMutex<Option<PersonaService>>>;

/// Transport layer for the Connect listener.
///
/// - [`ConnectTransport::Tcp`]: loopback TCP (default; `port` 0 = OS assigns a
///   real port).
/// - [`ConnectTransport::Unix`]: unix domain socket (creation succeeds on unix
///   platforms only; on Windows [`start_connect_server_with_transport`] errors
///   outright -- tokio has no Windows UnixListener, and named pipes are a
///   follow-up topic, not an equivalent of this transport).
#[derive(Clone, Debug)]
pub enum ConnectTransport {
    /// loopback TCP: `127.0.0.1:{port}` (port 0 = OS-assigned).
    Tcp { port: u16 },
    /// unix domain socket: 0600 file permissions + owner uid verification at the
    /// accept layer.
    Unix { path: PathBuf },
}

mod endpoints;
mod guard;
mod unix;

#[cfg(test)]
use axum::http::header;
#[cfg(test)]
use axum::response::Response;
use endpoints::{health, identities, item, item_totp, items};
#[cfg(test)]
use endpoints::{internal_or_locked, item_meta_json, item_type_slug, locked_response};
use guard::guard;
#[cfg(test)]
use guard::{err_json, is_vault_locked, ok_json};
#[cfg(test)]
use persona_core::PersonaError;
#[cfg(test)]
use serde_json::json;
#[cfg(unix)]
use unix::UidCheckedListener;
#[cfg(all(test, unix))]
use unix::{peer_allowed, Accept};

#[derive(Clone)]
pub struct ConnectServerState {
    /// The same service slot shared with AppState (token verification + unlock
    /// gate).
    pub service: ArcTokService,
    /// Fixed-window counters per token: token id -> (window start, counted
    /// request count). Purely in-memory and cleared on process restart -- this
    /// is host protection (a runaway poller must not drag down the host), not
    /// auditing.
    rates: Arc<Mutex<HashMap<Uuid, (Instant, u32)>>>,
    /// Whether to enforce the Host header allowlist
    /// (`127.0.0.1`/`localhost`/`::1`).
    ///
    /// This line of defense targets DNS rebinding: a domain resolving to the
    /// local IP plus a malicious Host hitting the loopback port. A unix socket has
    /// no name-resolution surface (connections target a file path, so browser /
    /// DNS resolution is unreachable), so the allowlist has nothing to protect
    /// against and only costs wrongly rejected legitimate clients (the Go
    /// ecosystem routinely sends arbitrary values like `Host: unix`); hence the
    /// unix transport skips it. The `Origin` / token / rate-limit lines of
    /// defense apply unchanged on both transports.
    require_loopback_host: bool,
}

impl ConnectServerState {
    pub fn new(service: ArcTokService) -> Self {
        Self {
            service,
            rates: Arc::new(Mutex::new(HashMap::new())),
            require_loopback_host: true,
        }
    }

    /// State for the unix transport: skip the Host allowlist (rationale in the field
    /// docs).
    #[cfg(unix)]
    fn new_unix(service: ArcTokService) -> Self {
        Self {
            require_loopback_host: false,
            ..Self::new(service)
        }
    }

    /// Fixed-window accounting: reset to 1 when the window has expired; return
    /// false (429) when it is unexpired and already full.
    fn consume_rate(&self, token_id: Uuid) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // Low-frequency sweep: at the threshold, clear dead slots whose windows have
        // expired, capping the slow-leak upper bound. Below the threshold (normal
        // low-cardinality deployments) nothing triggers, avoiding a per-request
        // O(n) scan of the whole table.
        if rates.len() >= RATE_SWEEP_THRESHOLD {
            rates.retain(|_, (window_start, _)| now.duration_since(*window_start) < RATE_WINDOW);
        }
        let slot = rates.entry(token_id).or_insert((now, 0));
        if now.duration_since(slot.0) >= RATE_WINDOW {
            *slot = (now, 1);
            return true;
        }
        if slot.1 >= RATE_LIMIT_PER_MINUTE {
            return false;
        }
        slot.1 += 1;
        true
    }
}

/// Assemble routes + the three-lines-of-defense / authentication / rate-limit
/// middleware. Shared by tests and production (production binds via
/// [`start_connect_server`]; tests drive it directly via `Router::oneshot`
/// without a network).
pub fn build_router(state: ConnectServerState) -> Router {
    Router::new()
        .route("/api/v1/connect/health", get(health))
        .route("/api/v1/connect/identities", get(identities))
        .route("/api/v1/connect/items", get(items))
        .route("/api/v1/connect/items/{id}", get(item))
        .route("/api/v1/connect/items/{id}/totp", post(item_totp))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Start the Connect listener (loopback TCP, compatibility entry point).
///
/// Equivalent to [`start_connect_server_with_transport`] + [`ConnectTransport::Tcp`].
/// Returns a handle (actual port + shutdown channel); bind failure (e.g. port in
/// use) propagates to the caller (the settings page reports it explicitly, no
/// silent retry).
pub async fn start_connect_server(
    service: ArcTokService,
    port: u16,
) -> anyhow::Result<ConnectServerHandle> {
    start_connect_server_with_transport(service, ConnectTransport::Tcp { port }).await
}

/// Start the Connect listener on the given transport; returns a handle (TCP:
/// actual port; unix: socket path) + shutdown channel. Bind failure propagates,
/// no silent retry.
///
/// - [`ConnectTransport::Tcp`]: `127.0.0.1:{port}` (0 = OS-assigned).
/// - [`ConnectTransport::Unix`]: 0600 socket file + owner uid verification at the
///   accept layer (stale leftovers are taken over; a live listener always errors
///   instead of hijacking, same policy as the ssh-agent transport). Non-unix
///   platforms (Windows) error outright -- see the [`ConnectTransport`] docs.
pub async fn start_connect_server_with_transport(
    service: ArcTokService,
    transport: ConnectTransport,
) -> anyhow::Result<ConnectServerHandle> {
    match transport {
        ConnectTransport::Tcp { port } => {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let actual_port = listener.local_addr()?.port();
            let router = build_router(ConnectServerState::new(service));
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let closed = tokio::spawn(async move {
                let _ = axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
            Ok(ConnectServerHandle {
                port: actual_port,
                socket_path: None,
                shutdown: shutdown_tx,
                closed,
            })
        }
        ConnectTransport::Unix { path } => {
            #[cfg(unix)]
            {
                start_unix(service, path).await
            }
            #[cfg(not(unix))]
            {
                let _ = (service, path);
                // On Windows tokio has no UnixListener (AF_UNIX is not portable within this
                // crate's supported surface); named pipes are a different transport
                // form and are not faked here. Error out explicitly so the caller
                // (CLI --unix) gets actionable guidance on alternatives.
                anyhow::bail!(
                    "unix socket transport is not supported on this platform; \
                     use TCP loopback instead (`persona connect serve` without --unix)"
                )
            }
        }
    }
}

/// Unix transport implementation (compiled on unix platforms only).
///
/// Three layers of local protection: (1) socket file 0600 (tightened immediately
/// after bind, guarding against umask leftover group/other bits); (2) owner uid
/// verification at the accept layer ([`UidCheckedListener`] -- file permissions
/// are the kernel layer, uid verification covers scenarios where permission bits
/// were altered or misbehaving, fail-closed); (3) HTTP-layer token
/// authentication (same on both transports). `Origin`/rate limit apply
/// unchanged; the Host allowlist is skipped (see
/// [`ConnectServerState::require_loopback_host`]).
#[cfg(unix)]
async fn start_unix(service: ArcTokService, path: PathBuf) -> anyhow::Result<ConnectServerHandle> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Bind first, do not pre-delete (TOCTOU: the path could be swapped out between
    // exists->remove->bind). Only take over once the old path is confirmed stale
    // (not a socket, or nobody listening); a live listener always errors rather
    // than silently hijacking the path (same policy as ssh-agent transport::bind,
    // with the implementation consolidated in
    // persona_core::socket::is_stale_socket).
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            // Use symlink_metadata to detect "the path name is taken": with a broken
            // symlink present, Path::exists() follows the link, returns false, and
            // would miss leftover files that can be taken over.
            if path.symlink_metadata().is_err() {
                anyhow::bail!("failed to bind connect socket {}: {err}", path.display());
            }
            if !persona_core::socket::is_stale_socket(&path) {
                anyhow::bail!(
                    "connect socket {} already bound by a live process: {err}",
                    path.display()
                );
            }
            std::fs::remove_file(&path)?;
            tokio::net::UnixListener::bind(&path)?
        }
    };

    // 0600: permissions of the socket file created by bind = 0777 & ~umask (a
    // common umask of 022 -> 0755, visible to group/other). Tighten immediately to
    // owner-only connectability (a unix socket connection needs write permission,
    // so 0600 means same-user exclusivity -- kernel layer).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    // Owner = the current process user that just bound successfully (a fresh
    // file, or recreated after taking over a stale path, see above).
    let owner_uid = std::fs::metadata(&path)?.uid();

    let listener = UidCheckedListener {
        inner: listener,
        owner_uid,
    };
    let router = build_router(ConnectServerState::new_unix(service));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let cleanup = path.clone();
    let closed = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        // Clean shutdown: remove the socket file (leftovers from a crash are handled as
        // stale paths by the next start).
        let _ = std::fs::remove_file(&cleanup);
    });
    Ok(ConnectServerHandle {
        port: 0,
        socket_path: Some(path),
        shutdown: shutdown_tx,
        closed,
    })
}

/// Handle for a running listener.
#[derive(Debug)]
pub struct ConnectServerHandle {
    /// The port the listener actually bound (TCP transport; a configured port of
    /// 0 is replaced by the OS-assigned value).
    /// **Always 0 for the unix transport** (there is no TCP port; see
    /// [`Self::socket_path`] for the endpoint).
    pub port: u16,
    /// Socket path for the unix transport (`None` for TCP).
    ///
    /// After a clean shutdown the socket file has been removed; leftovers from a
    /// process crash are handled by the next start as a stale-path takeover
    /// (`persona_core::socket::is_stale_socket`).
    pub socket_path: Option<PathBuf>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    /// Join handle for the listener task (both the end of the serve loop and the
    /// socket file cleanup happen inside it).
    closed: tokio::task::JoinHandle<()>,
}

impl ConnectServerHandle {
    /// Trigger graceful shutdown (sends synchronously; the listener task does its
    /// own cleanup).
    ///
    /// Fire-and-forget: the caller **does not wait for cleanup to finish**. If
    /// the process exits right after, the runtime drops the unfinished cleanup
    /// task (on unix a stale socket is left behind and self-heals via the next
    /// start's stale-path takeover) -- for process exit paths use
    /// [`Self::stop_and_wait`].
    pub fn stop(self) {
        let _ = self.shutdown.send(());
    }

    /// Trigger graceful shutdown and wait for the listener task to finish (including
    /// socket file removal).
    ///
    /// The correct cleanup before process exit: `closed` completing guarantees the
    /// port/socket has been released, leaving no race window (the fire-and-forget
    /// `stop` does not guarantee cleanup when the process exits right after).
    pub async fn stop_and_wait(self) {
        let _ = self.shutdown.send(());
        let _ = self.closed.await;
    }
}

// -----------------------------------------------------------------------
// Envelope and error mapping
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests;
