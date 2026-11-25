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

#[cfg(unix)]
use std::time::Duration;

/// Unix listener wrapper with owner uid verification at the accept layer (unix
/// platforms only).
///
/// For every new connection, `SO_PEERCRED` is fetched first: only a uid matching
/// the socket file's owner is handed to axum; a mismatch (other users, unusual
/// credentials) drops the connection and keeps accepting -- fail-closed, without
/// consuming any HTTP-layer state. The check lives at accept rather than in
/// middleware: rejected connections never enter the HTTP parsing surface.
#[cfg(unix)]
pub(super) struct UidCheckedListener<L = tokio::net::UnixListener> {
    pub(super) inner: L,
    /// Owner uid of the socket file (= this process's uid, read at bind time).
    pub(super) owner_uid: u32,
}

/// Inner accept abstraction for [`UidCheckedListener`] (testability seam, unix
/// platforms only).
///
/// Always yields a tokio `UnixStream`/`unix::SocketAddr` (peer verification needs
/// `peer_cred`), with errors surfaced as `io::Result` -- the real implementation
/// is tokio `UnixListener`'s inherent method, while test implementations can
/// inject an error sequence.
#[cfg(unix)]
#[cfg(unix)]
pub(super) trait Accept: Send + 'static {
    fn accept(
        &mut self,
    ) -> impl std::future::Future<
        Output = std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>,
    > + Send;

    fn local_addr(&self) -> std::io::Result<tokio::net::unix::SocketAddr>;
}

#[cfg(unix)]
#[cfg(unix)]
impl Accept for tokio::net::UnixListener {
    async fn accept(
        &mut self,
    ) -> std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
        tokio::net::UnixListener::accept(self).await
    }

    fn local_addr(&self) -> std::io::Result<tokio::net::unix::SocketAddr> {
        tokio::net::UnixListener::local_addr(self)
    }
}

/// Pure peer uid decision (unix platforms only): does the peer uid match the
/// socket owner?
///
/// A free function rather than an inherent method -- once [`UidCheckedListener`]
/// was generalized, tests no longer need to name an instance type just to run a
/// pure comparison.
#[cfg(unix)]
#[cfg(unix)]
pub(super) fn peer_allowed(peer_uid: u32, owner_uid: u32) -> bool {
    peer_uid == owner_uid
}

#[cfg(unix)]
#[cfg(unix)]
impl<L> UidCheckedListener<L>
where
    L: Accept,
{
    /// Peer credential decision: `Ok` with uid == owner -> allowed; mismatch /
    /// credentials unavailable -> reject (each logs a trace and returns false;
    /// the connection is dropped).
    ///
    /// Splitting this into a pure function is the testability seam: the `Err`
    /// branch cannot be triggered from a real connection on Linux (SO_PEERCRED
    /// always succeeds on a connected socket), so unit tests feed `io::Error`
    /// directly; the mismatch branch is covered end-to-end by
    /// `unix_listener_drops_connections_whose_uid_is_not_the_owner`.
    pub(super) fn peer_gate(
        cred: std::io::Result<tokio::net::unix::UCred>,
        owner_uid: u32,
    ) -> bool {
        match cred {
            Ok(cred) if peer_allowed(cred.uid(), owner_uid) => true,
            Ok(cred) => {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    owner_uid,
                    peer_pid = ?cred.pid(),
                    "dropped unix socket connection: peer uid is not the socket owner"
                );
                false
            }
            Err(err) => {
                // Credentials unavailable is treated as rejection (fail-closed). The 0600
                // file permission is already the primary kernel-level defense;
                // this is the backstop layer.
                tracing::warn!("dropped unix socket connection: peer cred unavailable: {err}");
                false
            }
        }
    }
}

#[cfg(unix)]
#[cfg(unix)]
impl<L> axum::serve::Listener for UidCheckedListener<L>
where
    L: Accept,
{
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    if Self::peer_gate(stream.peer_cred(), self.owner_uid) {
                        return (stream, addr);
                    }
                    // The dropped stream makes the peer read EOF/RST; go on accepting the next
                    // connection
                }
                Err(err) => {
                    // Accept error semantics mirror axum's serve/listener.rs (connection-type
                    // errors retry immediately; everything else logs + a 1s backoff,
                    // preventing EMFILE-style spinning).
                    let connection_error = matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                    );
                    if connection_error {
                        continue;
                    }
                    tracing::error!("accept error: {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
