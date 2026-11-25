//! Signature approval abstraction.
//!
//! The agent itself must stay UI-free: approval can come from a terminal
//! (CLI daemon), a desktop modal window, or a mobile biometric sheet.
//! [`ApprovalHandler`] is the seam between the signing policy and whatever
//! user interaction the host application provides.

use anyhow::Result;
use async_trait::async_trait;

/// A pending signature-approval request.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Credential UUID backing the key
    pub key_id: String,
    /// Short public-key fingerprint for display (e.g. "SHA256:abcd1234…")
    pub fingerprint: String,
    /// Operation being approved (currently always "sign")
    pub operation: String,
    /// Target host, when known
    pub peer: Option<String>,
    /// Why confirmation was triggered (policy / unknown host / …)
    pub reason: String,
    /// Complete prompt text (used by terminal handlers)
    pub prompt: String,
}

/// Decide whether an agent operation may proceed.
///
/// Implementations must eventually return — a UI that abandons the request
/// should resolve to `Ok(false)` rather than hang the agent connection.
#[async_trait]
pub trait ApprovalHandler: Send + Sync {
    async fn confirm(&self, request: &ApprovalRequest) -> Result<bool>;
}

/// Default terminal implementation: blocking `/dev/tty` (stdin/stdout
/// fallback) prompt. Used by the CLI daemon unchanged.
pub struct TtyApprovalHandler;

#[async_trait]
impl ApprovalHandler for TtyApprovalHandler {
    async fn confirm(&self, request: &ApprovalRequest) -> Result<bool> {
        // prompt_confirm_blocking is blocking I/O on a tty; keep it off the
        // async reactor's core threads.
        let prompt = request.prompt.clone();
        tokio::task::spawn_blocking(move || crate::daemon::prompt_confirm_blocking(&prompt))
            .await
            .map_err(|e| anyhow::anyhow!("approval task panicked: {}", e))?
    }
}

/// Handler that auto-denies (used when no interactive UI exists).
pub struct DenyAllApprovalHandler;

#[async_trait]
impl ApprovalHandler for DenyAllApprovalHandler {
    async fn confirm(&self, request: &ApprovalRequest) -> Result<bool> {
        tracing::warn!(
            "signature request auto-denied (no approval UI): {}",
            request.reason
        );
        Ok(false)
    }
}

/// Build the display fingerprint for a key's public blob.
pub fn fingerprint_for_blob(public_blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_blob);
    let hex: String = digest
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("SHA256:{}", hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deny_all_handler_denies() {
        let req = ApprovalRequest {
            key_id: "k".to_string(),
            fingerprint: "SHA256:x".to_string(),
            operation: "sign".to_string(),
            peer: Some("example.com".to_string()),
            reason: "policy".to_string(),
            prompt: "allow?".to_string(),
        };
        assert!(!DenyAllApprovalHandler.confirm(&req).await.unwrap());
    }

    #[test]
    fn fingerprint_is_stable_and_prefixed() {
        let fp = fingerprint_for_blob(b"blob");
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp, fingerprint_for_blob(b"blob"));
        assert_ne!(fp, fingerprint_for_blob(b"other"));
    }

    /// The full body of `TtyApprovalHandler::confirm` (spawn_blocking
    /// orchestration + join error mapping + decision pass-through) on a
    /// deterministic path in an environment without a tty: /dev/tty cannot
    /// be opened -> stdin fallback -> EOF -> empty line -> deny.
    #[cfg(unix)]
    #[tokio::test]
    async fn tty_handler_without_tty_surfaces_stdin_eof_as_deny() {
        // On a dev machine with a controlling terminal:
        // prompt_confirm_blocking prefers opening /dev/tty and blocks
        // waiting for keyboard input -- skip, to avoid hanging an
        // interactive session (see the daemon.rs module docs: that path
        // needs a real terminal). The CI coverage container and headless
        // environments have no /dev/tty, so the test runs there in full.
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
        {
            return;
        }
        // stdin is redirected to /dev/null no matter how the tests are
        // launched: read_line hits a deterministic EOF ->
        // stdin_confirm_from_line("") -> false. No other test in the suite
        // reads stdin, so the process-wide dup2 is harmless.
        use std::os::unix::io::AsRawFd;
        let devnull = std::fs::File::open("/dev/null").expect("open /dev/null");
        unsafe { libc::dup2(devnull.as_raw_fd(), 0) };

        let req = ApprovalRequest {
            key_id: "k".to_string(),
            fingerprint: "SHA256:x".to_string(),
            operation: "sign".to_string(),
            peer: None,
            reason: "policy".to_string(),
            prompt: "approve? [y/N]".to_string(),
        };
        let decision = TtyApprovalHandler
            .confirm(&req)
            .await
            .expect("spawn_blocking join must not fail");
        assert!(!decision, "stdin EOF must deny");
    }
}
