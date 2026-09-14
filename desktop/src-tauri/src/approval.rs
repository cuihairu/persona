//! Desktop SSH signature-approval bridge.
//!
//! Implements the agent crate's [`ApprovalHandler`] seam for the GUI:
//! every confirmation request is emitted to the frontend as
//! `persona://ssh-approval`, and the answer arrives via the
//! `ssh_approval_respond` command, which completes a oneshot channel
//! looked up in a map shared with [`crate::types::AppState`].
//!
//! Unanswered requests time out to "deny" so a backgrounded/abandoned
//! window can never hang the agent connection.

use crate::types::SshApprovalRequest;
use async_trait::async_trait;
use persona_ssh_agent::ApprovalHandler;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{Emitter, Runtime};

/// Shared pending-approval registry (written by [`DesktopApprovalHandler`],
/// drained by the `ssh_approval_respond` command).
pub type PendingApprovals = Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>;

/// Default how-long-a pending approval may sit unanswered before auto-denial.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Emit-and-wait approval handler for the embedded SSH agent.
pub struct DesktopApprovalHandler<R: Runtime> {
    app: tauri::AppHandle<R>,
    pending: PendingApprovals,
    next_id: AtomicU64,
    timeout: Duration,
}

impl<R: Runtime> DesktopApprovalHandler<R> {
    pub fn new(app: tauri::AppHandle<R>, pending: PendingApprovals) -> Self {
        Self {
            app,
            pending,
            next_id: AtomicU64::new(1),
            timeout: APPROVAL_TIMEOUT,
        }
    }

    /// Override the answer deadline (unit tests use a short one).
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn emit_request(
        &self,
        request_id: &str,
        request: &persona_ssh_agent::ApprovalRequest,
    ) -> anyhow::Result<()> {
        let payload = SshApprovalRequest {
            request_id: request_id.to_string(),
            key_id: request.key_id.clone(),
            fingerprint: request.fingerprint.clone(),
            operation: request.operation.clone(),
            peer: request.peer.clone(),
            reason: request.reason.clone(),
        };
        self.app
            .emit("persona://ssh-approval", &payload)
            .map_err(|e| anyhow::anyhow!("failed to emit approval event: {e}"))
    }
}

#[async_trait]
impl<R: Runtime> ApprovalHandler for DesktopApprovalHandler<R> {
    async fn confirm(&self, request: &persona_ssh_agent::ApprovalRequest) -> anyhow::Result<bool> {
        let request_id = format!("ssh-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut map = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("approval map poisoned"))?;
            map.insert(request_id.clone(), tx);
        }
        if let Err(e) = self.emit_request(&request_id, request) {
            if let Ok(mut map) = self.pending.lock() {
                map.remove(&request_id);
            }
            return Err(e);
        }

        // Abandoned UI / app exit must resolve instead of hanging the agent.
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(allow)) => Ok(allow),
            Ok(Err(_dropped)) => Ok(false),
            Err(_elapsed) => {
                if let Ok(mut map) = self.pending.lock() {
                    map.remove(&request_id);
                }
                tracing::warn!("SSH approval {request_id} timed out; denying");
                Ok(false)
            }
        }
    }
}

/// Resolve a pending approval by id. Returns `Ok(false)` (deny) when the
/// request is unknown or already answered (timeout cleanup, duplicate click).
pub fn resolve_from_map(pending: &PendingApprovals, request_id: &str, allow: bool) -> bool {
    let sender = pending
        .lock()
        .ok()
        .and_then(|mut map| map.remove(request_id));
    match sender {
        Some(tx) => tx.send(allow).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use persona_ssh_agent::ApprovalRequest;
    use std::sync::atomic::Ordering;

    fn sample_request() -> ApprovalRequest {
        ApprovalRequest {
            key_id: "key-1".to_string(),
            fingerprint: "SHA256:abcd".to_string(),
            operation: "sign".to_string(),
            peer: Some("example.com".to_string()),
            reason: "policy".to_string(),
            prompt: "allow?".to_string(),
        }
    }

    fn mock_handler(
        pending: PendingApprovals,
        timeout: Duration,
    ) -> DesktopApprovalHandler<tauri::test::MockRuntime> {
        let app = tauri::test::mock_app();
        DesktopApprovalHandler::new(app.handle().clone(), pending).with_timeout(timeout)
    }

    #[tokio::test]
    async fn confirm_denies_after_timeout_and_cleans_map() {
        let pending: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
        let handler = mock_handler(pending.clone(), Duration::from_millis(50));

        let allowed = handler.confirm(&sample_request()).await.unwrap();

        assert!(!allowed, "timeout must deny");
        assert!(
            pending.lock().unwrap().is_empty(),
            "timed-out request must be removed from the map"
        );
    }

    #[tokio::test]
    async fn confirm_returns_frontend_answer() {
        let pending: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
        let handler = mock_handler(pending.clone(), Duration::from_secs(5));

        // Answer the request from "the frontend" once it appears in the map.
        let waiter = {
            let pending = pending.clone();
            tokio::spawn(async move {
                let id = loop {
                    let ids: Vec<String> = pending.lock().unwrap().keys().cloned().collect();
                    if let Some(id) = ids.into_iter().next() {
                        break id;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                };
                assert!(resolve_from_map(&pending, &id, true));
            })
        };

        let allowed = handler.confirm(&sample_request()).await.unwrap();
        waiter.await.unwrap();
        assert!(allowed, "frontend allow must reach the agent");
    }

    #[tokio::test]
    async fn request_ids_increase_monotonically() {
        let pending: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
        let handler = mock_handler(pending.clone(), Duration::from_secs(5));
        let first = format!("ssh-{}", handler.next_id.fetch_add(1, Ordering::SeqCst));
        let second = format!("ssh-{}", handler.next_id.fetch_add(1, Ordering::SeqCst));
        assert_ne!(first, second);
    }

    #[test]
    fn resolve_unknown_request_denies() {
        let pending: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
        assert!(!resolve_from_map(&pending, "ssh-404", true));
    }

    #[test]
    fn resolve_duplicate_answer_denies_second_time() {
        let pending: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        pending.lock().unwrap().insert("ssh-7".to_string(), tx);
        assert!(resolve_from_map(&pending, "ssh-7", true));
        assert!(
            !resolve_from_map(&pending, "ssh-7", true),
            "map entry removed"
        );
    }
}
