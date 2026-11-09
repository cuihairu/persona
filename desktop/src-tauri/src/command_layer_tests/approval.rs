//! Command-layer integration tests — `approval` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn approval_respond_commands_resolve_and_reject_unknown() {
    let app = mock_app();

    // Unknown ids (double click, stale modal) are rejected, never approved.
    let resp = ssh_approval_respond(
        SshApprovalRespondRequest {
            request_id: "ghost".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("ghost"));

    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "ghost".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("ghost"));

    // A registered approval resolves through the oneshot with the verdict.
    let (ssh_tx, ssh_rx) = tokio::sync::oneshot::channel();
    {
        let state = app.state::<AppState>();
        state
            .ssh_approvals
            .lock()
            .unwrap()
            .insert("req-ssh".to_string(), ssh_tx);
    }
    let resp = ssh_approval_respond(
        SshApprovalRespondRequest {
            request_id: "req-ssh".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(ssh_rx.await.unwrap(), "allow verdict delivered");

    let (pk_tx, pk_rx) = tokio::sync::oneshot::channel();
    {
        let state = app.state::<AppState>();
        state
            .passkey_approvals
            .lock()
            .unwrap()
            .insert("req-pk".to_string(), pk_tx);
    }
    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "req-pk".to_string(),
            allow: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(!pk_rx.await.unwrap(), "deny verdict delivered");

    // Second answer for the same id is "unknown" (already consumed).
    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "req-pk".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "double answer must not re-deliver");
}
