use super::*;

/// The `--approve-code` entry point resolves paths from the args and
/// reports an unknown code without ever touching stdio.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_execute_approve_code_reports_missing_pairing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("bridge-state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let err = execute(BridgeArgs {
        db_path: Some(dir.path().join("identities.db")),
        approve_code: Some("000-000".to_string()),
        state_dir: Some(state_dir),
        browser_origin: Vec::new(),
    })
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "pairing_not_found_or_expired");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_pairing_lifecycle() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    // status before any pairing: no auth needed.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(resp.ok, "status must succeed: {:?}", resp.error);

    // hello without client_instance_id while pairing is required.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("hello", serde_json::json!({ "extension_id": "ext-a" })),
    )
    .await
    .unwrap();
    assert!(resp.ok);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["pairing_required"], true);
    assert!(payload["paired"] == false);

    // pairing_request creates a pending code.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "pairing_request",
            serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1" }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "pairing_request must succeed: {:?}", resp.error);
    let code = resp.payload.unwrap()["code"]
        .as_str()
        .expect("pairing code present")
        .to_string();

    // finalize before approval fails.
    let err = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1", "code": code }),
            ),
        )
        .await
        .expect_err("finalize before approval must fail");
    assert!(
        err.to_string().contains("pairing_not_approved"),
        "got: {err}"
    );

    // Approve via the CLI-side command, then finalize.
    approve_pairing(&state_dir, &code).expect("approve pairing");
    let resp = handle_request(
            &db_path,
            &state_dir,
            request(
                "pairing_finalize",
                serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1", "code": code }),
            ),
        )
        .await
        .unwrap();
    assert!(resp.ok, "finalize must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert!(payload["pairing_key_b64"].is_string());
    assert!(payload["session_id"].is_string());

    // hello now reports the session (paired).
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "hello",
            serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "inst-1" }),
        ),
    )
    .await
    .unwrap();
    let payload = resp.payload.unwrap();
    assert_eq!(payload["paired"], true);
    assert!(payload["session_id"].is_string());

    // Unknown pairing code is rejected.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("pairing_request", serde_json::json!({ "extension_id": "" })),
    )
    .await;
    assert!(err.is_err(), "empty extension_id payload must be rejected");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_hello_bad_payload_and_pairing_disabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    // Malformed payload surfaces the context error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("hello", serde_json::json!({})),
    )
    .await
    .expect_err("hello without extension_id must fail");
    assert!(
        err.to_string().contains("invalid payload for hello"),
        "got: {err}"
    );

    // With pairing disabled, hello reports no pairing and no session.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "hello",
            serde_json::json!({
                "extension_id": "ext-hello",
                "extension_version": "1.2.3",
                "protocol_version": 2,
                "client_instance_id": "inst-hello"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "hello must succeed: {:?}", resp.error);
    assert_eq!(resp.kind, "hello_response");
    assert_eq!(resp.request_id.as_deref(), Some("req-1"));
    let payload = resp.payload.unwrap();
    assert_eq!(payload["pairing_required"], false);
    assert_eq!(payload["paired"], false);
    assert!(payload["session_id"].is_null());
    assert!(payload["session_expires_at_ms"].is_null());
    assert_eq!(payload["protocol_version"], 7);
    assert!(payload["server_version"].is_string());
    let caps = payload["capabilities"].as_array().unwrap();
    for capability in [
        "status",
        "pairing_request",
        "pairing_finalize",
        "get_suggestions",
        "request_fill",
        "get_totp",
        "copy",
        "find_for_save",
        "save_credential",
    ] {
        assert!(
            caps.iter().any(|c| c == capability),
            "capability {capability} must be advertised"
        );
    }

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_pairing_request_and_finalize_error_paths() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    // Bad payload -> context error.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "pairing_request",
            serde_json::json!({ "extension_id": "ext-a" }),
        ),
    )
    .await
    .expect_err("pairing_request missing client_instance_id must fail");
    assert!(
        err.to_string()
            .contains("invalid payload for pairing_request"),
        "got: {err}"
    );

    // Blank fields are rejected by create_pairing_request itself.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "pairing_request",
            serde_json::json!({ "extension_id": "ext-a", "client_instance_id": "   " }),
        ),
    )
    .await
    .expect_err("blank client_instance_id must fail");
    assert!(
        err.to_string().starts_with("invalid_payload:"),
        "got: {err}"
    );

    // Bad payload for finalize.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("pairing_finalize", serde_json::json!({ "code": "111-222" })),
    )
    .await
    .expect_err("pairing_finalize missing fields must fail");
    assert!(
        err.to_string()
            .contains("invalid payload for pairing_finalize"),
        "got: {err}"
    );

    // Unknown finalize code.
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "pairing_finalize",
            serde_json::json!({
                "extension_id": "ext-a",
                "client_instance_id": "inst-a",
                "code": "000-000"
            }),
        ),
    )
    .await
    .expect_err("unknown code must fail");
    assert!(
        err.to_string().contains("pairing_not_found_or_expired"),
        "got: {err}"
    );

    // Full pairing, then a duplicate pairing_request reports already_paired.
    pair_extension(&state_dir, "ext-dup", "inst-dup").await;
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "pairing_request",
            serde_json::json!({
                "extension_id": "ext-dup",
                "client_instance_id": "inst-dup"
            }),
        ),
    )
    .await
    .expect_err("second pairing_request for a paired client must fail");
    assert!(err.to_string().contains("already_paired"), "got: {err}");

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
}

#[tokio::test]
async fn execute_approve_code_marks_pending_pairing_approved() {
    let (_dir, _db_path, state_dir, _identity_id) = seeded_bridge().await;

    // Create a pending request through the protocol, then approve it via
    // the CLI flag (leading/trailing whitespace is normalized away).
    let resp = handle_request(
        Path::new(""),
        &state_dir,
        request(
            "pairing_request",
            serde_json::json!({
                "extension_id": "ext-cli",
                "client_instance_id": "inst-cli"
            }),
        ),
    )
    .await
    .unwrap();
    let code = resp.payload.unwrap()["code"]
        .as_str()
        .expect("pairing code present")
        .to_string();

    execute(BridgeArgs {
        db_path: None,
        approve_code: Some(format!(" {}", code)),
        state_dir: Some(state_dir.clone()),
        browser_origin: Vec::new(),
    })
    .await
    .expect("approve must succeed");

    let state = load_state(&state_dir).unwrap();
    assert_eq!(state.pending.len(), 1);
    assert!(
        state.pending[0].approved,
        "pending request must be marked approved"
    );

    // Unknown codes fail without mutating anything.
    let err = execute(BridgeArgs {
        db_path: None,
        approve_code: Some("000-000".to_string()),
        state_dir: Some(state_dir.clone()),
        browser_origin: Vec::new(),
    })
    .await
    .expect_err("unknown approval code must fail");
    assert!(
        err.to_string().contains("pairing_not_found_or_expired"),
        "got: {err}"
    );
}

#[test]
fn finalize_pairing_promotes_approved_pending_to_session() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path();
    let now = now_ms();

    // An approved pending request plus a stale pairing row for the same
    // extension: finalizing must replace the row and mint a session.
    let mut st = BridgeStateFile {
        version: 1,
        pairings: vec![PairingInfo {
            extension_id: "ext".to_string(),
            client_instance_id: "client-1".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([1u8; 32]),
            paired_at_ms: now - 1000,
            session: None,
        }],
        pending: vec![PendingPairing {
            code: "123 456".to_string(),
            extension_id: "ext".to_string(),
            client_instance_id: "client-1".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([7u8; 32]),
            requested_at_ms: now,
            expires_at_ms: now + 5 * 60_000,
            approved: true,
        }],
    };
    save_state(state_dir, &st).unwrap();

    // The code is matched after normalization (spaces and case ignored).
    let info = finalize_pairing(
        state_dir,
        PairingFinalizePayload {
            extension_id: "ext".to_string(),
            client_instance_id: "client-1".to_string(),
            code: " 123456 ".to_string(),
        },
    )
    .unwrap();
    assert_eq!(info.extension_id, "ext");
    assert_eq!(info.key_b64, URL_SAFE_NO_PAD.encode([7u8; 32]));
    let session = info.session.expect("finalized pairing carries a session");
    assert!(!session.session_id.is_empty());

    let loaded = load_state(state_dir).unwrap();
    assert!(loaded.pending.is_empty(), "pending entry consumed");
    assert_eq!(loaded.pairings.len(), 1, "stale row replaced, not doubled");
    assert!(loaded.pairings[0].session.is_some());

    // Re-finalizing finds no pending entry anymore.
    let err = finalize_pairing(
        state_dir,
        PairingFinalizePayload {
            extension_id: "ext".to_string(),
            client_instance_id: "client-1".to_string(),
            code: "123456".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "pairing_not_found_or_expired");

    // An unapproved pending request never mints a session.
    st.pending.push(PendingPairing {
        code: "777-888".to_string(),
        extension_id: "ext2".to_string(),
        client_instance_id: "client-2".to_string(),
        key_b64: URL_SAFE_NO_PAD.encode([8u8; 32]),
        requested_at_ms: now,
        expires_at_ms: now + 5 * 60_000,
        approved: false,
    });
    save_state(state_dir, &st).unwrap();
    let err = finalize_pairing(
        state_dir,
        PairingFinalizePayload {
            extension_id: "ext2".to_string(),
            client_instance_id: "client-2".to_string(),
            code: "777-888".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "pairing_not_approved");
}
