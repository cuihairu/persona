use super::*;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_authenticated_session_signature_enforcement() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;
    let origin_payload = serde_json::json!({ "origin": "https://example.com" });

    // No auth block at all -> pairing_required.
    let err = handle_request(
        &db_path,
        &state_dir,
        request("get_suggestions", origin_payload.clone()),
    )
    .await
    .expect_err("unauthenticated request must fail");
    assert!(
        err.to_string().starts_with("pairing_required"),
        "got: {err}"
    );

    // Auth block without a session id -> pairing_required.
    let req = BridgeRequest {
        request_id: Some("req-1".to_string()),
        kind: "get_suggestions".to_string(),
        payload: origin_payload.clone(),
        auth: Some(BridgeAuth {
            session_id: None,
            ts_ms: now_ms(),
            nonce: "n1".to_string(),
            signature: "AA".to_string(),
        }),
    };
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("auth without session_id must fail");
    assert!(
        err.to_string().starts_with("pairing_required"),
        "got: {err}"
    );

    // Pair for real so a session and key exist.
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-sign", "inst-sign").await;

    // Unknown session id -> session_expired.
    let req = signed_request(
        "get_suggestions",
        origin_payload.clone(),
        "req-1",
        "00000000-0000-0000-0000-000000000000",
        &key_b64,
        now_ms(),
        "nonce-unknown",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("unknown session must fail");
    assert!(err.to_string().starts_with("session_expired"), "got: {err}");

    // Valid signature passes.
    let req = signed_request(
        "get_suggestions",
        origin_payload.clone(),
        "req-1",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-ok",
    );
    let resp = handle_request(&db_path, &state_dir, req).await.unwrap();
    assert!(
        resp.ok,
        "correctly signed request must succeed: {:?}",
        resp.error
    );

    // Tampered but well-formed signature -> authentication_failed.
    let mut req = signed_request(
        "get_suggestions",
        origin_payload.clone(),
        "req-1",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-bad",
    );
    if let Some(auth) = req.auth.as_mut() {
        auth.signature = "AAAA".to_string();
    }
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("tampered signature must fail");
    assert_eq!(err.to_string(), "authentication_failed");

    // Stale timestamp is rejected under the default 5 minute skew.
    let req = signed_request(
        "get_suggestions",
        origin_payload.clone(),
        "req-1",
        &session_id,
        &key_b64,
        now_ms() - 10 * 60 * 1000,
        "nonce-stale",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("stale timestamp must fail");
    assert!(
        err.to_string()
            .starts_with("authentication_failed: stale timestamp"),
        "got: {err}"
    );

    // A larger configured skew lets the very same request through.
    std::env::set_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS", "3600000");
    let req = signed_request(
        "get_suggestions",
        origin_payload.clone(),
        "req-1",
        &session_id,
        &key_b64,
        now_ms() - 10 * 60 * 1000,
        "nonce-skew",
    );
    let resp = handle_request(&db_path, &state_dir, req).await.unwrap();
    assert!(
        resp.ok,
        "stale request must pass with a raised skew: {:?}",
        resp.error
    );
    std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");

    // A pairing whose key is not valid base64url -> invalid key.
    save_state(
        &state_dir,
        &BridgeStateFile {
            version: 1,
            pairings: vec![PairingInfo {
                extension_id: "ext-evil".to_string(),
                client_instance_id: "inst-evil".to_string(),
                key_b64: "!!!not-base64".to_string(),
                paired_at_ms: now_ms(),
                session: Some(SessionInfo {
                    session_id: "session-evil".to_string(),
                    expires_at_ms: now_ms() + 60_000,
                }),
            }],
            pending: vec![],
        },
    )
    .unwrap();
    let req = BridgeRequest {
        request_id: Some("req-1".to_string()),
        kind: "get_suggestions".to_string(),
        payload: origin_payload.clone(),
        auth: Some(BridgeAuth {
            session_id: Some("session-evil".to_string()),
            ts_ms: now_ms(),
            nonce: "n".to_string(),
            signature: "AA".to_string(),
        }),
    };
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("corrupt pairing key must fail");
    assert!(
        err.to_string()
            .starts_with("authentication_failed: invalid key"),
        "got: {err}"
    );

    // A valid key but non-base64url signature encoding.
    save_state(
        &state_dir,
        &BridgeStateFile {
            version: 1,
            pairings: vec![PairingInfo {
                extension_id: "ext-enc".to_string(),
                client_instance_id: "inst-enc".to_string(),
                key_b64: URL_SAFE_NO_PAD.encode([9u8; 32]),
                paired_at_ms: now_ms(),
                session: Some(SessionInfo {
                    session_id: "session-enc".to_string(),
                    expires_at_ms: now_ms() + 60_000,
                }),
            }],
            pending: vec![],
        },
    )
    .unwrap();
    let req = BridgeRequest {
        request_id: Some("req-1".to_string()),
        kind: "get_suggestions".to_string(),
        payload: origin_payload,
        auth: Some(BridgeAuth {
            session_id: Some("session-enc".to_string()),
            ts_ms: now_ms(),
            nonce: "n".to_string(),
            signature: "!!!".to_string(),
        }),
    };
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("bad signature encoding must fail");
    assert!(
        err.to_string()
            .starts_with("authentication_failed: invalid signature encoding"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_AUTH_MAX_SKEW_MS");
}

#[test]
fn bridge_state_file_helpers_roundtrip_and_purge() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path();
    let now = now_ms();

    // Missing file -> default state with version 1.
    let state = load_state(state_dir).unwrap();
    assert_eq!(state.version, 1);
    assert!(state.pairings.is_empty());
    assert!(state.pending.is_empty());

    // Round trip through save_state.
    let mut st = BridgeStateFile {
        version: 1,
        pairings: vec![PairingInfo {
            extension_id: "ext".to_string(),
            client_instance_id: "inst".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([1u8; 32]),
            paired_at_ms: now,
            session: Some(SessionInfo {
                session_id: "s1".to_string(),
                expires_at_ms: now + 1_000,
            }),
        }],
        pending: vec![PendingPairing {
            code: "111-222".to_string(),
            extension_id: "ext".to_string(),
            client_instance_id: "inst".to_string(),
            key_b64: URL_SAFE_NO_PAD.encode([2u8; 32]),
            requested_at_ms: now,
            expires_at_ms: now + 1_000,
            approved: false,
        }],
    };
    save_state(state_dir, &st).unwrap();
    let loaded = load_state(state_dir).unwrap();
    assert_eq!(loaded.pairings.len(), 1);
    assert_eq!(
        loaded.pairings[0].session.as_ref().unwrap().session_id,
        "s1"
    );
    assert_eq!(loaded.pending.len(), 1);

    // Version 0 files are normalized to 1.
    std::fs::write(state_path(state_dir), br#"{"version": 0}"#).unwrap();
    assert_eq!(load_state(state_dir).unwrap().version, 1);

    // Corrupt JSON is an error, not a panic.
    std::fs::write(state_path(state_dir), b"{nope").unwrap();
    assert!(load_state(state_dir).is_err());

    // purge_expired drops stale pending requests and clears expired
    // sessions while leaving live entries untouched.
    st.pending.push(PendingPairing {
        code: "999-999".to_string(),
        extension_id: "old".to_string(),
        client_instance_id: "old".to_string(),
        key_b64: URL_SAFE_NO_PAD.encode([3u8; 32]),
        requested_at_ms: now - 20 * 60_000,
        expires_at_ms: now - 1,
        approved: false,
    });
    st.pairings.push(PairingInfo {
        extension_id: "dead".to_string(),
        client_instance_id: "dead".to_string(),
        key_b64: URL_SAFE_NO_PAD.encode([4u8; 32]),
        paired_at_ms: now - 90_000,
        session: Some(SessionInfo {
            session_id: "dead-session".to_string(),
            expires_at_ms: now - 1,
        }),
    });
    purge_expired(&mut st);
    assert_eq!(st.pending.len(), 1, "only the live pending request remains");
    assert_eq!(st.pending[0].code, "111-222");
    assert_eq!(st.pairings.len(), 2);
    assert!(
        st.pairings[0].session.is_some(),
        "live session must survive"
    );
    assert!(
        st.pairings[1].session.is_none(),
        "expired session must be cleared"
    );
}

#[test]
fn ensure_session_creates_once_and_reuses() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path();

    // Unknown pairing -> no session.
    assert!(ensure_session(state_dir, "ext-s", "inst-s")
        .unwrap()
        .is_none());

    // A stored pairing without a session gets one on the first hello.
    save_state(
        state_dir,
        &BridgeStateFile {
            version: 1,
            pairings: vec![PairingInfo {
                extension_id: "ext-s".to_string(),
                client_instance_id: "inst-s".to_string(),
                key_b64: URL_SAFE_NO_PAD.encode([3u8; 32]),
                paired_at_ms: now_ms(),
                session: None,
            }],
            pending: vec![],
        },
    )
    .unwrap();
    let first = ensure_session(state_dir, "ext-s", "inst-s")
        .unwrap()
        .unwrap();
    let second = ensure_session(state_dir, "ext-s", "inst-s")
        .unwrap()
        .unwrap();
    assert_eq!(
        first.session_id, second.session_id,
        "an existing session must be reused"
    );
    assert!(second.expires_at_ms > now_ms());

    // The issued session was persisted.
    let state = load_state(state_dir).unwrap();
    assert_eq!(
        state.pairings[0].session.as_ref().unwrap().session_id,
        first.session_id
    );
}
