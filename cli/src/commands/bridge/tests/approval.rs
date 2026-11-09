use super::*;

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn desktop_approval_roundtrip_pins_wire_format() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let (_dir, path, server) = spawn_fake_desktop(true, None).await;
    set_gate_env(Some(&path), None); // auto

    let verdict = desktop_approval_gate(
        "passkey_assert",
        None,
        "https://example.com",
        None,
        Some("item-uuid"),
    )
    .await
    .unwrap();
    assert_eq!(verdict, DesktopApproval::Approved);

    let line = server.await.unwrap();
    let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(req["v"], 1);
    assert_eq!(req["op"], "passkey_assert");
    assert_eq!(req["origin"], "https://example.com");
    assert_eq!(req["item_id"], "item-uuid");
    // Privacy pin: the approval wire carries request metadata only.
    assert!(
        line.trim().len() < 200,
        "no client data on the wire: {line}"
    );
    assert!(!line.contains("client_data"), "no client data: {line}");

    set_gate_env(None, None);
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn desktop_approval_denied_and_auto_fallback() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Explicit denial from the desktop.
    let (_dir, path, _server) = spawn_fake_desktop(false, Some("timeout")).await;
    set_gate_env(Some(&path), None);
    let verdict = desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
        .await
        .unwrap();
    assert_eq!(verdict, DesktopApproval::Denied("timeout".to_string()));

    // auto + unreachable socket → fall back to the gesture gate.
    let nowhere = std::env::temp_dir().join(format!(
        "persona-no-approval-{}-fallback",
        std::process::id()
    ));
    set_gate_env(Some(&nowhere), None);
    let verdict = desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
        .await
        .unwrap();
    assert_eq!(verdict, DesktopApproval::Unavailable);

    set_gate_env(None, None);
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn desktop_approval_require_fails_closed_and_off_skips() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // require + no desktop → hard error (fail closed).
    let nowhere = std::env::temp_dir().join(format!(
        "persona-no-approval-{}-require",
        std::process::id()
    ));
    set_gate_env(Some(&nowhere), Some("require"));
    let err = desktop_approval_gate(
        "passkey_create",
        Some("example.com"),
        "https://example.com",
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("passkey_desktop_approval_required"),
        "got: {err}"
    );

    // off → never contacts the desktop, even when a socket exists.
    let (_dir, path, server) = spawn_fake_desktop(true, None).await;
    set_gate_env(Some(&path), Some("off"));
    let verdict = desktop_approval_gate("passkey_assert", None, "https://example.com", None, None)
        .await
        .unwrap();
    assert_eq!(verdict, DesktopApproval::Unavailable);
    tokio::time::timeout(std::time::Duration::from_millis(150), server)
        .await
        .expect_err("off mode must not contact the fake desktop");

    set_gate_env(None, None);
}

/// A running desktop that answers "denied" surfaces as the
/// `passkey_desktop_denied` error codes from both passkey handlers
/// (before anything is signed or stored).
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn desktop_denial_reaches_the_passkey_handlers() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "1");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    // ---- passkey_create denied by the desktop ----
    let (desk_dir, sock, server) = spawn_fake_desktop(false, Some("not now")).await;
    set_gate_env(Some(&sock), None); // auto

    let options_json = serde_json::json!({
        "rp": { "id": "example.com", "name": "Example" },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(b"denied-user-handle"),
            "name": "alice@example.com",
            "displayName": "Alice"
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_create",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "request_json": options_json,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(local_client_data_for(
                    "https://example.com",
                    "Y3JlYXRlLWNoYWxsZW5nZQ",
                )),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("passkey_desktop_denied"),
        "got: {err}"
    );
    assert!(err.to_string().contains("not now"), "got: {err}");
    let _line = server.await.unwrap();
    drop(desk_dir);

    // ---- passkey_assert denied by the desktop ----
    let db = open_db(&db_path).await.unwrap();
    let repo = persona_core::storage::PasskeyRepository::new(std::sync::Arc::new(db));
    let stored = repo.find_by_rp_id("example.com").await.unwrap();
    let item_id = stored[0].id.to_string();
    drop(repo);

    let (desk_dir, sock, server) = spawn_fake_desktop(false, Some("user refused")).await;
    set_gate_env(Some(&sock), None);

    let get_client_data =
        r#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#
            .to_string()
            .into_bytes();
    let err = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().starts_with("passkey_desktop_denied"),
        "got: {err}"
    );
    assert!(err.to_string().contains("user refused"), "got: {err}");
    let _line = server.await.unwrap();
    drop(desk_dir);

    set_gate_env(None, None);
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// The Approved verdict flows through both passkey handlers end to end,
/// and a desktop that accepts the connection but never answers fails
/// closed in require mode.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn desktop_approval_allows_the_passkey_handlers_and_silent_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_PAIRING", "0");
    std::env::set_var("PERSONA_BRIDGE_REQUIRE_GESTURE", "0");
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);

    let (_dir, db_path, state_dir, _identity_id) = seeded_bridge().await;

    let options_json = serde_json::json!({
        "rp": { "id": "example.com", "name": "Example" },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(b"approved-user-handle"),
            "name": "alice@example.com",
            "displayName": "Alice"
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    let create_payload = || {
        serde_json::json!({
            "origin": "https://example.com",
            "user_gesture": true,
            "request_json": options_json,
            "client_data_json_b64": URL_SAFE_NO_PAD.encode(local_client_data_for(
                "https://example.com",
                "Y3JlYXRlLWNoYWxsZW5nZQ",
            )),
        })
    };

    // ---- Approved: passkey_create signs and stores ----
    let (desk_dir, sock, server) = spawn_fake_desktop(true, None).await;
    set_gate_env(Some(&sock), None); // auto
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("passkey_create", create_payload()),
    )
    .await
    .unwrap();
    assert!(resp.ok, "approved creation must succeed: {:?}", resp.error);
    let _line = server.await.unwrap();
    drop(desk_dir);

    // ---- Approved: passkey_assert signs the seeded credential ----
    let db = open_db(&db_path).await.unwrap();
    let repo = persona_core::storage::PasskeyRepository::new(std::sync::Arc::new(db));
    let stored = repo.find_by_rp_id("example.com").await.unwrap();
    let item_id = stored[0].id.to_string();
    drop(repo);

    let (desk_dir, sock, server) = spawn_fake_desktop(true, None).await;
    set_gate_env(Some(&sock), None);
    let get_client_data =
        r#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#
            .to_string()
            .into_bytes();
    let resp = handle_request(
        &db_path,
        &state_dir,
        request(
            "passkey_assert",
            serde_json::json!({
                "origin": "https://example.com",
                "user_gesture": true,
                "item_id": item_id,
                "client_data_json_b64": URL_SAFE_NO_PAD.encode(&get_client_data),
            }),
        ),
    )
    .await
    .unwrap();
    assert!(resp.ok, "approved assertion must succeed: {:?}", resp.error);
    let _line = server.await.unwrap();
    drop(desk_dir);

    // ---- A desktop that goes silent (empty answer) fails closed in
    // require mode instead of hanging on the connection ----
    let desk_dir = tempfile::tempdir().unwrap();
    let silent_sock = desk_dir.path().join("passkey-approval.sock");
    let silent_listener = tokio::net::UnixListener::bind(&silent_sock).unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        if let Ok((stream, _)) = silent_listener.accept().await {
            let mut line = String::new();
            let _ = BufReader::new(stream).read_line(&mut line).await;
            // Drop the connection without ever answering.
        }
    });
    set_gate_env(Some(&silent_sock), Some("require"));
    let err = handle_request(
        &db_path,
        &state_dir,
        request("passkey_create", create_payload()),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("passkey_desktop_approval_required"),
        "got: {err}"
    );
    drop(desk_dir);

    set_gate_env(None, None);
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_PAIRING");
    std::env::remove_var("PERSONA_BRIDGE_REQUIRE_GESTURE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
