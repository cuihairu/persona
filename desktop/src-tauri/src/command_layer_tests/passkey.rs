//! Command-layer integration tests — `passkey` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn passkey_commands_round_trip_create_list_selftest_export_delete() {
    use base64::Engine;

    let (app, identity_id) = app_with_identity().await;

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"create-challenge"),
        "origin": "https://example.com",
    });
    let client_data_b64 = base64::engine::general_purpose::STANDARD.encode(client_data.to_string());
    let user_handle_b64 = base64::engine::general_purpose::STANDARD.encode(b"passkey-user-handle");

    // Register.
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id: identity_id.clone(),
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: client_data_b64,
            user_handle_b64: Some(user_handle_b64),
            user_name: Some("alice@example.com".to_string()),
            user_display_name: Some("Alice".to_string()),
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creation = resp.data.expect("passkey created");
    let passkey_id = creation.passkey.id.clone();
    assert!(
        !creation.attestation_object_b64.is_empty(),
        "attestation object returned"
    );

    // List by identity and by rp id; get one.
    let resp = passkey_list(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 1);

    let resp = passkey_list_by_rp("example.com".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 1);

    let resp = passkey_get(passkey_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().expect("passkey found").id, passkey_id);

    // Self-test (sign + verify round trip) and private-key export.
    let resp = passkey_self_test(passkey_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap(), "self test passes");

    // Assertion lives at the service layer (no desktop command wraps it) and
    // stamps last_used_at; the next get surfaces it as a timestamp.
    let assertion_client_data =
        br#"{"type":"webauthn.get","challenge":"YXNzZXJ0aW9u","origin":"https://example.com"}"#;
    {
        let state = app.state::<AppState>();
        let mut guard = state.service.lock().await;
        let service = guard.as_mut().expect("service initialized");
        let assertion = service
            .passkey_assertion(
                &uuid::Uuid::parse_str(&passkey_id).unwrap(),
                "https://example.com",
                assertion_client_data,
                true,
                "extension",
            )
            .await
            .unwrap();
        assert!(!assertion.credential_id.is_empty());
    }
    let resp = passkey_get(passkey_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let found = resp.data.unwrap().expect("passkey found");
    assert!(
        found.last_used_at.is_some(),
        "assertion stamps last_used_at"
    );

    let resp = passkey_export_private_key(passkey_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pk = base64::engine::general_purpose::STANDARD
        .decode(resp.data.unwrap())
        .expect("private key is base64");
    assert_eq!(pk.len(), 32, "P-256 scalar is 32 bytes");

    // Delete and confirm gone.
    let resp = passkey_delete(passkey_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = passkey_get(passkey_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_none());
}
/// passkey 家族的未初始化/坏 UUID/锁定（SERVICE_LOCKED 错误码）门禁。
#[tokio::test]
async fn passkey_gates_fail_closed_with_error_codes() {
    let app = mock_app();

    let resp = passkey_list(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = passkey_list_by_rp("example.com".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = passkey_get(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = passkey_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // 坏 UUID 都是 ApiResponse 错误（命令内匹配，不用 `?` 传播）。
    let resp = passkey_list("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = passkey_get("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = passkey_delete("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // 锁定后：ensure_unlocked 的 AuthenticationFailed("Service is locked")
    // 被 map_persona_error 映射成机器可读的 SERVICE_LOCKED。
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = passkey_list(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = passkey_list_by_rp("example.com".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = passkey_get(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = passkey_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
}
#[tokio::test]
async fn passkey_commands_surface_db_errors_from_garbage_vault() {
    use base64::Engine;

    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    let resp = passkey_list(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to list passkeys"),
        "got: {:?}",
        resp.error
    );

    let resp = passkey_list_by_rp("example.com".to_string(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to list passkeys"),
        "got: {:?}",
        resp.error
    );

    let resp = passkey_get(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );

    let resp = passkey_delete(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );

    let resp = passkey_self_test(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success, "self test must fail on a dead db");

    let resp = passkey_export_private_key(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to export passkey private key"),
        "got: {:?}",
        resp.error
    );

    // 注册请求合法（client_data 可解析），最后一步落到 repo 才报错。
    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"create-challenge"),
        "origin": "https://example.com",
    });
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id: bogus.clone(),
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: base64::engine::general_purpose::STANDARD
                .encode(client_data.to_string()),
            user_handle_b64: Some(
                base64::engine::general_purpose::STANDARD.encode(b"passkey-user-handle"),
            ),
            user_name: Some("alice@example.com".to_string()),
            user_display_name: Some("Alice".to_string()),
            user_verification: false,
        },
        state,
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );
}
#[tokio::test]
async fn passkey_gate_spawns_approval_server_only_after_flag_enabled_and_reunlock() {
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);
    let app = mock_app();

    let vault_dir = tempfile::tempdir().unwrap();
    let db_path = vault_dir.path().join("gate.db");
    // Leak: the service holds the vault file open for the whole test.
    std::mem::forget(vault_dir);
    let db_path_str = db_path.to_string_lossy().to_string();

    // 首次解锁：flag 默认关，门禁不 spawn
    let resp = init_service(
        InitRequest {
            master_password: "master-pw-123".to_string(),
            db_path: Some(db_path_str.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let socket = state_dir
        .path()
        .join(crate::passkey_bridge::APPROVAL_SOCKET_NAME);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!socket.exists(), "gate closed: no approval socket");

    // 打开 passkeys 开关（当前已解锁，允许写）
    let resp = set_feature_flags(
        false,
        false,
        true,
        false,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // lock→unlock（重新 init）：门禁读到开关后 spawn
    let resp = init_service(
        InitRequest {
            master_password: "master-pw-123".to_string(),
            db_path: Some(db_path_str.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !socket.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(socket.exists(), "flag on + re-unlock must spawn the server");
    assert!(app
        .state::<AppState>()
        .passkey_server_started
        .load(std::sync::atomic::Ordering::SeqCst));

    // 幂等：已启动后重复 init 不再 spawn（标记保持，无 panic/重复绑定报错）
    let resp = init_service(
        InitRequest {
            master_password: "master-pw-123".to_string(),
            db_path: Some(db_path_str.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
#[tokio::test]
async fn passkey_gate_stays_off_for_missing_vault_and_default_flags() {
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);
    let app = mock_app();
    let socket = state_dir
        .path()
        .join(crate::passkey_bridge::APPROVAL_SOCKET_NAME);

    // vault 打不开：只读探测失败 → 视为关，不 spawn、不置标记
    crate::commands::maybe_start_passkey_server(
        "/nonexistent/vault/gate.db",
        &app.state::<AppState>(),
        app.handle(),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!socket.exists());
    assert!(!app
        .state::<AppState>()
        .passkey_server_started
        .load(std::sync::atomic::Ordering::SeqCst));

    // 正常 vault 但 flag 保持默认关：init 尾部的门禁同样跳过
    init_service_ok(&app, "master-pw-123").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!socket.exists());
    assert!(!app
        .state::<AppState>()
        .passkey_server_started
        .load(std::sync::atomic::Ordering::SeqCst));
}
