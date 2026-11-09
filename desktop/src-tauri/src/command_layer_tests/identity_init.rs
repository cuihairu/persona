//! Command-layer integration tests — `identity_init` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// init_service 的可触发错误臂：垃圾 DB 文件在迁移时暴露（sqlx 连接是
/// 惰性的，打开不报错）、无法创建的路径在连接时暴露；同一 vault 连续输错
/// 5 次后，正确密码也只得到账号锁定。
#[tokio::test]
async fn init_service_degrades_loudly_on_bad_db_and_account_lockout() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("garbage.db");
    let db_path = dir.path().join("lockout.db");
    // Leak the TempDir: the vault keeps the file open for the whole test.
    std::mem::forget(dir);

    // 垃圾文件不是合法 sqlite：连接惰性成功，迁移时才失败。
    std::fs::write(&bad_path, "this is not a sqlite database").unwrap();
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(bad_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Database migration failed"),
        "got: {:?}",
        resp.error
    );

    // 打不开的路径（目录不存在）→ 连接失败。
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some("/proc/persona-must-not-exist/x.db".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Database connection failed"),
        "got: {:?}",
        resp.error
    );

    // 真实 vault：5 次失败触发账号锁定（第 6 次即使密码正确也拒绝）。
    let init_with = |password: &str| {
        init_service(
            InitRequest {
                master_password: password.to_string(),
                db_path: Some(db_path.to_string_lossy().to_string()),
            },
            app.state::<AppState>(),
            app.handle().clone(),
        )
    };
    let resp = init_with("correct-horse").await.unwrap();
    assert!(resp.success, "vault setup failed: {:?}", resp.error);

    for attempt in 0..5 {
        let resp = init_with("wrong").await.unwrap();
        assert_eq!(
            resp.error.as_deref(),
            Some("Invalid master password"),
            "attempt {}",
            attempt + 1
        );
    }
    let resp = init_with("correct-horse").await.unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Account is locked due to too many failed attempts")
    );
}
/// 锁定态下所有"直调 service"的命令都会得到 SERVICE_LOCKED 错误码
/// （map_persona_error → error_with_code 臂）。
#[tokio::test]
async fn locked_service_error_code_matrix() {
    use base64::Engine as _;

    let (app, _identity_id) = app_with_identity().await;
    lock_service(app.state::<AppState>()).await.unwrap();

    // get_credential_data
    let resp = get_credential_data(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // configure_auto_lock 锁定时仍允许（core 不做 ensure_unlocked）
    let resp = configure_auto_lock(
        AutoLockConfigRequest {
            inactivity_timeout_secs: 300,
            absolute_timeout_secs: None,
            require_reauth_sensitive: None,
            sensitive_operation_timeout_secs: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // start_auto_lock_monitoring 锁定时也允许（core 无 ensure_unlocked，
    // 监控本身不泄密）；stop 一并驱动。
    let resp = start_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = stop_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // health_scan（含 check_breaches=true 的 checker 构造分支）
    let resp = health_scan(
        Some(HealthScanRequest {
            min_password_score: None,
            expiry_warning_days: None,
            stale_after_days: None,
            check_breaches: Some(true),
        }),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // passkey 家族（request 先经 UUID/解码检查，用合法输入深入到 service）
    let resp = passkey_self_test(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp =
        passkey_export_private_key(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
            .await
            .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id: uuid::Uuid::new_v4().to_string(),
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            // 合法 base64 的 client_data（锁定错误在 service 调用层触发）
            client_data_json_b64: base64::engine::general_purpose::STANDARD
                .encode(br#"{"challenge":"c"}"#),
            user_handle_b64: None,
            user_name: None,
            user_display_name: None,
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // reveal_credential_secret（凭据不存在也会先撞 ensure_unlocked）
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: uuid::Uuid::new_v4().to_string(),
            field: "password".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
}
/// init_service 的 db_path=None 默认分支：落在 XDG 数据目录的 persona/
/// 子目录下，而非真实用户目录。
#[tokio::test]
async fn init_service_default_db_path_uses_xdg_data_dir() {
    let xdg = tempfile::tempdir().unwrap();
    let _guard = XdgDataDirGuard::sandbox(&xdg);

    let app = mock_app();
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: None,
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let expected = xdg.path().join("persona").join("persona.db");
    assert!(
        expected.exists(),
        "default db should live at {}, exists: {:?}",
        expected.display(),
        std::fs::read_dir(xdg.path()).ok().map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect::<Vec<_>>()
        })
    );
}
#[tokio::test]
async fn init_service_reauthenticates_existing_user_and_rejects_wrong_password() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("same-vault.db");
    // Leak the TempDir: the vault keeps the file open for the whole test.
    std::mem::forget(dir);
    let db_path = db_path.to_string_lossy().to_string();

    // First init creates the user; second init on the same vault takes the
    // existing-user branch and re-authenticates instead.
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "first init must succeed: {:?}", resp.error);

    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "re-init must succeed: {:?}", resp.error);

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true));

    // Wrong password on the same vault is rejected.
    let resp = init_service(
        InitRequest {
            master_password: "wrong-password".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Invalid master password"),
        "got: {:?}",
        resp.error
    );
}
#[tokio::test]
async fn reauth_verify_surfaces_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;

    // 坏库下 authenticate_user 查不到用户表 → Err → map_persona_error 分流。
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.is_some() || resp.error_code.is_some(),
        "got: {:?}",
        resp
    );
}
#[tokio::test]
async fn reauth_gate_round_trip_through_configure_and_reauth_verify() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let state = app.state::<AppState>();

    let resp = create_identity(
        CreateIdentityRequest {
            name: "Gate Holder".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    let identity_id = resp.data.expect("identity created").id;
    let resp = create_credential(password_credential_request(&identity_id), state.clone())
        .await
        .unwrap();
    let cred_id = resp.data.expect("credential created").id;

    // 公开配置 API 打开闸门：1 秒敏感窗口。修复前这个开关只改了超时
    // 副本，管理器从不感知——闸门从未生效。
    let resp = configure_auto_lock(
        AutoLockConfigRequest {
            inactivity_timeout_secs: 900,
            absolute_timeout_secs: None,
            require_reauth_sensitive: Some(true),
            sensitive_operation_timeout_secs: Some(1),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // reauth_verify（authenticate_user）建 session，并把登录本身记为
    // 一次敏感验证 → 刚认证的用户直接过闸。
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred_id.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.success,
        "just-authenticated user passes the gate: {:?}",
        resp
    );

    // 窗口过后：专用错误码 REAUTH_REQUIRED（分流前端弹再认证 modal）。
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred_id.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some("REAUTH_REQUIRED"),
        "got: {:?}",
        resp
    );

    let resp = get_auto_lock_status(state.clone()).await.unwrap();
    assert!(resp.data.expect("status").needs_reauth);

    // 再认证 → 恢复放行。
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred_id,
            field: "password".to_string(),
            item_password: None,
        },
        state,
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp);
    assert_eq!(resp.data.expect("reveal").value, "s3cret-password");
}
#[tokio::test]
async fn init_service_surfaces_password_change_required_code() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // 锁掉会话，模拟“下次解锁”场景；flag 短路发生在密码验证之前
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 经仓储置位（生产置位路径在 core 策略引擎里，此处直驱存储），
    // 只验证命令层把 AuthResult::PasswordChangeRequired 翻译成机器可读码
    let db = persona_core::storage::Database::from_file(&db_path)
        .await
        .unwrap();
    let repo = persona_core::storage::UserAuthRepository::new(db);
    let mut auth = repo
        .get_first()
        .await
        .unwrap()
        .expect("seeded auth row exists");
    auth.password_change_required = true;
    repo.update(&auth).await.unwrap();

    let resp = init_service(
        InitRequest {
            master_password: "master-pw-123".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_PASSWORD_CHANGE_REQUIRED),
        "flag set must short-circuit init with the typed error code"
    );
}
#[tokio::test]
async fn init_service_injects_state_biometric_provider() {
    // force_fail provider：默认 Mock 恒通过——若注入生效，service 层
    // authenticate_biometric 必须失败
    let app = mock_app_with_biometric(
        mock_provider(true, true),
        Arc::new(InMemoryTokenStore::default()),
    );
    init_service_ok(&app, "correct-horse").await;

    let state = app.state::<AppState>();
    let guard = state.service.lock().await;
    let service = guard.as_ref().expect("service initialized");
    let prompt = persona_core::BiometricPrompt {
        user_id: uuid::Uuid::nil(),
        reason: "test".to_string(),
        platform: None,
    };
    assert!(
        service.authenticate_biometric(&prompt).is_err(),
        "service must use the AppState provider, not the silent-pass default Mock"
    );
}
