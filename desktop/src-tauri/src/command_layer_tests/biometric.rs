//! Command-layer integration tests — `biometric` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn biometric_status_reports_disabled_without_entry() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    init_service_ok(&app, "master-pw-123").await;
    let db_path = app
        .state::<AppState>()
        .db_path
        .lock()
        .await
        .clone()
        .unwrap();

    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    // provider 可用 + keyring 可达（Ok(None)）但条目不存在
    assert!(status.available);
    assert!(!status.enabled);
    assert_eq!(status.platform, crate::biometric::platform_name());

    // 配置后 enabled 翻转；显式 db_path 参数与 state 路径同键
    store.set(&db_path, "master-pw-123").unwrap();
    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().enabled);
}
#[tokio::test]
async fn biometric_enable_rejects_wrong_password_without_writing() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "wrong-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));
    // 先证密码后弹框：密码错了连 ceremony 都不弹，更不写 keyring
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_ceremony_then_writes_entry() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(status.available && status.enabled);
    // 托管的正是验证过的主密码（键 = db_path，一库一钥匙）
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("correct-horse")
    );
}
#[tokio::test]
async fn biometric_enable_fails_closed_when_provider_unavailable() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(false, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not available"));
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_ceremony_failure_writes_nothing() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, true), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    // ceremony 失败在命令边界转 Ok(ApiResponse::error)（不逃逸），零写入
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "ceremony failure must surface an error");
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_enable_requires_unlocked_service() {
    // 未初始化：直接拒绝
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(InMemoryTokenStore::default()),
    );
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 锁定：启用是解锁会话里的敏感配置操作
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(InMemoryTokenStore::default()),
    );
    init_service_ok(&app, "correct-horse").await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
#[tokio::test]
async fn biometric_disable_is_idempotent() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    for _ in 0..2 {
        let resp = biometric_disable(app.state::<AppState>()).await.unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(!resp.data.unwrap().enabled);
    }
    assert_eq!(store.get(&db_path).unwrap(), None);
}
#[tokio::test]
async fn biometric_unlock_unlocks_via_init_service() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // 响应体是裸 bool——托管密码从未出进程（类型上就不含）
    assert_eq!(resp.data, Some(true));

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(true),
        "biometric unlock must unlock the service"
    );
}
#[tokio::test]
async fn biometric_unlock_without_entry_skips_ceremony_and_reports_reset() {
    // force_fail provider：若真弹了框，结果会是 Err(String) 而非带码错误
    let app = mock_app_with_biometric(
        mock_provider(true, true),
        Arc::new(InMemoryTokenStore::default()),
    );
    init_service_ok(&app, "correct-horse").await;
    // 从锁定态出发：无条目时必须既不弹框也不解锁
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // 没弹框也没解锁
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
#[tokio::test]
async fn biometric_unlock_stale_entry_self_heals() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;
    // 直接塞一条错密码条目：模拟桌面外（CLI）改密后的陈旧托管
    store.set(&db_path, "stale-password").unwrap();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // 条目当场删除（防止反复点指纹累计失败计数锁户）且仍锁定
    assert_eq!(store.get(&db_path).unwrap(), None);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
#[tokio::test]
async fn biometric_unlock_fails_closed_when_provider_unavailable() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(false, false), store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;
    store.set(&db_path, "correct-horse").unwrap();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not available"));
    // 条目保留（不可用 ≠ 陈旧），解锁屏报错但可改用主密码登录
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("correct-horse")
    );
}
#[tokio::test]
async fn biometric_enable_keyring_write_failure_reports_and_leaves_no_half_state() {
    let inner = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(FailingSetStore(inner.clone())),
    );
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    // ceremony 通过但 keyring 写失败：明确报错（提示含 keyring）
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("keyring write failed"));
    assert_eq!(inner.get("any").unwrap(), None);
}
/// 包裹链 enable：keyring 落的是密文 blob（门禁层密码条目不落盘），
/// status 报 hardware-bound。
#[tokio::test]
async fn biometric_wrap_enable_stores_ciphertext_blob() {
    let gate_store = Arc::new(InMemoryTokenStore::default());
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_wrap_parts(
        Arc::new(InMemoryTokenStore::default()),
        mock_provider(true, false),
        gate_store.clone(),
        Arc::new(persona_core::MockKeyWrapper::default()),
        wrap_store.clone(),
    );
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(status.available && status.enabled);
    assert_eq!(status.wrap_tier, "hardware-bound");

    // blob 是密文：base64 可解、magic 为 BIOWRAP1、且绝不能是明文密码
    let blob = wrap_store.get(&db_path).unwrap().expect("wrap blob stored");
    assert_ne!(blob, "correct-horse");
    let raw = base64_decode(&blob);
    assert_eq!(&raw[..8], b"BIOWRAP1");
    // 门禁层密码条目不落盘（两类互斥）
    assert_eq!(gate_store.get(&db_path).unwrap(), None);
}
/// 包裹链 unlock 全闭环：enable → lock → unlock，服务恢复且数据可读。
#[tokio::test]
async fn biometric_wrap_unlock_round_trip() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper, wrap_store);
    init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true));
}
/// 注册集漂移（换指纹）：unlock 报 BIOMETRIC_RESET、blob 当场删除，
///
/// 主密码登录不受影响。
#[tokio::test]
async fn biometric_wrap_enrollment_change_resets_to_master_password() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper.clone(), wrap_store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 用户在系统侧换了指纹
    wrapper.rotate_enrollment();
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_RESET)
    );
    // blob 当场删除（旧包裹永不再试），服务仍锁定
    assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));

    // 回退链终态：主密码照常登录
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 用户在系统弹框点取消：报 BIOMETRIC_CANCELLED、blob 保留、仍锁定
/// （取消不是失败，不删包裹不提示错误）。
#[tokio::test]
async fn biometric_wrap_user_cancel_keeps_blob() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let wrapper = Arc::new(persona_core::MockKeyWrapper::default());
    let app = mock_app_with_biometric_wrap(wrapper.clone(), wrap_store.clone());
    let db_path = init_service_ok(&app, "correct-horse").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    wrapper.set_user_cancelled(true);
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_BIOMETRIC_CANCELLED)
    );
    // 包裹仍有效（下次还能解），服务仍锁定
    assert!(wrap_store.get(&db_path).unwrap().is_some());
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}
/// blob 被改写（非 base64 / 信封损坏）：报 BIOMETRIC_RESET 并自删，
///
/// 不累计失败计数、不锁户。
#[tokio::test]
async fn biometric_wrap_corrupted_blob_resets() {
    for corrupt in ["!!!not-base64!!!", "QUJDRA=="] {
        let wrap_store = Arc::new(InMemoryTokenStore::default());
        let app = mock_app_with_biometric_wrap(
            Arc::new(persona_core::MockKeyWrapper::default()),
            wrap_store.clone(),
        );
        let db_path = init_service_ok(&app, "correct-horse").await;
        // 伪造条目：第一种连 base64 都不是，第二种是合法 base64 但非信封
        wrap_store.set(&db_path, corrupt).unwrap();
        lock_service(app.state::<AppState>()).await.unwrap();

        let resp = biometric_unlock(
            BiometricUnlockRequest { db_path: None },
            app.state::<AppState>(),
            app.handle().clone(),
        )
        .await
        .unwrap();
        assert!(!resp.success, "corrupt blob {corrupt:?} must fail");
        assert_eq!(
            resp.error_code.as_deref(),
            Some(crate::error::CODE_BIOMETRIC_RESET),
            "corrupt blob {corrupt:?}"
        );
        assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    }
}
/// 改密后包裹 blob 失效：旧 blob 解出的是 stale key，改密联动必须删
/// blob（用户重新启用），status 回到未启用。
#[tokio::test]
async fn biometric_wrap_invalidated_on_password_change() {
    let wrap_store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric_wrap(
        Arc::new(persona_core::MockKeyWrapper::default()),
        wrap_store.clone(),
    );
    let db_path = init_service_ok(&app, "old-password").await;

    let resp = biometric_enable(
        BiometricEnableRequest {
            master_password: "old-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(wrap_store.get(&db_path).unwrap().is_some());

    let resp = change_master_password(
        crate::types::ChangeMasterPasswordRequest {
            old_password: "old-password".to_string(),
            new_password: "new-password".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // blob 已删：status 回到未启用，前端隐藏指纹按钮
    assert_eq!(wrap_store.get(&db_path).unwrap(), None);
    let resp = biometric_status(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.unwrap().enabled);
}
/// spike 命令在 Linux 上报 Unsupported（探针是 Security.framework 调用）。
#[tokio::test]
async fn biometric_wrap_spike_unsupported_off_macos() {
    let resp = biometric_wrap_spike().await.unwrap();
    #[cfg(target_os = "macos")]
    assert!(resp.success);
    #[cfg(not(target_os = "macos"))]
    {
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("only available on macOS"));
    }
}
/// TPM spike 命令在非 Windows 上报 Unsupported（探针是 NCrypt 调用）。
#[tokio::test]
async fn biometric_tpm_spike_unsupported_off_windows() {
    let resp = biometric_tpm_spike().await.unwrap();
    #[cfg(target_os = "windows")]
    assert!(resp.success);
    #[cfg(not(target_os = "windows"))]
    {
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("only available on Windows"));
    }
}
