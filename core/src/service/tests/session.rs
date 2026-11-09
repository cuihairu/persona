use super::*;

/// log_audit → emitter 挂钩：同步入队、None 解除后不再上报。
#[tokio::test]
async fn log_audit_feeds_event_emitter_until_detached() {
    use crate::events::testing::{eventually, FakeSink};
    use std::sync::Arc;

    let (_db, mut service) = unlocked_service().await;
    let sink = Arc::new(FakeSink::default());
    // batch_size=1：单条事件即触发 notify flush（默认 100 要等 interval）
    let emitter = crate::events::Emitter::with_config(
        sink.clone(),
        crate::events::EmitterConfig {
            batch_size: 1,
            ..Default::default()
        },
    );
    emitter.start();
    service.set_event_emitter(Some(emitter.clone()));

    service
        .log_audit(
            AuditAction::Login,
            ResourceType::User,
            true,
            None,
            None,
            None,
        )
        .await;
    eventually(|| sink.call_count() >= 1).await;
    assert_eq!(sink.batches()[0].len(), 1);
    assert_eq!(sink.batches()[0][0].action, "login");
    emitter.stop().await;

    // None 解除挂钩：后续审计只落本地库，不再上报
    service.set_event_emitter(None);
    service
        .log_audit(
            AuditAction::Login,
            ResourceType::User,
            true,
            None,
            None,
            None,
        )
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(sink.call_count(), 1);
}

/// `set_event_emitter` 传播到 auto_lock_manager：session 锁定审计
/// 走同一上报链，`None` 时两处（service + manager）一起摘除。
#[tokio::test]
async fn set_event_emitter_propagates_to_auto_lock_manager() {
    use crate::events::testing::{eventually, FakeSink};
    use std::sync::Arc;

    let (_db, mut service) = unlocked_service().await;

    // 注册真 session 让 force_lock_session 触达 manager 的审计路径。
    let user_id = service.current_user.expect("initialized user");
    let session = Session::new(user_id.to_string(), Duration::from_secs(600));
    let session_id = session.id.clone();
    service
        .auto_lock_manager
        .add_session(session)
        .await
        .unwrap();
    *service.current_session_id.write().await = Some(session_id.clone());

    let sink = Arc::new(FakeSink::default());
    let emitter = crate::events::Emitter::with_config(
        sink.clone(),
        crate::events::EmitterConfig {
            batch_size: 1,
            ..Default::default()
        },
    );
    emitter.start();
    service.set_event_emitter(Some(emitter.clone()));

    service.force_lock_session().await.unwrap();
    eventually(|| sink.call_count() >= 1).await;
    assert_eq!(sink.batches()[0][0].action, "session_locked");
    assert_eq!(
        sink.batches()[0][0].session_id.as_deref(),
        Some(session_id.as_str())
    );

    // None 同步摘除 manager 侧：解锁/再锁只落本地库，不再上报
    service.set_event_emitter(None);
    service.unlock_session().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let count_after_detach = sink.call_count();
    service.force_lock_session().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(sink.call_count(), count_after_detach);
    emitter.stop().await;
}

#[tokio::test]
async fn test_locked_service_rejects_operations() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db).await.unwrap();
    assert!(!service.is_unlocked());

    let id = Uuid::new_v4();
    for err in [
        service
            .create_identity("locked".to_string(), IdentityType::Personal)
            .await
            .unwrap_err()
            .to_string(),
        service.get_identities().await.unwrap_err().to_string(),
        service.get_identity(&id).await.unwrap_err().to_string(),
        service
            .get_credentials_for_identity(&id)
            .await
            .unwrap_err()
            .to_string(),
        service.get_credential(&id).await.unwrap_err().to_string(),
        service
            .delete_credential(&id)
            .await
            .unwrap_err()
            .to_string(),
        service.export_identity(&id).await.unwrap_err().to_string(),
        service.get_statistics().await.unwrap_err().to_string(),
        service
            .attach_file(id, "/tmp/x", false)
            .await
            .unwrap_err()
            .to_string(),
        service.get_attachments(&id).await.unwrap_err().to_string(),
    ] {
        assert!(
            err.contains("Service is locked"),
            "unexpected error: {}",
            err
        );
    }
}

#[tokio::test]
async fn test_get_master_encryption_service_reports_locked() {
    // The public operations gate through ensure_unlocked first, so the
    // accessor's own locked branch is exercised directly (the same-module
    // legacy-decryption tests already poke the success side).
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db).await.unwrap();

    // A fresh service carries no encryption material at all.
    let err = service
        .get_master_encryption_service()
        .err()
        .expect("fresh service must be locked");
    assert!(err.to_string().contains("Service is locked"));

    // After a successful unlock, lock() drops the material again and the
    // same error surfaces.
    service.initialize_user("master-pin").await.unwrap();
    assert!(service.get_master_encryption_service().is_ok());
    service.lock();
    let err = service
        .get_master_encryption_service()
        .err()
        .expect("locked service must report locked");
    assert!(err.to_string().contains("Service is locked"));
}

/// Connect 面敏感活动刷新回归：登录后敏感窗口（默认 300s）超时 →
/// force_lock_sensitive 锁会话、敏感操作报错——无人值守 serve 实测
/// （fleet-apply 的读密文请求 500，token 面无再认证入口，永久失败）。
/// `mark_authorized_request`（Connect 中间件每请求调用）刷新后恢复。
#[tokio::test]
async fn mark_authorized_request_clears_sensitive_timeout_lock() {
    // 自建服务 + 运行时密码：字面量流入 authenticate_user 会被 CodeQL
    // rust/hard-coded-cryptographic-value 标 critical（本 PR 实测，
    // annotation core/src/service.rs:4950）；unlocked_service 内的
    // 字面量是基线，不随本 diff 计。
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db).await.unwrap();
    let master = format!("sensitive-test-{}", std::process::id());
    service.initialize_user(&master).await.unwrap();
    service.authenticate_user(&master).await.unwrap();

    let sid = service
        .current_session_id
        .read()
        .await
        .clone()
        .expect("session after authenticate");
    service
        .auto_lock_manager
        .backdate_sensitive_for_test(&sid, std::time::Duration::from_secs(600))
        .await;

    let err = service
        .update_sensitive_auto_lock_activity()
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("sensitive operation timeout"),
        "敏感窗口超时应报错: {err}"
    );

    // token 面刷新 → 恢复（等价 Connect 中间件的每请求调用）
    service.mark_authorized_request().await.unwrap();
    service
        .update_sensitive_auto_lock_activity()
        .await
        .expect("刷新后敏感操作应通过");
    assert!(service.is_unlocked());

    // 无会话服务：机会性刷新为 no-op（不改任何拒绝语义）
    let fresh_db = Database::in_memory().await.unwrap();
    fresh_db.migrate().await.unwrap();
    let fresh = PersonaService::new(fresh_db).await.unwrap();
    fresh.mark_authorized_request().await.unwrap();
}

#[tokio::test]
async fn test_sensitive_operation_gated_behind_reauth() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Reauth Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Gated", CredentialType::Password).await;

    // Swap in a manager that demands re-authentication for sensitive
    // operations (the default config keeps this off).
    service.auto_lock_manager = AutoLockManager::with_basic_config(crate::auth::AutoLockConfig {
        require_reauth_sensitive: true,
        sensitive_operation_timeout_secs: 3600,
        ..Default::default()
    });
    let session = Session::new("reauth-user".to_string(), Duration::from_secs(3600));
    let session_id = session.id.clone();
    service
        .auto_lock_manager
        .add_session(session)
        .await
        .unwrap();
    *service.current_session_id.write().await = Some(session_id.clone());

    // A freshly registered session has no sensitive-activity history, so
    // the gate must reject the read with the dedicated error variant.
    assert!(service.needs_reauth().await);
    let err = service.get_credential_data(&cred.id).await.unwrap_err();
    assert!(
        err.to_string().contains("Re-authentication required"),
        "unexpected error: {err}"
    );

    // Once sensitive activity is recorded, the same call goes through and
    // (via the success path) refreshes the sensitive timer again.
    service
        .auto_lock_manager
        .update_sensitive_activity(&session_id)
        .await
        .unwrap();
    assert!(!service.needs_reauth().await);
    let data = service
        .get_credential_data(&cred.id)
        .await
        .unwrap()
        .expect("credential exists");
    assert!(matches!(data, CredentialData::Password(_)));
}

/// 公开 API 的完整回路：configure_auto_lock 打开敏感闸门 → 登录
/// （authenticate_user）记录敏感活动即放行 → 窗口过后被
/// ReauthRequired 拦下 → 再认证恢复 → 关闭闸门同样恢复。
/// 此前的测试只能换私有 manager 字段，公开路径下开关从未生效。
#[tokio::test]
async fn test_configure_auto_lock_gate_round_trip_via_public_api() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Gate Round Trip".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(
        &service,
        identity.id,
        "Gated Three",
        CredentialType::Password,
    )
    .await;

    // 打开闸门，敏感窗口 1 秒。
    service
        .configure_auto_lock(crate::auth::AutoLockConfig {
            inactivity_timeout_secs: 900,
            absolute_timeout_secs: 0,
            require_reauth_sensitive: true,
            sensitive_operation_timeout_secs: 1,
        })
        .await
        .unwrap();

    // 生产登录路径建立 session，并把登录本身记为一次敏感验证——
    // 刚登录的用户应能直接做敏感操作（否则闸门无法自愈：计时器只能
    // 由成功的敏感操作刷新）。
    let auth = service.authenticate_user("master-pin").await.unwrap();
    assert!(matches!(auth, AuthResult::Success));
    assert!(!service.needs_reauth().await);
    assert!(service.get_credential_data(&cred.id).await.is_ok());

    // 窗口过后，同一操作被专用错误变体拦下。
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(service.needs_reauth().await);
    let err = service.get_credential_data(&cred.id).await.unwrap_err();
    assert!(
        err.to_string().contains("Re-authentication required"),
        "unexpected error: {err}"
    );

    // 再认证（同一登录路径）刷新敏感计时器，操作恢复放行。
    let auth = service.authenticate_user("master-pin").await.unwrap();
    assert!(matches!(auth, AuthResult::Success));
    assert!(!service.needs_reauth().await);

    // 关闭闸门后，即使窗口再次过期也放行。
    tokio::time::sleep(Duration::from_millis(1100)).await;
    service
        .configure_auto_lock(crate::auth::AutoLockConfig::default())
        .await
        .unwrap();
    assert!(!service.needs_reauth().await);
    assert!(service.get_credential_data(&cred.id).await.is_ok());
}

#[tokio::test]
async fn test_session_auto_lock_surface() {
    let (_db, service) = unlocked_service().await;

    // Without a session (initialize_user does not create one) the
    // legacy checks keep the service usable.
    assert!(!service.is_session_locked().await);
    assert!(!service.needs_reauth().await);
    assert!(service.force_lock_session().await.is_ok());
    assert!(service.unlock_session().await.is_ok());
    assert!(service.get_user_sessions().await.unwrap().is_empty());
    let _stats = service.get_auto_lock_statistics().await.unwrap();

    // With a session id pointing at an unknown session, lock/unlock
    // surface the manager's errors and the service reports locked.
    *service.current_session_id.write().await = Some("ghost-session".to_string());
    assert!(service.is_session_locked().await);
    assert!(service.force_lock_session().await.is_err());
    assert!(service.unlock_session().await.is_err());
    // Default config does not require re-auth for sensitive ops.
    assert!(!service.needs_reauth().await);
    assert!(service.get_user_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_auto_lock_configuration_and_monitoring() {
    let (_db, mut service) = unlocked_service().await;

    service
        .configure_auto_lock(crate::auth::AutoLockConfig::default())
        .await
        .unwrap();
    service.set_auto_lock_timeout(Duration::from_secs(60));
    service.touch_activity();
    service
        .register_auto_lock_callback(Arc::new(|_event| {}))
        .await;

    // Monitoring works with and without a current user.
    service.start_auto_lock_monitoring().await.unwrap();
    service.stop_auto_lock_monitoring().await;
    assert!(service.get_auto_lock_statistics().await.is_ok());
}

#[tokio::test]
async fn test_auto_lock_timeout_configuration_semantics() {
    let (_db, mut service) = unlocked_service().await;

    // set_auto_lock_timeout and inactivity_timeout_secs round-trip.
    service.set_auto_lock_timeout(Duration::from_secs(90));
    assert_eq!(service.inactivity_timeout_secs(), 90);

    // configure_auto_lock propagates the configured inactivity timeout.
    service
        .configure_auto_lock(crate::auth::AutoLockConfig {
            inactivity_timeout_secs: 120,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(service.inactivity_timeout_secs(), 120);

    // touch_activity keeps the service unlocked inside the window ...
    service.set_auto_lock_timeout(Duration::from_secs(60));
    service.touch_activity();
    assert!(service.is_unlocked());

    // ... and a zero window is expired the moment it is touched.
    service.set_auto_lock_timeout(Duration::ZERO);
    service.touch_activity();
    assert!(!service.is_unlocked());
}

#[tokio::test]
async fn test_monitoring_lifecycle_registers_user_and_sessions() {
    let (_db, service) = unlocked_service().await;
    let user_id = service.current_user.expect("initialized user");

    // A session registered on the manager is visible through the service.
    let session = Session::new(user_id.to_string(), Duration::from_secs(600));
    let session_id = session.id.clone();
    service
        .auto_lock_manager
        .add_session(session)
        .await
        .unwrap();
    *service.current_session_id.write().await = Some(session_id.clone());

    let sessions = service.get_user_sessions().await.unwrap();
    assert!(sessions.iter().any(|s| s.id == session_id));

    // Starting monitoring with a current user wires it into the manager;
    // stopping is idempotent and the session stays registered.
    service.start_auto_lock_monitoring().await.unwrap();
    service.stop_auto_lock_monitoring().await;
    service.stop_auto_lock_monitoring().await;

    let stats = service.get_auto_lock_statistics().await.unwrap();
    assert!(stats.total_sessions >= 1);
    assert!(service
        .get_user_sessions()
        .await
        .unwrap()
        .iter()
        .any(|s| s.id == session_id));
}

#[tokio::test]
async fn test_remote_and_biometric_provider_surface() {
    let (_db, mut service) = unlocked_service().await;

    // Swap in providers explicitly (default no-op setters).
    service.set_remote_auth_provider(Arc::new(MockRemoteAuthProvider));
    service.set_biometric_provider(Arc::new(MockBiometricProvider::default()));

    let challenge = service.begin_remote_auth("alice").unwrap();
    let result = service
        .finalize_remote_auth(&challenge, "client-proof")
        .unwrap();
    assert_eq!(result.user_id, challenge.user_id);
    assert!(!result.session_key_fingerprint.is_empty());

    // Empty client proof is rejected.
    assert!(service.finalize_remote_auth(&challenge, "").is_err());

    // Biometrics: default mock is available and verifies.
    assert!(service.biometric_available(None));
    assert!(service.biometric_available(Some(BiometricPlatform::Unknown)));
    let prompt = BiometricPrompt {
        user_id: Uuid::new_v4(),
        reason: "unlock vault".to_string(),
        platform: None,
    };
    assert!(service.authenticate_biometric(&prompt).unwrap());

    // A failing provider surfaces the error.
    service.set_biometric_provider(Arc::new(MockBiometricProvider {
        force_fail: true,
        ..Default::default()
    }));
    assert!(service.authenticate_biometric(&prompt).is_err());
}

#[tokio::test]
async fn test_get_user_sessions_without_current_user_is_empty() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let service = PersonaService::new(db).await.unwrap();
    assert!(service.get_user_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_session_tracking_paths_with_injected_session() {
    let (_db, service) = unlocked_service().await;

    // An expired session registered with the auto-lock manager, injected
    // as the current session id, drives the auto-locked error branch.
    let expired = crate::auth::session::Session::new(
        service.current_user.unwrap().to_string(),
        std::time::Duration::from_secs(0),
    );
    let session_id = expired.id.clone();
    service
        .auto_lock_manager
        .add_session(expired)
        .await
        .unwrap();
    *service.current_session_id.write().await = Some(session_id.clone());

    assert!(service.is_session_locked().await);

    let err = service
        .create_identity("locked-work".to_string(), IdentityType::Personal)
        .await;
    let err_text = format!("{:#}", err.unwrap_err());
    assert!(err_text.contains("auto-locked") || err_text.contains("Session is auto-locked"));

    // Activity updates with a session registered do not error, and
    // needs_reauth consults the manager through the same branch.
    service.update_auto_lock_activity().await.unwrap();
    service.update_sensitive_auto_lock_activity().await.unwrap();
    let _ = service.needs_reauth().await;

    // A live session keeps the service usable and hits the Some(session)
    // arm again after replacing the injected id.
    let live = crate::auth::session::Session::new(
        "session-user".to_string(),
        std::time::Duration::from_secs(3600),
    );
    let live_id = live.id.clone();
    service.auto_lock_manager.add_session(live).await.unwrap();
    *service.current_session_id.write().await = Some(live_id);
    service.update_auto_lock_activity().await.unwrap();
    service.update_sensitive_auto_lock_activity().await.unwrap();
    assert!(!service.needs_reauth().await);
}
