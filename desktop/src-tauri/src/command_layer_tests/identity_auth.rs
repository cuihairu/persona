//! Command-layer integration tests — `identity_auth` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn auto_lock_commands_configure_status_and_monitoring() {
    let app = mock_app();

    // Monitoring without a service reports the failure.
    let resp = start_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // Configure a 300s inactivity timeout with an absolute cap.
    let resp = configure_auto_lock(
        AutoLockConfigRequest {
            inactivity_timeout_secs: 300,
            absolute_timeout_secs: Some(3600),
            require_reauth_sensitive: Some(true),
            sensitive_operation_timeout_secs: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_auto_lock_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status returned");
    assert_eq!(status.inactivity_timeout_secs, 300);

    // Touch + monitoring lifecycle all succeed once a session exists.
    let resp = touch_activity(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = start_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = stop_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
#[tokio::test]
async fn audit_commands_return_empty_results_for_fresh_vault() {
    let app = mock_app();

    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // init itself writes audit events, so the query path must return rows
    // and the statistics must be consistent with them.
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: Some(50),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let logs = resp.data.expect("logs returned");
    assert!(!logs.is_empty(), "init writes audit events; got none");

    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let stats = resp.data.expect("stats returned");
    assert!(
        stats.total_logs > 0,
        "statistics reflect the init events: {stats:?}"
    );

    // Failures-only filter starts empty on a healthy vault.
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: Some(true),
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty(), "no failures recorded yet");

    // Retaining 30 days keeps the fresh init events; the command reports
    // the (zero) number of rows it deleted.
    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// Audit query filter branches + init_service re-routing the sole workspace to a new path.
#[tokio::test]
async fn audit_query_filters_and_workspace_repath() {
    let (app, _identity_id) = app_with_identity().await;

    // A legal action filter (empty result).
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: Some("login".to_string()),
            failures_only: Some(true),
            security_sensitive_only: None,
            time_range: None,
            limit: Some(10),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());

    // AuditAction::from_str maps unknown actions to Custom and never fails, so
    // build_audit_query's "Unknown audit action" branch is purely defensive dead
    // code.
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: Some("NotAnAction".to_string()),
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "custom action accepted: {:?}", resp.error);

    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: Some("bad-uuid".to_string()),
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid identity_id"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: Some(("not-a-date".to_string(), "2026-01-01T00:00:00Z".to_string())),
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid time_range start"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    // Workspace re-routing: move the tempdir to a new path and then init; the
    // only workspace in the db (pointing at the old path) gets re-routed to the
    // new path (the ensure_workspace_for_path branch).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("repath.db");
    std::mem::forget(dir);
    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "first init failed: {:?}", resp.error);

    let old_path = std::path::PathBuf::from(&db_path);
    // Move it to a sibling directory under /tmp (it cannot be moved inside itself: EINVAL).
    let new_dir = std::env::temp_dir().join(format!("persona-repath-{}", uuid::Uuid::new_v4()));
    std::fs::rename(old_path.parent().unwrap(), &new_dir).unwrap();
    let new_db = new_dir.join("repath.db");

    let resp = init_service(
        InitRequest {
            master_password: "correct-horse".to_string(),
            db_path: Some(new_db.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "repath init failed: {:?}", resp.error);
}
/// The mapping and serde tags of `SerializableAutoLockEvent`'s four variants.
#[test]
fn serializable_auto_lock_event_variants() {
    use persona_core::auth::LockReason;

    let events = vec![
        persona_core::auth::AutoLockEvent::LockPending {
            session_id: "s1".to_string(),
            seconds_remaining: 30,
        },
        persona_core::auth::AutoLockEvent::Locked {
            session_id: "s1".to_string(),
            reason: LockReason::Inactivity,
        },
        persona_core::auth::AutoLockEvent::Unlocked {
            session_id: "s2".to_string(),
        },
        persona_core::auth::AutoLockEvent::Activity {
            session_id: "s3".to_string(),
        },
    ];

    let tags: Vec<String> = events
        .into_iter()
        .map(|e| {
            let value = serde_json::to_value(SerializableAutoLockEvent::from(e)).unwrap();
            value["type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(tags, ["lock_pending", "locked", "unlocked", "activity"]);

    let locked = serde_json::to_value(SerializableAutoLockEvent::from(
        persona_core::auth::AutoLockEvent::Locked {
            session_id: "s1".to_string(),
            reason: LockReason::Inactivity,
        },
    ))
    .unwrap();
    // reason goes through Debug formatting (the enum name), session passes through.
    assert_eq!(locked["session_id"], "s1");
    assert_eq!(locked["reason"], "Inactivity");

    let pending = serde_json::to_value(SerializableAutoLockEvent::from(
        persona_core::auth::AutoLockEvent::LockPending {
            session_id: "s1".to_string(),
            seconds_remaining: 30,
        },
    ))
    .unwrap();
    assert_eq!(pending["seconds_remaining"], 30);
}
/// `From<AuditLog>`: optional identity/credential ids become strings, and action and resource types are made human-readable.
#[test]
fn serializable_audit_log_maps_option_ids() {
    use persona_core::models::{AuditAction, ResourceType};

    let log = persona_core::models::AuditLog {
        id: uuid::Uuid::new_v4(),
        user_id: Some("user-1".to_string()),
        identity_id: Some(uuid::Uuid::new_v4()),
        credential_id: Some(uuid::Uuid::new_v4()),
        session_id: Some("sess".to_string()),
        action: AuditAction::IdentityCreated,
        resource_type: ResourceType::Identity,
        resource_id: Some("res-1".to_string()),
        ip_address: None,
        user_agent: None,
        success: true,
        error_message: None,
        metadata: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };

    let json = serde_json::to_value(SerializableAuditLog::from(log)).unwrap();
    assert_eq!(json["user_id"], "user-1");
    assert!(json["identity_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(json["credential_id"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    // Action and resource types serialize as snake_case (symmetric with AuditAction::from_str).
    assert_eq!(json["action"], "identity_created");
    assert_eq!(json["resource_type"], "identity");
    assert_eq!(json["success"], true);
}
/// The auto-lock event bridge closed loop: once the Locked event fires, the
/// callback emits the event and, in a background task, forces `service.lock()`
/// to wipe the in-memory master key (not depending on the frontend being
/// alive).
#[tokio::test]
async fn auto_lock_event_bridge_force_locks_on_locked_event() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    // init_service has registered the bridge callback.

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true), "fresh init must be unlocked");

    {
        let state = app.state::<AppState>();
        let mut guard = state.service.lock().await;
        let service = guard.as_mut().expect("service initialized");

        // The first init only calls initialize_user and does not create an
        // auto-lock session (real product behavior: the session is created at
        // authentication time); run one lock -> authenticate to create the
        // session, matching the frontend's real "init -> lock -> unlock again"
        // chain.
        service.lock();
        let result = service.authenticate_user("correct-horse").await.unwrap();
        assert!(matches!(result, persona_core::AuthResult::Success));

        // Trigger the Locked event manually via the public API (the same emit
        // path as the timeout monitor, without waiting for a real timer).
        service.force_lock_session().await.expect("force lock");
    }

    // The callback runs asynchronously: poll until the forced lock takes effect.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
        if resp.data == Some(false) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bridge never force-locked the service after a Locked event"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
#[tokio::test]
async fn audit_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();

    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: Some(50),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "audit query must fail on a dead db");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );

    let resp = audit_statistics(state.clone()).await.unwrap();
    assert!(!resp.success, "audit stats must fail on a dead db");

    let resp = audit_cleanup(30, state).await.unwrap();
    assert!(!resp.success, "audit cleanup must fail on a dead db");
}
#[tokio::test]
async fn auto_lock_and_reauth_commands_require_initialized_service() {
    let app = mock_app();
    let state = app.state::<AppState>();
    let expect_uninit = |resp: &ApiResponse<bool>| {
        assert_eq!(
            resp.error.as_deref(),
            Some("Service not initialized"),
            "got: {:?}",
            resp.error
        );
        assert!(!resp.success);
    };

    let resp = configure_auto_lock(
        AutoLockConfigRequest {
            inactivity_timeout_secs: 900,
            absolute_timeout_secs: None,
            require_reauth_sensitive: None,
            sensitive_operation_timeout_secs: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    expect_uninit(&resp);

    let resp = start_auto_lock_monitoring(state.clone()).await.unwrap();
    expect_uninit(&resp);

    let resp = stop_auto_lock_monitoring(state.clone()).await.unwrap();
    expect_uninit(&resp);

    let resp = reauth_verify(
        ReauthRequest {
            master_password: "whatever".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    expect_uninit(&resp);

    let resp = touch_activity(state).await.unwrap();
    expect_uninit(&resp);
}
#[tokio::test]
async fn change_master_password_command_rotates_and_allows_reinit() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "old-master-pw").await;

    // Rotation while locked: the command builds a fresh service itself
    // (state.service stays None / the old instance is untouched), and the
    // frontend then re-inits with the new password
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = change_master_password(
        ChangeMasterPasswordRequest {
            old_password: "old-master-pw".to_string(),
            new_password: "new-master-pw".to_string(),
            db_path: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));

    // The old password is rejected from now on
    let resp = init_service(
        InitRequest {
            master_password: "old-master-pw".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));

    // The new password init succeeds and the service is unlocked (the session is created as usual)
    let resp = init_service(
        InitRequest {
            master_password: "new-master-pw".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true), "post-rotation init must unlock");
}
#[tokio::test]
async fn change_master_password_command_rejects_wrong_old_password() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "real-master-pw").await;

    let resp = change_master_password(
        ChangeMasterPasswordRequest {
            old_password: "wrong-master-pw".to_string(),
            new_password: "new-master-pw".to_string(),
            db_path: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let msg = resp.error.as_deref().expect("error message present");
    assert!(
        msg.contains("Invalid current master password"),
        "unexpected error: {msg}"
    );

    // A failed attempt must not corrupt the vault: the real password still creates a session
    let resp = init_service(
        InitRequest {
            master_password: "real-master-pw".to_string(),
            db_path: Some(db_path),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
#[tokio::test]
async fn set_password_expiry_narrow_write_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // A brand-new vault: no expiry by default
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("settings present");
    assert_eq!(settings.password_expiry_days, None);

    // A narrow write of 90 days; the other fields in the returned full settings are not clobbered
    let resp = set_password_expiry(Some(90), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("updated settings returned");
    assert_eq!(settings.password_expiry_days, Some(90));
    assert!(settings.encryption_enabled);
    assert_eq!(settings.session_timeout_seconds, 3600);

    // No interference with the features bits (the two narrow-write paths share one settings row)
    let resp = set_feature_flags(
        true,
        false,
        false,
        false,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("updated settings returned");
    assert!(settings.features.ssh_agent);
    assert_eq!(settings.password_expiry_days, Some(90));

    let resp = set_password_expiry(None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("updated settings returned");
    assert_eq!(settings.password_expiry_days, None);
    assert!(
        settings.features.ssh_agent,
        "expiry write must not clobber features"
    );

    // Some(0) is meaningless and explicitly rejected
    let resp = set_password_expiry(Some(0), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Password expiry must be at least 1 day")
    );
}
#[tokio::test]
async fn change_master_password_updates_biometric_entry() {
    let store = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(mock_provider(true, false), store.clone());
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
    // The escrow entry is updated in lockstep with the password change
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("new-password")
    );

    // Closed loop: biometric unlock succeeds with the new escrow entry
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = biometric_unlock(
        BiometricUnlockRequest { db_path: None },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
#[tokio::test]
async fn change_master_password_deletes_entry_when_keyring_write_fails() {
    let inner = Arc::new(InMemoryTokenStore::default());
    let app = mock_app_with_biometric(
        mock_provider(true, false),
        Arc::new(FailingSetStore(inner.clone())),
    );
    let db_path = init_service_ok(&app, "old-password").await;
    // A pre-planted entry (bypassing the injected FailingSetStore.set): the coupled write fails after a successful password change
    inner.set(&db_path, "old-password").unwrap();

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
    // fail-closed: a failed write -> delete the entry (better to re-enable than keep a bad entry)
    assert_eq!(inner.get(&db_path).unwrap(), None);
}
