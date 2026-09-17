//! Command-level integration tests.
//!
//! The `#[command]` handlers are plain async functions, so each test drives
//! them directly: a `tauri::test::mock_app()` supplies `State<'_, AppState>`
//! (via `manage`) and `AppHandle`, and the database is a per-test temp file.
//! The `sqlite_works_after_mock_app_creation` probe in main.rs guards the
//! mock-runtime/sqlx interaction this relies on.

use crate::commands::*;
use crate::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;

/// Mock app with a fresh, uninitialized `AppState`.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    let app = tauri::test::mock_app();
    app.manage(AppState {
        service: Arc::new(Mutex::new(None)),
        db_path: Mutex::new(None),
        agent_handle: Mutex::new(None),
        auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
        ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
        passkey_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
    });
    app
}

/// Initialize the service against a fresh temp database and return the guard.
async fn init_service_ok(app: &tauri::App<tauri::test::MockRuntime>, password: &str) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cmd.db");
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);

    let resp = init_service(
        InitRequest {
            master_password: password.to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "init failed: {:?}", resp.error);
}

#[tokio::test]
async fn service_lifecycle_through_init_reauth_and_lock() {
    let app = mock_app();

    // Before initialization the service-dependent commands degrade loudly.
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(false));

    // First-time init creates the user and leaves the service unlocked.
    init_service_ok(&app, "correct-horse").await;
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true), "fresh init must be unlocked");

    // Re-init against the same vault with a wrong password is rejected.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("reinit.db");
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
    assert!(resp.success, "re-init with the right password succeeds");
    let resp = init_service(
        InitRequest {
            master_password: "wrong-password".to_string(),
            db_path: Some(db_path.to_string_lossy().to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));

    // Lock, then re-auth: wrong password rejected, right one restores.
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "locked after lock_service");

    let resp = reauth_verify(
        ReauthRequest {
            master_password: "wrong-password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid master password"));

    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "correct re-auth failed: {:?}", resp.error);
}

#[tokio::test]
async fn identity_crud_commands_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // Create.
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "work".to_string(),
            description: Some("day job".to_string()),
            email: Some("work@example.com".to_string()),
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("created identity returned");
    assert_eq!(created.name, "Work");

    // List + get.
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().iter().any(|i| i.id == created.id));

    let resp = get_identity(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().map(|i| i.name), Some("Work".to_string()));

    // Update (name + tags).
    let resp = update_identity(
        UpdateIdentityRequest {
            id: created.id.clone(),
            name: "Work (renamed)".to_string(),
            identity_type: "work".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: Some(vec!["ops".to_string()]),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let updated = resp.data.expect("updated identity returned");
    assert_eq!(updated.name, "Work (renamed)");
    assert_eq!(updated.tags, vec!["ops".to_string()]);

    // Delete + confirm gone.
    let resp = delete_identity(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = get_identity(created.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_none(), "deleted identity is gone");
}

#[tokio::test]
async fn identity_commands_reject_bad_uuids_and_missing_service() {
    let app = mock_app();

    // Without a service every identity command fails closed.
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // Malformed ids never reach the repository.
    let resp = get_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid UUID format"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = delete_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Invalid UUID format"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    // A well-formed id that does not exist is a clean None, not an error.
    let missing = uuid::Uuid::new_v4().to_string();
    let resp = get_identity(missing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_none());
    let resp = update_identity(
        UpdateIdentityRequest {
            id: missing,
            name: "ghost".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "updating a missing identity must fail");
}

#[tokio::test]
async fn active_identity_commands_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // Initially nothing is active (fresh workspace row).
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(
        resp.data,
        Some(None),
        "fresh workspace has no active identity"
    );

    // Create an identity and activate it.
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Solo".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity = resp.data.expect("created identity");
    let identity_id = identity.id.clone();

    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(Some(identity_id.clone())));

    // Clear returns to the empty state.
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(None));
}

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

#[tokio::test]
async fn generate_password_and_statistics_serve_values() {
    let app = mock_app();

    let resp = generate_password(16, true, app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    let resp = generate_password(16, true, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 16);

    let resp = get_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let stats = resp.data.expect("statistics returned");
    assert!(stats.is_object(), "statistics is a JSON object: {stats}");
}
