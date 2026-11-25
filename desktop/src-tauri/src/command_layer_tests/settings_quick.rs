//! Command-layer integration tests — `settings_quick` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// Uninitialized database: status hits the "missing db_path" error instead of panicking
#[tokio::test]
async fn quick_access_status_requires_initialized_service() {
    let app = mock_app();
    let resp = quick_access_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .is_some_and(|e| e.contains("Database path unavailable")));
}
/// Writing the config passes the unlock gate (like set_locale / set_feature_flags); reading status needs no unlock
#[tokio::test]
async fn quick_access_set_requires_unlocked_service() {
    let app = mock_app();

    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "master-pw-123").await;

    // Locked: reads still work (the settings page has to show whether the hotkey actually took effect); writes are refused
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = quick_access_status(app.state::<AppState>()).await.unwrap();
    assert!(
        resp.success,
        "status must work while locked: {:?}",
        resp.error
    );

    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    // Writes in the locked state must not land in the DB
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.expect("settings").quick_access_hotkey.is_none());
}
/// Default tier (off by default since 2026-09-28): the switch is off and the binding
/// falls back to the platform default; once explicitly enabled, the test environment (mock
/// context) has no quick-access overlay, so registration necessarily fails -> registered is
/// empty but carries a reason (exactly the surface the settings page displays)
#[tokio::test]
async fn quick_access_status_reports_defaults_and_missing_registration() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // Off by default: a fresh install / missing key registers no global hotkey, registered is empty, no error
    let resp = quick_access_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(!status.enabled, "全局热键默认关闭（与云备份同口径）");
    assert!(status.registered_accelerator.is_none());
    assert!(status.error.is_none(), "默认关不是失败，不带原因");

    // Only after explicit enablement (the settings page switch) does the "registration failed" surface appear
    let resp = quick_access_set(app.handle().clone(), true, None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(status.enabled);
    assert_eq!(
        status.configured_accelerator,
        crate::quick_access::default_accelerator()
    );
    assert!(status.registered_accelerator.is_none());
    assert!(status.error.is_some(), "未生效必须带原因，不能静默");

    // The runtime state was really recorded (unlock's apply_quick_access goes through the same path)
    let state = app.state::<AppState>();
    let runtime = state.quick_access.lock().unwrap();
    assert!(runtime.registered.is_none());
    assert!(runtime.last_error.is_some());
}
/// Rebinding persists to the DB and reads back (the DB is the source of truth); an invalid accelerator does **not** land in the DB
#[tokio::test]
async fn quick_access_set_persists_binding_and_rejects_invalid() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert_eq!(status.configured_accelerator, "Control+Alt+K");

    // Persist and read back
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.data.expect("settings").quick_access_hotkey.as_deref(),
        Some("Control+Alt+K")
    );

    // Invalid string: the command fails and the DB is untouched
    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("Ctrl+".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.data.expect("settings").quick_access_hotkey.as_deref(),
        Some("Control+Alt+K"),
        "非法加速键不得覆盖已落库的绑定"
    );
}
/// Switching off + a blank string restores the default: hotkey is stored back as None (the default value is not pinned into the DB)
#[tokio::test]
async fn quick_access_set_disable_and_reset_default() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    quick_access_set(
        app.handle().clone(),
        false,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("   ".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(status.enabled);
    assert_eq!(
        status.configured_accelerator,
        crate::quick_access::default_accelerator()
    );

    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings");
    assert!(settings.quick_access_enabled);
    assert!(settings.quick_access_hotkey.is_none());
}
/// After switching off, the runtime state must not retain "registered" (otherwise the UI would display a binding that has actually lapsed)
#[tokio::test]
async fn quick_access_set_disable_clears_registered_state() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // First hand-set a "previously registered successfully" runtime state, simulating the in-process state before rebinding
    {
        let state = app.state::<AppState>();
        let mut runtime = state.quick_access.lock().unwrap();
        runtime.registered = Some("Control+Alt+K".to_string());
    }

    let resp = quick_access_set(
        app.handle().clone(),
        false,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(!status.enabled);
    assert!(status.registered_accelerator.is_none());

    let state = app.state::<AppState>();
    let runtime = state.quick_access.lock().unwrap();
    assert!(runtime.registered.is_none());
}
/// Uninitialized database: status hits the "missing db_path" error instead of panicking (same cause as quick_access)
#[tokio::test]
async fn generator_status_requires_initialized_service() {
    let app = mock_app();
    let resp = generator_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .is_some_and(|e| e.contains("Database path unavailable")));
}
/// Writing the config passes the unlock gate (reads need no unlock); writes in the locked state must not land in the DB
#[tokio::test]
async fn generator_set_requires_unlocked_service() {
    let app = mock_app();

    let resp = generator_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+G".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "master-pw-123").await;

    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = generator_status(app.state::<AppState>()).await.unwrap();
    assert!(
        resp.success,
        "status must work while locked: {:?}",
        resp.error
    );

    let resp = generator_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+G".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp
        .data
        .expect("settings")
        .generator_panel_hotkey
        .is_none());
}
/// Off by default; once explicitly enabled the mock context has no generator-panel overlay ->
/// registration necessarily fails and carries a reason. **Changing the search binding must not
/// touch the generator slot** (independent runtime state)
#[tokio::test]
async fn generator_status_reports_defaults_and_missing_registration() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    let resp = generator_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(
        !status.enabled,
        "生成器热键默认关闭（与 Quick Access 同口径）"
    );
    assert!(status.registered_accelerator.is_none());
    assert!(status.error.is_none(), "默认关不是失败，不带原因");

    let resp = generator_set(app.handle().clone(), true, None, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(status.enabled);
    assert_eq!(
        status.configured_accelerator,
        crate::quick_access::default_generator_accelerator()
    );
    assert!(status.registered_accelerator.is_none());
    assert!(status.error.is_some(), "未生效必须带原因，不能静默");

    let state = app.state::<AppState>();
    let runtime = state.quick_access.lock().unwrap();
    assert!(runtime.generator_registered.is_none());
    assert!(runtime.generator_last_error.is_some());
}
/// Rebinding persists and reads back; invalid accelerators do not land in the DB; no cross-effects with the search binding
#[tokio::test]
async fn generator_set_persists_binding_and_rejects_invalid() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    let resp = generator_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+G".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert_eq!(status.configured_accelerator, "Control+Alt+G");

    // Persist and read back
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.data
            .expect("settings")
            .generator_panel_hotkey
            .as_deref(),
        Some("Control+Alt+G")
    );

    // After writing the search binding, neither the generator's DB value nor its runtime slot gets carried along
    let resp = quick_access_set(
        app.handle().clone(),
        true,
        Some("Control+Alt+K".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings");
    assert_eq!(
        settings.generator_panel_hotkey.as_deref(),
        Some("Control+Alt+G"),
        "检索改绑不得动生成器落库值"
    );
    assert_eq!(
        settings.quick_access_hotkey.as_deref(),
        Some("Control+Alt+K")
    );
    let state = app.state::<AppState>();
    // The lock's scope ends at the end of the block: there are more awaits later (clippy::await_holding_lock)
    {
        let runtime = state.quick_access.lock().unwrap();
        assert!(runtime.generator_last_error.is_some());
        assert!(
            runtime.last_error.is_some(),
            "两条绑定各自带自己的抢注失败原因"
        );
    }

    // Invalid string: the command fails and the DB is untouched
    let resp = generator_set(
        app.handle().clone(),
        true,
        Some("Ctrl+".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.data
            .expect("settings")
            .generator_panel_hotkey
            .as_deref(),
        Some("Control+Alt+G"),
        "非法加速键不得覆盖已落库的绑定"
    );
}
/// Switching off + a blank string restores the default: hotkey is stored back as None (the default value is not pinned into the DB)
#[tokio::test]
async fn generator_set_disable_and_reset_default() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    generator_set(
        app.handle().clone(),
        false,
        Some("Control+Alt+G".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let resp = generator_set(
        app.handle().clone(),
        true,
        Some("   ".to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(status.enabled);
    assert_eq!(
        status.configured_accelerator,
        crate::quick_access::default_generator_accelerator()
    );

    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings");
    assert!(settings.generator_panel_enabled);
    assert!(settings.generator_panel_hotkey.is_none());
}
/// Input validation for cross-window jumps: an invalid UUID is rejected outright (the main window receiving a bad id would only silently skip selection)
#[tokio::test]
async fn quick_access_open_credential_rejects_invalid_uuid() {
    let app = mock_app();
    let resp = quick_access_open_credential(
        QuickAccessOpenCredentialRequest {
            identity_id: "not-a-uuid".to_string(),
            credential_id: uuid::Uuid::new_v4().to_string(),
        },
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // Main window absent (mock context has no windows) -> an explicit error, not silence
    let resp = quick_access_open_credential(
        QuickAccessOpenCredentialRequest {
            identity_id: uuid::Uuid::new_v4().to_string(),
            credential_id: uuid::Uuid::new_v4().to_string(),
        },
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Main window unavailable"));
}
#[tokio::test]
async fn report_frontend_error_never_fails_on_any_input_shape() {
    // The reporting path never fails: empty arguments
    let resp = report_frontend_error(String::new(), None, None);
    assert!(resp.success);

    // Regular arguments
    let resp = report_frontend_error(
        "boom".to_string(),
        Some("at Foo (bar.tsx:1)".to_string()),
        Some("in ErrorBoundary".to_string()),
    );
    assert!(resp.success);

    // Overlong field (> 8 KiB, with multi-byte characters): truncates on a char boundary without panicking
    let long_message = "错".repeat(10_000);
    let long_stack = "x".repeat(50_000);
    let resp = report_frontend_error(long_message, Some(long_stack), None);
    assert!(resp.success);
}
