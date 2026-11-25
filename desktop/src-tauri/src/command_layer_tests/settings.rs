//! Command-layer integration tests — `settings` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn workspace_settings_round_trip_through_get_and_set_feature_flags() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // A brand-new vault: flags are all off by default, the remaining fields keep the core defaults
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("settings present");
    assert!(!settings.features.ssh_agent);
    assert!(!settings.features.wallet);
    assert!(!settings.features.passkeys);
    assert!(!settings.features.fetch_favicons);
    assert!(settings.encryption_enabled);
    assert_eq!(settings.session_timeout_seconds, 3600);

    // A narrow write of features, returning the full updated settings
    let resp = set_feature_flags(
        true,
        true,
        true,
        true,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("updated settings returned");
    assert!(settings.features.ssh_agent);
    assert!(settings.features.wallet);
    assert!(settings.features.passkeys);
    assert!(settings.features.fetch_favicons);

    // get reflects the persisted result
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.features.ssh_agent);

    // Partial enablement: only the four feature bits change
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
    let settings = resp.data.expect("updated settings returned");
    assert!(settings.features.ssh_agent);
    assert!(!settings.features.wallet);
    assert!(!settings.features.passkeys);
    assert!(!settings.features.fetch_favicons);
}
#[tokio::test]
async fn set_feature_flags_requires_unlocked_service() {
    let app = mock_app();

    // Not initialized: set is rejected
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
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "master-pw-123").await;

    // get has no unlock requirement (the unlock screen must also tailor its UI to the flags); set requires being unlocked
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "get must work while locked: {:?}", resp.error);

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
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
/// The switch coupling of set_feature_flags: turning passkeys on pulls up the
/// approval server in this very session (no longer waiting for lock->unlock);
/// turning passkeys off sends the shutdown signal, resets the idempotency flag,
/// and drops any leftover approvals; turning ssh_agent off stops a running agent.
#[tokio::test]
async fn set_feature_flags_toggles_passkey_server_and_ssh_agent_lifecycle() {
    use std::sync::atomic::Ordering;

    // The coupled startup really spawns the server and binds a real socket: redirect the agent state dir
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Turn on passkeys + ssh_agent: pulled up immediately (a fresh vault has everything off by default, so prev is all false)
    let resp = set_feature_flags(
        true,
        false,
        true,
        false,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(
        state.passkey_server_started.load(Ordering::SeqCst),
        "enabling passkeys must start the approval server in-session"
    );
    assert!(
        state.passkey_server_shutdown.lock().await.is_some(),
        "shutdown sender must be stored for the started server"
    );

    // Manufacture leftover state: one unanswered approval + one running agent handle + confirm env
    let (stale_tx, _stale_rx) = tokio::sync::oneshot::channel();
    state
        .passkey_approvals
        .lock()
        .unwrap()
        .insert("passkey-stale".to_string(), stale_tx);
    let (ssh_tx, _ssh_rx) = tokio::sync::oneshot::channel();
    state
        .ssh_approvals
        .lock()
        .unwrap()
        .insert("ssh-stale".to_string(), ssh_tx);
    let agent_task = tauri::async_runtime::spawn(std::future::pending::<()>());
    *state.agent_handle.lock().await = Some(agent_task);
    std::env::set_var("PERSONA_AGENT_REQUIRE_CONFIRM", "1");

    // Turn off passkeys + ssh_agent: the coupled stop
    let resp = set_feature_flags(
        false,
        false,
        false,
        false,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(
        !state.passkey_server_started.load(Ordering::SeqCst),
        "disabling passkeys must reset the started marker (re-enable works)"
    );
    assert!(
        state.passkey_server_shutdown.lock().await.is_none(),
        "shutdown sender must be consumed exactly once"
    );
    assert!(
        state.passkey_approvals.lock().unwrap().is_empty(),
        "stale passkey approvals must be dropped with the server"
    );
    assert!(
        state.ssh_approvals.lock().unwrap().is_empty(),
        "stale SSH approvals must be dropped with the agent"
    );
    assert!(
        state.agent_handle.lock().await.is_none(),
        "disabling ssh_agent must abort the running agent"
    );
    assert_eq!(
        std::env::var("PERSONA_AGENT_REQUIRE_CONFIRM").ok(),
        None::<String>,
        "confirm env must be cleared with the agent"
    );
}
#[tokio::test]
async fn workspace_settings_commands_fail_without_db_path() {
    let app = mock_app();

    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );

    // set is rejected first, at the unlock check (Service not initialized)
    let resp = set_feature_flags(
        true,
        true,
        true,
        true,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // The token existence query needs db_path as well
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
}
#[tokio::test]
async fn favicon_commands_gate_on_service_state_and_flag() {
    let app = mock_app();

    // Not initialized: fetch reports an error, get silently returns an empty array
    let resp = fetch_credential_favicon(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = get_favicons(vec!["a.com".to_string()], app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());

    // Locked: fetch reports the lock, get silently returns an empty array
    init_service_ok(&app, "master-pw-123").await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = fetch_credential_favicon(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = get_favicons(vec!["a.com".to_string()], app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());

    // Unlocked but the flag is off (default): fetch is rejected by the backend's backstop, get silently returns an empty array
    init_service_ok(&app, "master-pw-123").await;
    let resp = fetch_credential_favicon(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Favicon fetching is disabled in settings")
    );
    let resp = get_favicons(vec!["a.com".to_string()], app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());
}
#[tokio::test]
async fn favicon_commands_validate_input_and_read_cache_locally_when_flag_enabled() {
    let (app, identity_id) = app_with_identity().await;

    // Hiding the button while the flag is off is not enough — here the backend is explicitly turned on before the later cases are allowed
    let resp = set_feature_flags(
        false,
        false,
        false,
        true,
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Bad UUID -> Invalid UUID format (parameter validation only happens after the flag check passes)
    let resp = fetch_credential_favicon("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // Flag on + a credential without a url -> rejected (never contacts the outside)
    let mut req = password_credential_request(&identity_id);
    req.url = None;
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let no_url_cred = resp.data.expect("credential created");
    let resp = fetch_credential_favicon(no_url_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("no url")),
        "got: {:?}",
        resp.error
    );

    // The bulk read with the flag on is purely local: empty hosts / an uncached host both return success + an empty array
    let resp = get_favicons(Vec::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());
    let resp = get_favicons(
        vec!["A.COM".to_string(), "  ".to_string()],
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_empty());
}
#[tokio::test]
async fn set_locale_rejects_bad_values_and_gates_on_lock() {
    let app = mock_app();

    // An invalid locale is rejected first (no initialization needed — parameter validation precedes the unlock gate)
    let resp = set_locale("fr".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Unsupported locale: fr"));

    // Not initialized: Service not initialized
    let resp = set_locale("en".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // Initialized but locked: Service is locked
    init_service_ok(&app, "correct-horse").await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = set_locale("en".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
#[tokio::test]
async fn set_locale_round_trips_zh_cn_and_en() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    for locale in ["zh-CN", "en"] {
        let resp = set_locale(locale.to_string(), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{locale}: {:?}", resp.error);
        let settings = resp.data.expect("updated settings");
        assert_eq!(settings.locale.as_deref(), Some(locale));

        // get reflects the persisted result (a fresh connection reads the db, not an in-process cache)
        let resp = get_workspace_settings(app.state::<AppState>())
            .await
            .unwrap();
        let settings = resp.data.expect("settings");
        assert_eq!(settings.locale.as_deref(), Some(locale));
    }
}
#[tokio::test]
async fn set_tray_locale_is_harmless_noop_without_tray() {
    let app = mock_app();

    // No tray in the test environment (tray_by_id finds nothing): it must report
    // success, not an error — running in degraded mode must not turn the language
    // switch red
    let labels = crate::TrayLocaleLabels {
        open: "Open Persona".to_string(),
        quick_access: "Quick Access".to_string(),
        generator: "Password Generator".to_string(),
        lock: "Lock".to_string(),
        quit: "Quit".to_string(),
    };
    let resp = set_tray_locale(labels, app.handle().clone());
    assert!(resp.success);
    assert_eq!(resp.data, Some(true));
}
/// `set_account_binding`: writes the vault JSON (directly readable from
/// get_workspace_settings); None unbinds; a locked account is rejected.
#[tokio::test]
async fn set_account_binding_round_trips_through_workspace_settings() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    let binding = persona_core::models::workspace::AccountBinding {
        account_id: "acct-1".to_string(),
        username: "alice@example.com".to_string(),
        device_name: Some("laptop".to_string()),
    };
    let resp = set_account_binding(Some(binding.clone()), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().account, Some(binding.clone()));

    let resp = get_workspace_settings(state.clone()).await.unwrap();
    assert_eq!(resp.data.unwrap().account, Some(binding.clone()));

    // Unbind
    let resp = set_account_binding(None, state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().account, None);

    // Rejected when locked
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = set_account_binding(Some(binding), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
