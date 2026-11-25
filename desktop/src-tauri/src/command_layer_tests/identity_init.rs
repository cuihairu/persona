//! Command-layer integration tests — `identity_init` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// The triggerable error arms of init_service: a junk DB file is exposed by
/// migration (sqlx connections are lazy, so opening it reports nothing) and an
/// uncreatable path is exposed at connection time; after 5 consecutive wrong
/// attempts on the same vault, even the correct password only yields an
/// account lockout.
#[tokio::test]
async fn init_service_degrades_loudly_on_bad_db_and_account_lockout() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("garbage.db");
    let db_path = dir.path().join("lockout.db");
    // Leak the TempDir: the vault keeps the file open for the whole test.
    std::mem::forget(dir);

    // A junk file is not valid sqlite: the connection succeeds lazily and only migration fails.
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

    // An unopenable path (directory does not exist) -> connection failure.
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

    // A real vault: 5 failures trigger the account lockout (the 6th attempt is rejected even with the correct password).
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
/// While locked, every command that "calls the service directly" gets the
/// SERVICE_LOCKED error code (the map_persona_error -> error_with_code arm).
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

    // configure_auto_lock is still allowed while locked (core does no ensure_unlocked)
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

    // start_auto_lock_monitoring is likewise allowed while locked (core has no
    // ensure_unlocked, and the monitoring itself leaks nothing); stop is driven
    // along with it.
    let resp = start_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = stop_auto_lock_monitoring(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // health_scan (including the checker-construction branch with check_breaches=true)
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

    // The passkey family (the request first passes UUID/decode checks, so legal input reaches deep into the service)
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
            // Legal base64 client_data (the locked error fires at the service-call layer)
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

    // reveal_credential_secret (a nonexistent credential also hits ensure_unlocked first)
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
/// The db_path=None default branch of init_service: it lands under the
/// persona/ subdirectory of the XDG data directory, not the real user
/// directory.
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

    // With a bad db, authenticate_user cannot find the user table -> Err -> map_persona_error routes it.
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

    // The public configuration API opens the gate: a 1-second sensitive window. Before the fix this switch only touched a copy of the timeout
    // the manager never saw — the gate never took effect.
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

    // reauth_verify (authenticate_user) builds a session and records the login
    // itself as a sensitive verification -> a freshly authenticated user passes
    // the gate straight through.
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

    // After the window: the dedicated error code REAUTH_REQUIRED (routed so the frontend pops the re-auth modal).
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

    // Re-authenticating -> release resumes.
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

    // Lock the session to simulate the "next unlock" scenario; the flag short-circuit happens before password verification
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Set via the repository (production sets it inside core's policy engine;
    // here the store is driven directly), only verifying that the command layer
    // translates AuthResult::PasswordChangeRequired into a machine-readable code
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
    // force_fail provider: the default Mock always passes — if the injection
    // takes effect, the service layer's authenticate_biometric must fail
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
