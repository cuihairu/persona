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

// ---------------------------------------------------------------------------
// 第二批：credential / wallet / reveal / export / passkey
// ---------------------------------------------------------------------------

/// 建一个已初始化服务的 app + 一条已存在的身份，返回 (app, identity_id)。
async fn app_with_identity() -> (tauri::App<tauri::test::MockRuntime>, String) {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Cred Holder".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity = resp.data.expect("identity created");
    (app, identity.id)
}

fn password_credential_request(identity_id: &str) -> CreateCredentialRequest {
    CreateCredentialRequest {
        identity_id: identity_id.to_string(),
        name: "Example Login".to_string(),
        credential_type: "Password".to_string(),
        security_level: "High".to_string(),
        url: Some("https://example.com".to_string()),
        username: Some("alice".to_string()),
        notes: Some("  note with padding  ".to_string()),
        tags: Some(vec![
            "web".to_string(),
            "  ".to_string(),
            "work".to_string(),
        ]),
        credential_data: CredentialDataRequest::Password {
            password: "s3cret-password".to_string(),
            email: Some("alice@example.com".to_string()),
            security_questions: vec![SecurityQuestionRequest {
                question: "pet?".to_string(),
                answer: "cat".to_string(),
            }],
        },
    }
}

#[tokio::test]
async fn credential_commands_round_trip_search_favorite_and_totp() {
    let (app, identity_id) = app_with_identity().await;

    // Create (also normalizes notes/tags whitespace).
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");
    assert_eq!(cred.name, "Example Login");
    assert_eq!(cred.tags, vec!["web".to_string(), "work".to_string()]);
    assert_eq!(cred.notes.as_deref(), Some("note with padding"));

    // List for identity.
    let resp = get_credentials_for_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 1);

    // Decrypted data round-trips through the encrypted vault.
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Password");
    assert_eq!(data.data["password"], "s3cret-password");

    // Search by name.
    let resp = search_credentials("example".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().iter().any(|c| c.id == cred.id));

    // Toggle favorite twice: on, then off.
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_favorite);
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.unwrap().is_favorite);

    // TOTP credential: create with an RFC-vector secret and read a code.
    let mut totp_req = password_credential_request(&identity_id);
    totp_req.name = "GitHub TOTP".to_string();
    totp_req.credential_type = "TwoFactor".to_string();
    totp_req.credential_data = CredentialDataRequest::TwoFactor {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "GitHub".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };
    let resp = create_credential(totp_req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let totp_cred = resp.data.expect("totp credential created");

    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("totp code returned");
    assert_eq!(code.code.len(), 6);
    assert!(code.remaining_seconds <= 30);

    // Delete both credentials; the identity listing empties out.
    for id in [cred.id, totp_cred.id] {
        let resp = delete_credential(id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_empty());
}

#[tokio::test]
async fn wallet_commands_round_trip_generate_list_export_delete() {
    let (app, identity_id) = app_with_identity().await;

    // Empty listing before anything exists.
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().wallets.is_empty());

    // Generate an HD wallet (24-word mnemonic, 3 addresses).
    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Desktop HD".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(3),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let generated = resp.data.expect("wallet generated");
    assert_eq!(generated.mnemonic.split_whitespace().count(), 24);
    assert!(generated.first_address.starts_with("0x"));

    // Short passwords are rejected up front.
    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "short".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );

    // Listing now contains the wallet.
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallets = resp.data.unwrap().wallets;
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].id, generated.wallet_id);

    // Address listing shows the generated count.
    let resp = wallet_list_addresses(generated.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().addresses.len(), 3);

    // JSON export (no private material) succeeds.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: generated.wallet_id.clone(),
            format: "json".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let exported: serde_json::Value =
        serde_json::from_str(&resp.data.unwrap()).expect("export is valid JSON");
    assert_eq!(exported["name"], "Desktop HD");

    // Delete the wallet.
    let resp = wallet_delete(generated.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().wallets.is_empty());
}

#[tokio::test]
async fn reveal_credential_secret_round_trip_and_unknown_field() {
    let (app, identity_id) = app_with_identity().await;
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let cred = resp.data.expect("credential created");

    // The password reveals after decryption.
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred.id.clone(),
            field: "password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let reveal = resp.data.expect("reveal returned");
    assert_eq!(reveal.field, "password");
    assert_eq!(reveal.value, "s3cret-password");

    // Unknown fields are rejected with a clear message.
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred.id.clone(),
            field: "not_a_field".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "unknown field must not reveal");
}

#[tokio::test]
async fn export_identity_command_returns_exportable_json() {
    let (app, identity_id) = app_with_identity().await;

    let resp = export_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let export = resp.data.expect("export returned");
    assert!(!export.exported_at.is_empty());
    assert!(export.data.is_object(), "export payload is JSON");
}

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

// ---------------------------------------------------------------------------
// 第三批：wallet 交易 / approval respond / SSH agent 状态与生命周期
// ---------------------------------------------------------------------------

/// 沙箱 agent 状态目录：`PERSONA_AGENT_STATE_DIR` 指向 tempdir，drop 恢复。
struct StateDirGuard {
    prev: Option<std::ffi::OsString>,
}

impl StateDirGuard {
    fn sandbox(dir: &tempfile::TempDir) -> Self {
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        StateDirGuard {
            prev: prev.map(Into::into),
        }
    }
}

impl Drop for StateDirGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var("PERSONA_AGENT_STATE_DIR", prev),
            None => std::env::remove_var("PERSONA_AGENT_STATE_DIR"),
        }
    }
}

#[tokio::test]
async fn wallet_transaction_commands_round_trip_and_rejections() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Tx Wallet".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallet = resp.data.expect("wallet generated");

    // Bad UUID and unknown wallet rejections come before any DB work.
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: "not-a-uuid".to_string(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1".to_string(),
            fee: "21000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap_err();
    assert_eq!(resp, "Invalid wallet_id");

    let missing = uuid::Uuid::new_v4().to_string();
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: missing.clone(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1".to_string(),
            fee: "21000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    // Create the pending request with full gas metadata (legacy EIP-155).
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id.clone(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1000000000000000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("20000000000".to_string()),
            gas_limit: Some(21000),
            nonce: Some(0),
            memo: Some("integration".to_string()),
            expires_in_minutes: Some(30),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let tx = resp.data.expect("transaction created");
    let tx_id = tx["id"].as_str().expect("transaction id").to_string();
    assert_eq!(
        tx["to_address"],
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(tx["network"], "Ethereum");

    // The pending listing contains it.
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"].as_str(), Some(tx_id.as_str()));

    // Bad uuid / unknown transaction on the sign path.
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: "not-a-uuid".to_string(),
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap_err();
    assert_eq!(resp, "Invalid transaction_id");

    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Transaction not found"));

    // Wrong password fails key derivation without storing a signature.
    // The sign command propagates signing failures with `?`, so the caller
    // sees Err(String) rather than an ApiResponse error body.
    let err = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wrong-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("Failed to derive signing key"), "got: {err}");

    // Correct password: sign → local verify → raw assembly → stored.
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let signed = resp.data.expect("signed transaction returned");
    let hash = signed["transaction_hash"].as_str().expect("tx hash");
    assert!(
        hash.starts_with("0x") && hash.len() == 66,
        "EIP-155 hash is a 32-byte hex: {hash}"
    );
    // raw_signed_transaction is a Vec<u8>, so it arrives as a JSON array of
    // bytes — a non-empty one proves the EIP-155 assembly succeeded (the
    // audit-only fallback would leave it empty).
    assert!(
        signed["raw_signed_transaction"]
            .as_array()
            .is_some_and(|raw| !raw.is_empty()),
        "raw transaction assembled"
    );

    // Re-signing the same request reproduces the identical RFC 6979
    // deterministic signature and hash, which the store's
    // UNIQUE(transaction_hash) guard refuses to duplicate. That rejection is
    // the current dedup contract (prevents double-broadcast records).
    let err = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("Failed to store signed transaction"),
        "got: {err}"
    );
}

#[tokio::test]
async fn approval_respond_commands_resolve_and_reject_unknown() {
    let app = mock_app();

    // Unknown ids (double click, stale modal) are rejected, never approved.
    let resp = ssh_approval_respond(
        SshApprovalRespondRequest {
            request_id: "ghost".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("ghost"));

    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "ghost".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("ghost"));

    // A registered approval resolves through the oneshot with the verdict.
    let (ssh_tx, ssh_rx) = tokio::sync::oneshot::channel();
    {
        let state = app.state::<AppState>();
        state
            .ssh_approvals
            .lock()
            .unwrap()
            .insert("req-ssh".to_string(), ssh_tx);
    }
    let resp = ssh_approval_respond(
        SshApprovalRespondRequest {
            request_id: "req-ssh".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(ssh_rx.await.unwrap(), "allow verdict delivered");

    let (pk_tx, pk_rx) = tokio::sync::oneshot::channel();
    {
        let state = app.state::<AppState>();
        state
            .passkey_approvals
            .lock()
            .unwrap()
            .insert("req-pk".to_string(), pk_tx);
    }
    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "req-pk".to_string(),
            allow: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(!pk_rx.await.unwrap(), "deny verdict delivered");

    // Second answer for the same id is "unknown" (already consumed).
    let resp = passkey_approval_respond(
        PasskeyApprovalRespondRequest {
            request_id: "req-pk".to_string(),
            allow: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "double answer must not re-deliver");
}

#[tokio::test]
async fn ssh_agent_status_reflects_state_files() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);

    // No handle, no state files: not running.
    let app = mock_app();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(!status.running);
    assert_eq!(status.socket_path, None);
    assert_eq!(status.pid, None);
    assert_eq!(status.state_dir, dir.path().to_string_lossy().to_string());

    // A socket file alone flips running and surfaces the path; the fake
    // socket accepts no connection, so key_count stays None.
    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/nowhere.sock").unwrap();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert!(status.running, "socket file means running");
    assert_eq!(status.socket_path.as_deref(), Some("/tmp/nowhere.sock"));
    assert_eq!(status.key_count, None);

    // A pid file surfaces the parsed pid.
    std::fs::write(dir.path().join("ssh-agent.pid"), "424242\n").unwrap();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert_eq!(status.pid, Some(424242));
}

#[tokio::test]
async fn start_stop_ssh_agent_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);
    let app = mock_app();

    // Start before initialization: db path unknown. The command propagates
    // this failure with `?`, so the caller sees Err(String).
    let err = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        "Database path unavailable. Initialize the service first."
    );

    init_service_ok(&app, "correct-horse").await;

    // Start boots the in-process agent; status reports running.
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "agent start failed: {:?}", resp.error);
    assert!(resp.data.unwrap().running, "agent handle is alive");

    // The agent bound its socket in the sandboxed state dir.
    let sock = dir.path().join("ssh-agent.sock");
    let bound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !sock.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "agent socket never appeared at {sock:?}");

    // A second start while running returns the current status (no reboot).
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().running);

    // Stop aborts the agent and clears pending approvals.
    let resp = stop_ssh_agent(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.data.unwrap().running, "no handle and no socket left");
}
