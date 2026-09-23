//! Command-level integration tests.
//!
//! The `#[command]` handlers are plain async functions, so each test drives
//! them directly: a `tauri::test::mock_app()` supplies `State<'_, AppState>`
//! (via `manage`) and `AppHandle`, and the database is a per-test temp file.
//! The `sqlite_works_after_mock_app_creation` probe in main.rs guards the
//! mock-runtime/sqlx interaction this relies on.

use crate::commands::*;
use crate::token_store::{InMemoryTokenStore, TokenStore};
use crate::types::*;
use persona_core::models::credential::CredentialData;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Mock app with a fresh, uninitialized `AppState` and explicit backend
/// parts（sync/biometric 两个 keyring 槽 + biometric provider）。各命令族
/// 测试按需注入 fake；默认组合见 [`mock_app_with_token_store`] /
/// [`mock_app_with_biometric`]。
fn mock_app_with_parts(
    token_store: Arc<dyn TokenStore>,
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    let app = tauri::test::mock_app();
    app.manage(AppState {
        service: Arc::new(Mutex::new(None)),
        db_path: Mutex::new(None),
        agent_handle: Mutex::new(None),
        auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
        passkey_server_started: std::sync::atomic::AtomicBool::new(false),
        passkey_server_shutdown: Mutex::new(None),
        ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
        passkey_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
        sync_emitter: Mutex::new(None),
        // CI/headless 没有 secret service——测试一律走内存 fake
        token_store,
        biometric_provider,
        biometric_store,
        // E2EE sync 设备身份槽：默认内存 fake，sync 命令族测试直接从
        // AppState 取 Arc 写入/断言条目
        device_store: Arc::new(InMemoryTokenStore::default()),
        connect_server: Mutex::new(None),
    });
    app
}

/// Mock app with a fresh, uninitialized `AppState` and the given token store.
/// biometric 侧默认注入恒通过的 Mock provider + 独立内存 store（biometric
/// 专属命令测试用 `mock_app_with_biometric` 换成可控 stub）。
fn mock_app_with_token_store(
    token_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_parts(
        token_store,
        Arc::new(persona_core::MockBiometricProvider::default()),
        Arc::new(InMemoryTokenStore::default()),
    )
}

/// Mock app with injectable biometric provider/store（biometric 命令族测试
/// 入口；provider 用 MockBiometricProvider 的 available/force_fail 组合
/// 分支，store 通常用 InMemoryTokenStore 便于直接断言条目内容）。
fn mock_app_with_biometric(
    biometric_provider: Arc<dyn persona_core::BiometricProvider>,
    biometric_store: Arc<dyn TokenStore>,
) -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_parts(
        Arc::new(InMemoryTokenStore::default()),
        biometric_provider,
        biometric_store,
    )
}

/// Mock app with a fresh, uninitialized `AppState`.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    mock_app_with_token_store(Arc::new(InMemoryTokenStore::default()))
}

/// Initialize the service against a fresh temp database and return the guard
/// (plus the db_path, for token-store/DB assertions).
async fn init_service_ok(app: &tauri::App<tauri::test::MockRuntime>, password: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cmd.db");
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);
    let db_path = db_path.to_string_lossy().to_string();

    let resp = init_service(
        InitRequest {
            master_password: password.to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "init failed: {:?}", resp.error);
    db_path
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

// ---------------------------------------------------------------------------
// 第三批：wallet 交易 / approval respond / SSH agent 状态与生命周期
// ---------------------------------------------------------------------------

/// 沙箱 agent 状态目录：`PERSONA_AGENT_STATE_DIR` 指向 tempdir，drop 恢复。
///
/// env 是进程全局的：并行测试各自 sandbox 会互相改道（socket 落错目录、
/// 状态断言失败），所以持一把进程级锁——同一时刻只有一个测试在改 env。
pub(crate) struct StateDirGuard {
    // 先声明先构造、最后 drop：env 先恢复，锁才释放。
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

impl StateDirGuard {
    pub(crate) fn sandbox(dir: &tempfile::TempDir) -> Self {
        static STATE_DIR_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let mutex = STATE_DIR_LOCK.get_or_init(|| std::sync::Mutex::new(()));
        let lock = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        StateDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
        }
    }

    /// 互斥地移除 PERSONA_AGENT_STATE_DIR：驱动 `agent_state_dir` 的
    /// home 回退臂。持有同一把进程级锁，恢复时 Drop 会移除 env（prev=None）。
    fn without_env() -> Self {
        static STATE_DIR_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let mutex = STATE_DIR_LOCK.get_or_init(|| std::sync::Mutex::new(()));
        let lock = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::remove_var("PERSONA_AGENT_STATE_DIR");
        StateDirGuard {
            _lock: lock,
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
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet_id"));

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
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid transaction_id"));

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
    // Boundary discipline: the caller sees an ApiResponse error body,
    // never an invoke-layer Err(String).
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wrong-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to derive signing key")),
        "got: {:?}",
        resp.error
    );

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
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to store signed transaction")),
        "got: {:?}",
        resp.error
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

    // Start before initialization: db path unknown. Boundary discipline:
    // infrastructure failures come back as Ok(ApiResponse::error), never as
    // an invoke-layer Err(String).
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
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

// ---------------------------------------------------------------------------
// 第四批：wallet import/地址管理/导出矩阵、get_ssh_keys、health_scan、门禁
// ---------------------------------------------------------------------------

/// wallet 家族在"服务未初始化"下一律失败关闭。
#[tokio::test]
async fn wallet_family_fails_closed_without_service() {
    let app = mock_app();

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_import(
        uuid::Uuid::new_v4().to_string(),
        WalletImportRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: uuid::Uuid::new_v4().to_string(),
            format: "json".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
}

/// wallet_import 三种导入方式 + 地址派生 + 删除与锁定门禁。
#[tokio::test]
async fn wallet_import_address_management_and_locked_gates() {
    let (app, identity_id) = app_with_identity().await;

    // HD 导入（mnemonic，2 个地址）。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Imported HD".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(2),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let hd = resp.data.expect("hd imported");
    assert!(hd.wallet_type.contains("HierarchicalDeterministic"));
    assert_eq!(hd.network, "Ethereum");
    assert_eq!(hd.address_count, 2);

    // 单地址导入（private_key）。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Imported Single".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4646464646464646464646464646464646464646464646464646464646464646".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let single = resp.data.expect("single imported");
    assert!(!single.wallet_type.contains("HierarchicalDeterministic"));
    assert_eq!(single.address_count, 1);

    // 短密码 / 未知 import_type / 坏助记词都被拒绝。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon about".to_string(),
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

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "yaml".to_string(),
            data: "whatever".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Unsupported import_type"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "not a real mnemonic phrase at all".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "invalid mnemonic must be rejected");

    // 按 identity 过滤 + 非法 UUID。
    let resp = wallet_list(Some(identity_id.clone()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().wallets.len(), 2);

    // wallet_list 落 bad UUID 为 ApiResponse 错误，不再逃逸命令边界。
    let resp = wallet_list(Some("not-a-uuid".to_string()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // 地址列表：非法 UUID / 未知钱包。
    // Bad UUID 同样落 ApiResponse。
    let resp = wallet_list_addresses("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet UUID format"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    // add_address：未知钱包 / 短密码 / 错误密码 / 单地址钱包 / HD 正常派生。
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    let resp = wallet_add_address(hd.id.clone(), "short".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );

    // Decrypt failure 落 ApiResponse 错误消息，不逃逸命令边界。
    let resp = wallet_add_address(
        hd.id.clone(),
        "wrong-passphrase".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to decrypt private key")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_add_address(
        single.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Address generation is only supported for HD wallets.")
    );

    let resp = wallet_add_address(
        hd.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addr = resp.data.expect("new address");
    assert_eq!(addr.index, 2, "next index after the two imported ones");
    assert_eq!(addr.address_type, "ETH");
    assert!(addr.address.starts_with("0x"));
    assert_eq!(
        addr.derivation_path.as_deref().map(|p| p.ends_with("/2")),
        Some(true)
    );

    // 地址列表能看到新地址（serialize_wallet_address 路径）。
    let resp = wallet_list_addresses(hd.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addresses = resp.data.unwrap().addresses;
    assert_eq!(addresses.len(), 3);
    assert!(addresses.iter().any(|a| a.index == 2));

    // 删除：未知钱包报错，真实删除返回 true。
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    for id in [hd.id, single.id] {
        let resp = wallet_delete(id, app.state::<AppState>()).await.unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }

    // 锁定后整个家族都被 "Service is locked" 门禁拦下。
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_import(
        uuid::Uuid::new_v4().to_string(),
        WalletImportRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: uuid::Uuid::new_v4().to_string(),
            format: "json".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}

/// 导出格式矩阵：json（含私钥）/ mnemonic / private_key / xpub / wif。
#[tokio::test]
async fn wallet_export_format_matrix() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Eth HD".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let eth = resp.data.expect("eth wallet");
    let eth_id = eth.id.clone();

    // Bitcoin 钱包供 WIF 导出。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Btc".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc = resp.data.expect("btc wallet");

    // mnemonic 导出：无密码被拒，有密码还原助记词。
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "mnemonic".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Password required for mnemonic export")
    );

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "mnemonic".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().split_whitespace().count(), 12);

    // private_key 导出：无密码被拒，有密码得到 0x hex。
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "private_key".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Password required for private key export")
    );

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "private_key".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let priv_hex = resp.data.unwrap();
    assert!(
        priv_hex.len() >= 64,
        "hex private key, got {} chars",
        priv_hex.len()
    );

    // xpub 导出（HD 导入会写 extended_public_key）。
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "xpub".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().starts_with("xpub"));

    // WIF 导出：HD Bitcoin 钱包被拒（要求单地址），单地址 Bitcoin 才成功。
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: btc.id.clone(),
            format: "wif".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("single-address Bitcoin wallets"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id,
        WalletImportRequest {
            name: "Btc Single".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "private_key".to_string(),
            data: "4646464646464646464646464646464646464646464646464646464646464646".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc_single = resp.data.expect("btc single");

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: btc_single.id.clone(),
            format: "wif".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().len() >= 51);

    // JSON 含私钥导出 + 未知格式。
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "json".to_string(),
            include_private: true,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let exported: serde_json::Value =
        serde_json::from_str(&resp.data.unwrap()).expect("export is valid JSON");
    assert!(exported.get("private_keys").is_some());

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id,
            format: "yaml".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "unknown export format must be rejected");
}

/// get_ssh_keys 只挑出 SshKey 凭据并带 identity 名；health_scan 出报告。
#[tokio::test]
async fn get_ssh_keys_and_health_scan() {
    let app = mock_app();

    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = health_scan(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let (app, identity_id) = app_with_identity().await;

    // 一个 SSH key + 一个 Password 凭据：只有前者出现在列表里。
    let ssh_req = CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: "GitHub SSH".to_string(),
        credential_type: "SshKey".to_string(),
        security_level: "High".to_string(),
        url: None,
        username: Some("git".to_string()),
        notes: None,
        tags: Some(vec!["git".to_string()]),
        credential_data: CredentialDataRequest::SshKey {
            private_key: "data:private-key-blob".to_string(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB test@persona".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        },
    };
    let resp = create_credential(ssh_req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let keys = resp.data.unwrap();
    assert_eq!(keys.len(), 1, "only the SshKey credential is listed");
    assert_eq!(keys[0].name, "GitHub SSH");
    assert_eq!(keys[0].identity_name, "Cred Holder");
    assert_eq!(keys[0].tags, vec!["git".to_string()]);

    // 健康扫描：无参数默认值 + 自定义阈值都出报告。
    let resp = health_scan(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let report = resp.data.expect("health report");
    assert_eq!(report.total_credentials, 2);

    let resp = health_scan(
        Some(HealthScanRequest {
            min_password_score: Some(3),
            expiry_warning_days: Some(30),
            stale_after_days: Some(90),
            check_breaches: Some(false),
        }),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().total_credentials, 2);
}

// ---------------------------------------------------------------------------
// 第五批：passkey 门禁与错误码、TOTP/凭据数据拒绝路径、审计过滤、工作区改道
// ---------------------------------------------------------------------------

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

/// get_totp_code / get_credential_data 的拒绝路径 + search 行为。
#[tokio::test]
async fn totp_and_credential_data_rejections() {
    let (app, identity_id) = app_with_identity().await;

    // 密码凭据（非 TOTP）。
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let password_cred = resp.data.expect("password credential");

    // TOTP 凭据。
    let mut totp_req = password_credential_request(&identity_id);
    totp_req.name = "GitHub TOTP".to_string();
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
    let totp_cred = resp.data.expect("totp credential");

    // get_credential_data：坏 UUID（ApiResponse）。
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // get_totp_code：坏 UUID / 未知凭据 —— 同纪律落 ApiResponse 错误。
    let resp = get_totp_code("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = get_totp_code(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));

    let resp = get_totp_code(password_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Credential is not a TwoFactor entry")
    );

    // 正常 TOTP 出码（RFC 向量 secret）。
    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.expect("totp code").code.len(), 6);

    // 搜索：空查询返回全部，精确子串过滤。
    let resp = search_credentials(String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 2);

    let resp = search_credentials("GitHub TOTP".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let hits = resp.data.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "GitHub TOTP");
}

/// get_totp_code 对 GameToken 凭据（Steam Guard）走 core 调度器臂：
/// 5 位码 / 30 秒周期 / algorithm=provider 大写；绑定型 provider 报错
/// 而不是伪造码。凭据经 service 直建（命令层请求枚举的 GameToken
/// 变体在 G1.5 登记）。
#[tokio::test]
async fn get_totp_code_supports_game_token_provider() {
    use persona_core::models::credential::GameTokenData;

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    let steam_cred_id = {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        let cred = service
            .create_credential(
                identity_uuid,
                "Steam Guard".to_string(),
                persona_core::models::credential::CredentialType::TwoFactor,
                persona_core::models::credential::SecurityLevel::High,
                &persona_core::models::credential::CredentialData::GameToken(GameTokenData {
                    provider: "steam_guard".to_string(),
                    secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
                    issuer: "Steam".to_string(),
                    account_name: "player_one".to_string(),
                    url: Some("https://store.steampowered.com".to_string()),
                }),
            )
            .await
            .unwrap();
        cred.id
    };

    let resp = get_totp_code(steam_cred_id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("game token code returned");
    assert_eq!(code.code.len(), 5, "steam guard code is five chars");
    assert!(
        code.code
            .bytes()
            .all(|c| b"23456789BCDFGHJKMNPQRTVWXY".contains(&c)),
        "code {} outside the Steam alphabet",
        code.code
    );
    assert_eq!(code.period, 30);
    assert_eq!(code.digits, 5);
    assert_eq!(code.algorithm, "STEAM_GUARD");
    assert_eq!(code.issuer, "Steam");
    assert_eq!(code.account_name, "player_one");

    // 绑定型 provider：命令层报错信息，绝不返回码。
    let bound_cred_id = {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        let cred = service
            .create_credential(
                identity_uuid,
                "Vendor bound token".to_string(),
                persona_core::models::credential::CredentialType::TwoFactor,
                persona_core::models::credential::SecurityLevel::High,
                &persona_core::models::credential::CredentialData::GameToken(GameTokenData {
                    provider: "tencent_security".to_string(),
                    secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
                    issuer: "Tencent".to_string(),
                    account_name: "player_one".to_string(),
                    url: None,
                }),
            )
            .await
            .unwrap();
        cred.id
    };

    // 绑定型 provider：与 TOTP 生成错误同路径，落 ApiResponse 错误消息，绝不返回码。
    let resp = get_totp_code(bound_cred_id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Unsupported game token provider")),
        "unexpected error: {:?}",
        resp.error
    );
}

/// G1.5：创建表单路径——CredentialDataRequest::GameToken 经 create_credential
/// 命令入库，读回 GameToken 变体并出码（steam_guard）。
#[tokio::test]
async fn create_credential_accepts_game_token_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Steam Guard (form)".to_string();
    req.credential_type = "TwoFactor".to_string();
    req.credential_data = CredentialDataRequest::GameToken {
        provider: "steam_guard".to_string(),
        secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
        issuer: "Steam".to_string(),
        account_name: "player_one".to_string(),
        url: Some("https://store.steampowered.com".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("game token credential created");

    // 读回：数据是 GameToken 变体（JSON 里不回传 secret_key）。
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "GameToken");
    assert_eq!(data.data["provider"], "steam_guard");
    assert_eq!(data.data["issuer"], "Steam");
    assert_eq!(data.data["account_name"], "player_one");
    assert!(data.data.get("secret_key").is_none());

    // steam_guard 出码经统一调度器。
    let resp = get_totp_code(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("game token code returned");
    assert_eq!(code.code.len(), 5);
    assert_eq!(code.period, 30);

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// 1Password 对齐 A 批：Secure Note 创建表单路径——
/// CredentialDataRequest::SecureNote 经 create_credential 入库，credential_type
/// 为真实 SecureNote 变体，读回正文逐字保留（per-item key 加密往返）。
#[tokio::test]
async fn create_credential_accepts_secure_note_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Recovery codes (form)".to_string();
    req.credential_type = "SecureNote".to_string();
    req.credential_data = CredentialDataRequest::SecureNote {
        note: "1111-2222\n3333-4444".to_string(),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("secure note created");

    // 读回：类型标签与正文都保留（多行内容不被折叠）。
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SecureNote");
    assert_eq!(data.data["note"], "1111-2222\n3333-4444");

    // 列表读回：credential_type 落库往返不退化为 Custom。
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SecureNote" && c.name == "Recovery codes (form)"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// 1Password 对齐 B 批：Identity / Software License 创建表单路径——
/// 两类 CredentialDataRequest 经 create_credential 入库，credential_type
/// 为真实变体，读回字段逐字保留（per-item key 加密往返），不退化为 Custom。
#[tokio::test]
async fn create_credential_accepts_identity_and_license_requests() {
    let (app, identity_id) = app_with_identity().await;

    // Identity：证件号等敏感字段全量读回（get_credential_data 走敏感门禁）。
    let mut req = password_credential_request(&identity_id);
    req.name = "Passport (main)".to_string();
    req.credential_type = "Identity".to_string();
    req.credential_data = CredentialDataRequest::Identity {
        first_name: "Alice".to_string(),
        last_name: "Zhang".to_string(),
        username: None,
        email: Some("alice@example.com".to_string()),
        phone: Some("+86 13800000000".to_string()),
        birthday: Some("1990-01-31".to_string()),
        address: Some("1 Main St\nBeijing".to_string()),
        id_number: Some("110101199001310011".to_string()),
        passport_number: Some("E12345678".to_string()),
        driver_license: None,
        tax_id: None,
        organization: Some("Example Inc".to_string()),
        job_title: Some("Engineer".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let identity_cred = resp.data.expect("identity credential created");

    let resp = get_credential_data(identity_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Identity");
    assert_eq!(data.data["first_name"], "Alice");
    assert_eq!(data.data["id_number"], "110101199001310011");
    assert_eq!(data.data["passport_number"], "E12345678");
    assert_eq!(data.data["address"], "1 Main St\nBeijing");
    assert_eq!(data.data["seats"], serde_json::Value::Null);

    // SoftwareLicense：license_key 读回、seats 数值往返。
    let mut req = password_credential_request(&identity_id);
    req.name = "JetBrains All Products".to_string();
    req.credential_type = "SoftwareLicense".to_string();
    req.credential_data = CredentialDataRequest::SoftwareLicense {
        license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
        version: Some("2024.2".to_string()),
        publisher: Some("JetBrains".to_string()),
        purchase_date: Some("2024-05-01".to_string()),
        order_number: None,
        support_email: None,
        download_url: Some("https://example.com/dl".to_string()),
        seats: Some(3),
        valid_until: Some("2027-05-01".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let license_cred = resp.data.expect("license credential created");

    let resp = get_credential_data(license_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SoftwareLicense");
    assert_eq!(data.data["license_key"], "AAAA-BBBB-CCCC-DDDD");
    assert_eq!(data.data["seats"], serde_json::json!(3));
    assert_eq!(data.data["order_number"], serde_json::Value::Null);

    // 列表读回：两个 credential_type 落库往返不退化为 Custom。
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "Identity" && c.name == "Passport (main)"));
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SoftwareLicense" && c.name == "JetBrains All Products"));

    let resp = delete_credential(identity_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = delete_credential(license_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// 桌面稳定化：编辑凭据闭环——update_credential 改元数据、
/// update_credential_data 换密文 payload（复用原 item key，wrapped key 不变），
/// 两路读回逐字校验；不存在的 id 报错。
#[tokio::test]
async fn update_credential_metadata_and_payload_round_trip() {
    let (app, identity_id) = app_with_identity().await;

    let req = password_credential_request(&identity_id);
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("credential created");
    assert_eq!(created.username.as_deref(), Some("alice"));

    // 元数据编辑：改名 + username/notes/tags 更新（url 传空串 = 清空）。
    let resp = update_credential(
        UpdateCredentialRequest {
            id: created.id.clone(),
            name: "Renamed login".to_string(),
            security_level: Some("Critical".to_string()),
            url: Some("  ".to_string()),
            username: Some("newuser".to_string()),
            notes: Some("edited note".to_string()),
            tags: Some(vec!["work".to_string(), " ".to_string()]),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let meta = resp.data.expect("metadata updated");
    assert_eq!(meta.name, "Renamed login");
    assert_eq!(meta.security_level, "Critical");
    assert_eq!(meta.url, None, "blank url must clear");
    assert_eq!(meta.username.as_deref(), Some("newuser"));
    assert_eq!(meta.notes.as_deref(), Some("edited note"));
    assert_eq!(meta.tags, vec!["work".to_string()]);

    // payload 编辑：换密码（复用原 item key 重封）。
    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: created.id.clone(),
            credential_data: CredentialDataRequest::Password {
                password: "rotated-secret".to_string(),
                email: Some("edited@example.com".to_string()),
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let payload = resp.data.expect("payload updated");
    assert_eq!(
        payload.name, "Renamed login",
        "metadata survives payload edit"
    );
    // item key 复用不变量（wrapped key 字节不动）在 core 层专测断言；
    // SerializableCredential 不回传密钥材料，命令层不重复覆盖。

    // 读回：新密码逐字保留、元数据编辑结果都在。
    let resp = get_credential_data(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp
        .data
        .expect("credential data returned")
        .expect("present");
    assert_eq!(data.data["password"], "rotated-secret");
    assert_eq!(data.data["email"], "edited@example.com");

    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    let stored = creds
        .iter()
        .find(|c| c.id == created.id)
        .expect("credential listed");
    assert_eq!(stored.name, "Renamed login");
    assert_eq!(stored.username.as_deref(), Some("newuser"));
    assert_eq!(stored.notes.as_deref(), Some("edited note"));

    // 不存在的 id：两命令都显式报错。
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = update_credential(
        UpdateCredentialRequest {
            id: ghost.clone(),
            name: "x".to_string(),
            security_level: None,
            url: None,
            username: None,
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not found"));

    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: ghost,
            credential_data: CredentialDataRequest::Password {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    let resp = delete_credential(created.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// 1Password 对齐 B 批：item history——创建与 favorite 切换自动落历史行，
/// get_credential_history 返回时间线（新版本在前）与字段级 diff。
#[tokio::test]
async fn credential_history_tracks_create_and_favorite_toggle() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Historied".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 初始：created (v1) + 紧随的元数据补写 updated (v2)——
    // 桌面 create 命令是 create-then-update 架构，两次写库即两条真实历史
    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 2);
    // 补写 diff = 表单的 url/username/notes/tags 四个元数据字段
    assert_eq!(history[0].changes.len(), 4);
    assert!(history[0]
        .changes
        .iter()
        .all(|c| c.field != "encrypted_data"));
    assert_eq!(history[1].change_type, "created");
    assert_eq!(history[1].version, 1);

    // favorite 切换 → updated 行，diff 只含 is_favorite
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 3);
    assert_eq!(history[0].changes.len(), 1);
    assert_eq!(history[0].changes[0].field, "is_favorite");
    assert_eq!(history[0].changes[0].old_value, "false");
    assert_eq!(history[0].changes[0].new_value, "true");

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// restore-to-version：元数据回滚到目标版本并落 restored 历史行；
/// 秘密不回滚（历史快照不含密文）。
#[tokio::test]
async fn restore_credential_version_reverts_metadata() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Versioned".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 再改一次元数据 → 多一个版本
    let resp = update_credential(
        UpdateCredentialRequest {
            id: cred.id.clone(),
            name: "Renamed".to_string(),
            security_level: None,
            url: Some("https://renamed.example.com".to_string()),
            username: Some("bob".to_string()),
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 恢复到 v1（创建态）：表单补写与改名一并回滚
    let resp = restore_credential_version(cred.id.clone(), 1, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let restored = resp.data.expect("restored");
    assert_eq!(restored.name, "Versioned");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history[0].change_type, "restored");
    assert!(
        history[0].restorable,
        "restore rows carry a restorable state"
    );
    assert!(history[1].restorable);

    // 未知版本 → 业务错误而非 panic
    let resp = restore_credential_version(cred.id.clone(), 99, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap_or_default().contains("99"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// 审计查询过滤分支 + init_service 把唯一工作区改道到新路径。
#[tokio::test]
async fn audit_query_filters_and_workspace_repath() {
    let (app, _identity_id) = app_with_identity().await;

    // 合法 action 过滤（空结果）。
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

    // AuditAction::from_str 把未知动作映射成 Custom、从不失败，所以
    // build_audit_query 的 "Unknown audit action" 分支只是防御性死代码。
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

    // 工作区改道：把 tempdir 挪到新路径后再 init，库内唯一工作区
    // （指向旧路径）会被改道到新路径（ensure_workspace_for_path 分支）。
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
    // 挪到 /tmp 下的兄弟目录（不能挪进自身内部，EINVAL）。
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

// ---------------------------------------------------------------------------
// 第六批：reveal 类型矩阵 / 导出与审计门禁 / reauth 余量分支
// ---------------------------------------------------------------------------

/// `extract_secret_field` 的字段×类型全矩阵（纯函数，无需服务）。
#[test]
fn extract_secret_field_type_matrix() {
    use persona_core::models::credential::{
        ApiKeyData, CryptoWalletData, PasswordCredentialData, SecurityQuestion, SshKeyData,
    };

    // Password：明文密码 + 安全问题 JSON 序列化；跨类型字段拒绝。
    let password = CredentialData::Password(PasswordCredentialData {
        password: "pw-1".to_string(),
        email: None,
        security_questions: vec![SecurityQuestion {
            question: "pet?".to_string(),
            answer: "cat".to_string(),
        }],
    });
    assert_eq!(extract_secret_field(&password, "password").unwrap(), "pw-1");
    let questions = extract_secret_field(&password, "security_questions").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&questions).unwrap();
    assert_eq!(parsed[0]["question"], "pet?");
    assert_eq!(parsed[0]["answer"], "cat");
    assert!(extract_secret_field(&password, "ssh_private_key").is_err());

    // CryptoWallet：私钥/助记词可选，缺失时给出可读错误。
    let wallet = |mnemonic: Option<&str>, key: Option<&str>| {
        CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "hd".to_string(),
            mnemonic_phrase: mnemonic.map(str::to_string),
            private_key: key.map(str::to_string),
            public_key: "pub".to_string(),
            address: "addr".to_string(),
            network: "Ethereum".to_string(),
        })
    };
    assert_eq!(
        extract_secret_field(&wallet(Some("m words"), Some("0xk")), "wallet_private_key").unwrap(),
        "0xk"
    );
    assert_eq!(
        extract_secret_field(&wallet(Some("m words"), None), "wallet_mnemonic").unwrap(),
        "m words"
    );
    assert_eq!(
        extract_secret_field(&wallet(None, None), "wallet_private_key").unwrap_err(),
        "This wallet has no stored private key"
    );
    assert_eq!(
        extract_secret_field(&wallet(None, None), "wallet_mnemonic").unwrap_err(),
        "This wallet has no stored mnemonic phrase"
    );
    assert!(extract_secret_field(&wallet(None, None), "api_key").is_err());

    // SshKey：私钥必有；口令可选。
    let ssh = |passphrase: Option<&str>| {
        CredentialData::SshKey(SshKeyData {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAA".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: passphrase.map(str::to_string),
        })
    };
    assert!(extract_secret_field(&ssh(None), "ssh_private_key")
        .unwrap()
        .starts_with("-----BEGIN"));
    assert_eq!(
        extract_secret_field(&ssh(Some("pp")), "ssh_passphrase").unwrap(),
        "pp"
    );
    assert_eq!(
        extract_secret_field(&ssh(None), "ssh_passphrase").unwrap_err(),
        "This SSH key has no stored passphrase"
    );

    // ApiKey：secret 与 token 可选。
    let api = |secret: Option<&str>, token: Option<&str>| {
        CredentialData::ApiKey(ApiKeyData {
            api_key: "AK123".to_string(),
            api_secret: secret.map(str::to_string),
            token: token.map(str::to_string),
            permissions: vec![],
            expires_at: None,
        })
    };
    assert_eq!(
        extract_secret_field(&api(None, None), "api_key").unwrap(),
        "AK123"
    );
    assert_eq!(
        extract_secret_field(&api(Some("sec"), None), "api_secret").unwrap(),
        "sec"
    );
    assert_eq!(
        extract_secret_field(&api(None, Some("tok")), "token").unwrap(),
        "tok"
    );
    assert_eq!(
        extract_secret_field(&api(None, None), "api_secret").unwrap_err(),
        "This API credential has no stored secret"
    );
    assert_eq!(
        extract_secret_field(&api(None, None), "token").unwrap_err(),
        "This API credential has no stored token"
    );

    // Raw：必须能按 UTF-8 解码。
    let raw_utf8 = CredentialData::Raw("plain-bytes".as_bytes().to_vec());
    assert_eq!(
        extract_secret_field(&raw_utf8, "raw_data").unwrap(),
        "plain-bytes"
    );
    let raw_binary = CredentialData::Raw(vec![0xff, 0xfe, 0x00]);
    assert_eq!(
        extract_secret_field(&raw_binary, "raw_data").unwrap_err(),
        "Raw data is not valid UTF-8"
    );

    // 未知字段名一律拒绝。
    assert_eq!(
        extract_secret_field(&password, "nonexistent").unwrap_err(),
        "Field 'nonexistent' is not available for this credential type"
    );
}

/// reveal 命令的错误路径 + ApiKey 凭据的成功 reveal（覆盖
/// `CredentialDataRequest::ApiKey` 的转换与序列化链）。
#[tokio::test]
async fn reveal_secret_paths_and_api_key_round_trip() {
    let app = mock_app();

    // 未初始化：服务缺失分支。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: uuid::Uuid::new_v4().to_string(),
            field: "password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let (app, identity_id) = app_with_identity().await;

    // 坏 UUID 在拿服务之前就被拒。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: "not-a-uuid".to_string(),
            field: "password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // ApiKey 凭据：创建 → reveal api_key 命中成功臂。
    let mut req = password_credential_request(&identity_id);
    req.name = "Service API".to_string();
    req.credential_type = "ApiKey".to_string();
    req.credential_data = CredentialDataRequest::ApiKey {
        api_key: "AKIA-example".to_string(),
        api_secret: Some("shhh".to_string()),
        token: None,
        permissions: vec!["read".to_string()],
        expires_at: None,
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let api_cred = resp.data.expect("api credential created");

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: api_cred.id.clone(),
            field: "api_key".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let revealed = resp.data.expect("secret revealed");
    assert_eq!(revealed.field, "api_key");
    assert_eq!(revealed.value, "AKIA-example");

    // 类型不匹配：对 ApiKey 凭据要 password 字段。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: api_cred.id.clone(),
            field: "password".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("not available for this credential type"));

    // 不存在的凭据 id。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: uuid::Uuid::new_v4().to_string(),
            field: "api_key".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));
}

/// export_identity 的成功/错误路径 + audit_cleanup 与 reauth 的门禁。
#[tokio::test]
async fn export_identity_and_audit_cleanup_gates() {
    let app = mock_app();
    let bad_uuid = uuid::Uuid::new_v4().to_string();

    // 无服务分支：export/audit_cleanup/reauth 全部降级报错；
    // passkey 导出则先在本地拒绝坏 UUID。
    let resp = export_identity(bad_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = passkey_export_private_key("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let (app, identity_id) = app_with_identity().await;

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 导出成功：身份 + 凭据 JSON 负载（元数据，不含密文）。
    let resp = export_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let export = resp.data.expect("identity exported");
    assert_eq!(export.data["identity"]["name"], "Cred Holder");
    assert_eq!(export.data["credentials"].as_array().map(Vec::len), Some(1));
    assert!(!export.exported_at.is_empty());

    // 不存在的身份：无专用错误码 → 常规错误串。
    let resp = export_identity(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("Failed to export identity"));

    // 锁定后：export/audit_cleanup 都带 SERVICE_LOCKED 错误码。
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = export_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
}

/// `query_agent_key_count` 走 std 同步 socket（不经过 tokio reactor，不受
/// mock 运行时毒化影响）：起一个本地假 agent 服务端按脚本回协议响应，
/// 覆盖成功计数与各错误分支。
#[cfg(unix)]
#[test]
fn query_agent_key_count_protocol_matrix() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();

    // 假 agent：读 5 字节 request_identities 请求，回 `payload`。
    // 返回 (socket 路径, responder 句柄)；join 必须发生在客户端连接之后，
    // 否则 responder 卡在 accept 而客户端还没跑起来，直接死锁。
    let serve_once = |payload: Vec<u8>| -> (String, std::thread::JoinHandle<()>) {
        let sock_path = dir
            .path()
            .join(format!("agent-{}.sock", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&sock_path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 5];
            stream.read_exact(&mut req).unwrap();
            // SSH_AGENTC_REQUEST_IDENTITIES = 11
            assert_eq!(req[4], 11, "client must ask for identities");
            let mut resp = vec![0, 0, 0, payload.len() as u8];
            resp.extend_from_slice(&payload);
            stream.write_all(&resp).unwrap();
        });
        let path = sock_path.to_string_lossy().to_string();
        (path, handle)
    };

    // 成功：SSH_AGENT_IDENTITIES_ANSWER(12) + 3 把钥匙。
    let (path, responder) = serve_once(vec![12, 0, 0, 0, 3]);
    assert_eq!(query_agent_key_count(&path).unwrap(), 3);
    responder.join().unwrap();

    // 首 byte 非 12 → "Unexpected agent response"。
    let (path, responder) = serve_once(vec![99, 0, 0, 0, 3]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Unexpected agent response"
    );
    responder.join().unwrap();

    // 响应过短 → "Malformed agent response"。
    let (path, responder) = serve_once(vec![12, 0]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Malformed agent response"
    );
    responder.join().unwrap();

    // 连不上 → 连接错误。
    let err = query_agent_key_count(&dir.path().join("absent.sock").to_string_lossy()).unwrap_err();
    assert!(err.starts_with("Failed to connect to agent"), "{}", err);
}

/// 状态文件内容畸形时不 panic：pid 解析失败降级为 None。
#[cfg(unix)]
#[tokio::test]
async fn ssh_agent_status_tolerates_malformed_state_files() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);
    let app = mock_app();

    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/empty-sock\n").unwrap();
    std::fs::write(dir.path().join("ssh-agent.pid"), "not-a-number").unwrap();

    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert!(status.running, "socket file alone still means running");
    assert_eq!(status.socket_path.as_deref(), Some("/tmp/empty-sock"));
    assert_eq!(status.pid, None, "unparseable pid degrades to None");
}

/// 多链签名路径（命令层可达部分）：
/// - Bitcoin：命令层无法提供 UTXO inputs（metadata 恒空），build_raw 失败 →
///   走 audit-only 落库（raw 为空、hash 带 `audit:` 前缀）——这是无 UTXO
///   集时唯一可落库的签名记录路径。
/// - Solana：命令层无法携带 raw_transaction_data，签名直接被拒。
#[tokio::test]
async fn wallet_sign_bitcoin_audit_only_and_solana_rejection() {
    let (app, identity_id) = app_with_identity().await;
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Bitcoin 单地址钱包（mnemonic 派生 P2WPKH）。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Btc Sign".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "mnemonic".to_string(),
            data: mnemonic.to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc = resp.data.expect("btc wallet");

    // 创建 pending BTC 交易。
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: btc.id.clone(),
            to_address: "bc1qexample0recipient0address".to_string(),
            amount: "1000".to_string(),
            fee: "150".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: Some("audit-only".to_string()),
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending btc tx");
    let tx_id = pending["id"].as_str().expect("tx id").to_string();

    // 签名落库：audit-only 记录。
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "btc sign failed: {:?}", resp.error);
    let signed = resp.data.expect("signed btc tx");
    assert!(
        signed["transaction_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("audit:"),
        "audit-only record must carry an audit: hash, got {signed}"
    );
    assert!(
        signed["raw_signed_transaction"]
            .as_array()
            .is_some_and(|raw| raw.is_empty()),
        "audit-only record must not carry raw bytes"
    );

    // Solana 钱包：签名因缺 raw_transaction_data 被拒。
    let resp = wallet_import(
        identity_id,
        WalletImportRequest {
            name: "Sol Sign".to_string(),
            network: "Solana".to_string(),
            import_type: "mnemonic".to_string(),
            data: mnemonic.to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let sol = resp.data.expect("sol wallet");

    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: sol.id.clone(),
            to_address: "SolanaRecipientAddress11111111111111111111111".to_string(),
            amount: "1000".to_string(),
            fee: "5000".to_string(),
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
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending sol tx");
    let tx_id = pending["id"].as_str().expect("tx id").to_string();

    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to sign transaction")),
        "solana sign must fail without raw_transaction_data: {:?}",
        resp.error
    );
}

// ---------------------------------------------------------------------------
// 第八批：types 层纯函数矩阵（序列化脱敏 + 转换 + 事件映射）
// ---------------------------------------------------------------------------

/// `credential_data_to_json` 覆盖全部凭据类型的序列化臂，并验证各敏感
/// 字段（密码、私钥、助记词、API secret、完整卡号）一律不出现在 JSON 里。
#[test]
fn credential_data_to_json_type_matrix_and_redaction() {
    use persona_core::models::credential::{
        ApiKeyData, BankCardData, CryptoWalletData, PasswordCredentialData, SecurityQuestion,
        ServerConfigData, SshKeyData, TwoFactorData,
    };

    let password = CredentialData::Password(PasswordCredentialData {
        password: "plain-secret".to_string(),
        email: Some("a@b.c".to_string()),
        security_questions: vec![SecurityQuestion {
            question: "q".to_string(),
            answer: "a".to_string(),
        }],
    });
    let json = credential_data_to_json(&password);
    assert_eq!(json["type"], "Password");
    assert_eq!(json["email"], "a@b.c");
    // 分层契约：登录密码是 UI 主视图数据（get_credential_data 直接携带），
    // 而钱包私钥/SSH 私钥/API secret/TOTP 种子等更高级别的敏感材料一律
    // 不进序列化负载，只能走 reveal_credential_secret。
    assert_eq!(json["password"], "plain-secret");

    let wallet = CredentialData::CryptoWallet(CryptoWalletData {
        wallet_type: "hd".to_string(),
        mnemonic_phrase: Some("never leak".to_string()),
        private_key: Some("never leak".to_string()),
        public_key: "pub".to_string(),
        address: "addr".to_string(),
        network: "Ethereum".to_string(),
    });
    let json = credential_data_to_json(&wallet);
    assert_eq!(json["type"], "CryptoWallet");
    assert_eq!(json["address"], "addr");
    assert!(
        !json.to_string().contains("never leak"),
        "wallet secret leaked: {json}"
    );

    let ssh = CredentialData::SshKey(SshKeyData {
        private_key: "PRIVATE".to_string(),
        public_key: "ssh-ed25519 AAA".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: Some("pp".to_string()),
    });
    let json = credential_data_to_json(&ssh);
    assert_eq!(json["type"], "SshKey");
    assert_eq!(json["key_type"], "ed25519");
    assert!(!json.to_string().contains("PRIVATE"));

    let api = CredentialData::ApiKey(ApiKeyData {
        api_key: "AKIA-leak".to_string(),
        api_secret: Some("SECRET-leak".to_string()),
        token: Some("TOKEN-leak".to_string()),
        permissions: vec!["read".to_string()],
        expires_at: None,
    });
    let json = credential_data_to_json(&api);
    assert_eq!(json["type"], "ApiKey");
    assert_eq!(json["permissions"][0], "read");
    assert!(!json.to_string().contains("leak"));

    let card = CredentialData::BankCard(BankCardData {
        card_number: "4111 1111 1111 1234".to_string(),
        cardholder_name: "Cred Holder".to_string(),
        expiry_date: "12/30".to_string(),
        cvv: "999".to_string(),
        bank_name: "Example Bank".to_string(),
        card_type: "visa".to_string(),
    });
    let json = credential_data_to_json(&card);
    assert_eq!(json["type"], "BankCard");
    assert_eq!(json["last4"], "1234");
    assert!(
        !json.to_string().contains("4111"),
        "full PAN leaked: {json}"
    );
    assert!(!json.to_string().contains("999"));

    let server = CredentialData::ServerConfig(ServerConfigData {
        hostname: "web01".to_string(),
        ip_address: Some("10.0.0.5".to_string()),
        port: 22,
        protocol: "ssh".to_string(),
        username: "deploy".to_string(),
        password: Some("SERVER-leak".to_string()),
        ssh_key_id: None,
        additional_config: HashMap::new(),
    });
    let json = credential_data_to_json(&server);
    assert_eq!(json["type"], "ServerConfig");
    assert_eq!(json["port"], 22);
    assert!(!json.to_string().contains("SERVER-leak"));

    let totp = CredentialData::TwoFactor(TwoFactorData {
        secret_key: "TOTP-leak".to_string(),
        issuer: "GitHub".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    });
    let json = credential_data_to_json(&totp);
    assert_eq!(json["type"], "TwoFactor");
    assert_eq!(json["issuer"], "GitHub");
    assert!(!json.to_string().contains("TOTP-leak"));

    let json = credential_data_to_json(&CredentialData::Raw(vec![1, 2, 3]));
    assert_eq!(json["type"], "Raw");
    assert_eq!(json["message"], "Binary data");
}

/// `CredentialDataRequest::to_credential_data` 的剩余转换臂：
/// CryptoWallet / SshKey / Raw，以及 ApiKey 的 expires_at RFC3339 解析。
#[test]
fn credential_data_request_conversion_extras() {
    let wallet = CredentialDataRequest::CryptoWallet {
        wallet_type: "hd".to_string(),
        mnemonic_phrase: Some("words".to_string()),
        private_key: Some("0xk".to_string()),
        public_key: "pub".to_string(),
        address: "addr".to_string(),
        network: "Ethereum".to_string(),
    };
    match wallet.to_credential_data() {
        CredentialData::CryptoWallet(w) => {
            assert_eq!(w.mnemonic_phrase.as_deref(), Some("words"));
            assert_eq!(w.private_key.as_deref(), Some("0xk"));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    let ssh = CredentialDataRequest::SshKey {
        private_key: "PRIVATE".to_string(),
        public_key: "pub".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: Some("pp".to_string()),
    };
    match ssh.to_credential_data() {
        CredentialData::SshKey(k) => assert_eq!(k.passphrase.as_deref(), Some("pp")),
        other => panic!("wrong variant: {other:?}"),
    }

    let api = CredentialDataRequest::ApiKey {
        api_key: "AK".to_string(),
        api_secret: None,
        token: None,
        permissions: vec![],
        expires_at: Some("2030-01-01T00:00:00Z".to_string()),
    };
    match api.to_credential_data() {
        CredentialData::ApiKey(a) => assert!(a.expires_at.is_some(), "rfc3339 parsed"),
        other => panic!("wrong variant: {other:?}"),
    }

    let raw = CredentialDataRequest::Raw {
        data: vec![9, 9, 9],
    };
    match raw.to_credential_data() {
        CredentialData::Raw(bytes) => assert_eq!(bytes, vec![9, 9, 9]),
        other => panic!("wrong variant: {other:?}"),
    }
}

/// `SerializableAutoLockEvent` 四个变体的映射与 serde tag。
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
    // reason 经 Debug 格式（枚举名），session 透传。
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

/// `From<AuditLog>`：可选身份/凭据 id 转字符串、动作与资源类型可读化。
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
    // 动作与资源类型序列化为 snake_case（与 AuditAction::from_str 对称）。
    assert_eq!(json["action"], "identity_created");
    assert_eq!(json["resource_type"], "identity");
    assert_eq!(json["success"], true);
}

// ---------------------------------------------------------------------------
// 第九批：init_service 错误臂 / auto-lock 事件桥闭环 / 路径工具
// ---------------------------------------------------------------------------

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

/// auto-lock 事件桥的闭环：Locked 事件触发后，回调 emit 事件并在后台任务
/// 里强制 `service.lock()` 清掉内存主密钥（不依赖前端存活）。
#[tokio::test]
async fn auto_lock_event_bridge_force_locks_on_locked_event() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    // init_service 已注册 bridge 回调。

    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true), "fresh init must be unlocked");

    {
        let state = app.state::<AppState>();
        let mut guard = state.service.lock().await;
        let service = guard.as_mut().expect("service initialized");

        // 首次 init 只调 initialize_user，不建立 auto-lock session（真实
        // 产品行为：会话在认证时创建）；走一次 lock → 认证来建立 session，
        // 与前端「初始化 → 锁定 → 再解锁」的真实链路一致。
        service.lock();
        let result = service.authenticate_user("correct-horse").await.unwrap();
        assert!(matches!(result, persona_core::AuthResult::Success));

        // 通过公开 API 手动触发 Locked 事件（与超时监控同一 emit 路径，
        // 无需等待真实定时器）。
        service.force_lock_session().await.expect("force lock");
    }

    // 回调异步执行：轮询等待强制落锁生效。
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

/// workspace 路径推导：裸文件名的 parent 是空串而非 None
/// （Path::parent 语义），落库时由上层 filter 回落到默认名。
#[test]
fn workspace_path_for_db_path_handles_bare_names() {
    assert_eq!(workspace_path_for_db_path("/tmp/x/vault.db"), "/tmp/x");
    // Path::new("bare.db").parent() == Some("")，不触发 unwrap_or_else。
    assert_eq!(workspace_path_for_db_path("bare.db"), "");
}

// ---------------------------------------------------------------------------
// 第十批：类型/等级矩阵、get_credential_data 全变体标签、锁定错误码矩阵、
// wallet 网络/DB 失败分支、agent 状态目录回退、agent 协议读错误
// ---------------------------------------------------------------------------

/// update_identity 的 identity_type 全臂 + 可选字段"空白即清除"归一化。
#[tokio::test]
async fn identity_update_type_matrix_and_optional_field_normalization() {
    let (app, identity_id) = app_with_identity().await;

    // 逐个驱动 identity_type 的映射臂（Personal 已由既有测试覆盖）。
    for (type_str, expected) in [
        ("Work", "Work"),
        ("Social", "Social"),
        ("Financial", "Financial"),
        ("Gaming", "Gaming"),
        ("Team Secret", "Team Secret"),
    ] {
        let resp = update_identity(
            UpdateIdentityRequest {
                id: identity_id.clone(),
                name: "Matrix Identity".to_string(),
                identity_type: type_str.to_string(),
                description: None,
                email: None,
                phone: None,
                tags: None,
            },
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{type_str}: {:?}", resp.error);
        let updated = resp.data.expect("identity updated");
        assert_eq!(updated.identity_type, expected, "arm for {type_str}");
    }

    // description/email/phone 传纯空白 → 归一化为 None（三个 and_then 臂）。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: identity_id.clone(),
            name: "Cleared".to_string(),
            identity_type: "personal".to_string(),
            tags: None,
            description: Some("   ".to_string()),
            email: Some(" \t ".to_string()),
            phone: Some("  ".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let updated = resp.data.expect("identity updated");
    assert_eq!(updated.description, None);
    assert_eq!(updated.email, None);
    assert_eq!(updated.phone, None);

    // 不存在的 id → "Identity not found"。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Ghost".to_string(),
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
    assert_eq!(resp.error.as_deref(), Some("Identity not found"));
}

/// create_credential 的 credential_type/security_level 字符串臂矩阵，
/// 以及 url/username/notes/tags 的归一化臂。
#[tokio::test]
async fn create_credential_type_and_security_level_matrix() {
    let (app, identity_id) = app_with_identity().await;

    let base = |name: &str, type_str: &str, level: &str| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: type_str.to_string(),
        security_level: level.to_string(),
        url: Some("https://matrix.example".to_string()),
        username: Some("alice".to_string()),
        notes: Some("  kept  ".to_string()),
        tags: Some(vec!["a".to_string(), "  ".to_string(), "b".to_string()]),
        credential_data: CredentialDataRequest::Raw {
            data: vec![1, 2, 3],
        },
    };

    // credential_type 的非 Password 臂（Password/TwoFactor 已有测试覆盖）。
    for type_str in [
        "CryptoWallet",
        "SshKey",
        "ApiKey",
        "BankCard",
        "GameAccount",
        "ServerConfig",
        "Certificate",
        "CustomStyle",
    ] {
        let resp = create_credential(
            base("Matrix", type_str, "Critical"),
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{type_str}: {:?}", resp.error);
        let cred = resp.data.expect("credential created");
        assert_eq!(cred.credential_type, type_str);
        assert_eq!(cred.security_level, "Critical");
        assert_eq!(cred.url.as_deref(), Some("https://matrix.example"));
        assert_eq!(cred.username.as_deref(), Some("alice"));
        assert_eq!(cred.notes.as_deref(), Some("kept"));
        assert_eq!(cred.tags, vec!["a".to_string(), "b".to_string()]);

        // security_level 的其余臂 + 未知值回落 Medium。
        for (level, expected) in [("High", "High"), ("Low", "Low"), ("Bogus", "Medium")] {
            let mut req = base("Levels", type_str, level);
            req.name = format!("Levels-{type_str}-{level}");
            let resp = create_credential(req, app.state::<AppState>())
                .await
                .unwrap();
            assert!(resp.success, "{type_str}/{level}: {:?}", resp.error);
            assert_eq!(resp.data.expect("credential").security_level, expected);
        }

        let resp = delete_credential(cred.id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
    }

    // 坏 identity UUID 在 get_credentials_for_identity 上同样失败关闭。
    let resp = get_credentials_for_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}

/// get_credential_data 对全部 8 种 CredentialData 变体输出正确的类型标签。
/// BankCard/ServerConfig 没有对应的命令层请求变体，直接经 service 构造。
#[tokio::test]
async fn get_credential_data_returns_type_labels_for_all_variants() {
    use persona_core::models::credential::{BankCardData, ServerConfigData};

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    // 经命令层建 6 种（Password/CryptoWallet/SshKey/ApiKey/TwoFactor/Raw）。
    let request_for = |name: &str, data: CredentialDataRequest| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: "Raw".to_string(),
        security_level: "Medium".to_string(),
        url: None,
        username: None,
        notes: None,
        tags: None,
        credential_data: data,
    };
    let mut ids: Vec<(String, String)> = Vec::new();
    let variants: Vec<(&str, CredentialDataRequest)> = vec![
        (
            "PW",
            CredentialDataRequest::Password {
                password: "s3cret".to_string(),
                email: None,
                security_questions: vec![],
            },
        ),
        (
            "CW",
            CredentialDataRequest::CryptoWallet {
                wallet_type: "hd".to_string(),
                mnemonic_phrase: None,
                private_key: None,
                public_key: "pub".to_string(),
                address: "0xabc".to_string(),
                network: "Ethereum".to_string(),
            },
        ),
        (
            "SSH",
            CredentialDataRequest::SshKey {
                private_key: "priv".to_string(),
                public_key: "pub".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            },
        ),
        (
            "API",
            CredentialDataRequest::ApiKey {
                api_key: "key".to_string(),
                api_secret: None,
                token: None,
                permissions: vec![],
                expires_at: None,
            },
        ),
        (
            "TOTP",
            CredentialDataRequest::TwoFactor {
                secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                issuer: "i".to_string(),
                account_name: "a".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
            },
        ),
        ("RAW", CredentialDataRequest::Raw { data: vec![9] }),
    ];
    for (name, data) in variants {
        let resp = create_credential(request_for(name, data), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{name}: {:?}", resp.error);
        ids.push((resp.data.expect("created").id, name.to_string()));
    }

    // BankCard/ServerConfig 直经 service 建（命令层请求枚举没有这两种）。
    {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        for data in [
            persona_core::models::credential::CredentialData::BankCard(BankCardData {
                card_number: "4111111111111111".to_string(),
                cardholder_name: "Alice".to_string(),
                expiry_date: "12/30".to_string(),
                cvv: "123".to_string(),
                bank_name: "Test Bank".to_string(),
                card_type: "visa".to_string(),
            }),
            persona_core::models::credential::CredentialData::ServerConfig(ServerConfigData {
                hostname: "server.example".to_string(),
                ip_address: None,
                port: 22,
                protocol: "ssh".to_string(),
                username: "root".to_string(),
                password: None,
                ssh_key_id: None,
                additional_config: std::collections::HashMap::new(),
            }),
        ] {
            let cred = service
                .create_credential(
                    identity_uuid,
                    format!("direct-{}", ids.len()),
                    persona_core::models::credential::CredentialType::Custom("Direct".into()),
                    persona_core::models::credential::SecurityLevel::Medium,
                    &data,
                )
                .await
                .unwrap();
            ids.push((cred.id.to_string(), "DIRECT".to_string()));
        }
    }

    // 逐一读回：类型标签与存储变体一一对应。
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{id}: {:?}", resp.error);
        let wrapper = resp.data.expect("data returned").expect("data present");
        assert!(
            [
                "Password",
                "CryptoWallet",
                "SshKey",
                "ApiKey",
                "TwoFactor",
                "Raw",
                "BankCard",
                "ServerConfig"
            ]
            .contains(&wrapper.credential_type.as_str()),
            "unexpected label {}",
            wrapper.credential_type
        );
    }
    // 8 个凭据的标签合计必须覆盖全部 8 种。
    let mut labels = std::collections::HashSet::new();
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        labels.insert(resp.data.unwrap().unwrap().credential_type);
    }
    assert_eq!(labels.len(), 8, "all 8 variant labels covered: {labels:?}");

    // 坏 UUID 仍是格式错误。
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
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
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
}

/// wallet_add_address 的 Bitcoin P2WPKH 派生臂与 Solana"未实现"拒绝臂。
#[tokio::test]
async fn wallet_add_address_bitcoin_and_unsupported_network() {
    let (app, identity_id) = app_with_identity().await;

    // BTC HD 钱包（1 地址）→ 追加地址走 Bitcoin P2WPKH 派生臂。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "BTC HD".to_string(),
            network: "bitcoin".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc = resp.data.expect("btc imported");

    let resp = wallet_add_address(
        btc.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addr = resp.data.expect("address added");
    assert!(
        addr.address.starts_with("bc1"),
        "P2WPKH bech32 address, got {}",
        addr.address
    );
    assert_eq!(addr.address_type, "P2WPKH");
    assert_eq!(addr.index, 1, "next index after the seeded first address");

    // 地址生成未实现的网络：core 的 import/generate 都在派生阶段就拒绝
    //（derive_addresses 对非 BTC/ETH 系报 not implemented），所以拿已导入
    // 的 BTC HD 钱包把 network 改写为 Litecoin（等价于旧版本遗留钱包），
    // 让 add_address 走完派生后撞上命令层的 not-implemented 拒绝臂。
    let wallet_id = uuid::Uuid::parse_str(&btc.id).unwrap();
    {
        let db_path = app
            .state::<AppState>()
            .db_path
            .lock()
            .await
            .clone()
            .expect("db path set by wallet_import");
        let db = persona_core::storage::Database::from_file(&db_path)
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = persona_core::storage::CryptoWalletRepository::new(std::sync::Arc::new(db));
        let mut wallet = repo
            .find_by_id(&wallet_id)
            .await
            .unwrap()
            .expect("wallet persisted");
        wallet.network = persona_core::models::wallet::BlockchainNetwork::Litecoin;
        repo.update(&wallet).await.unwrap();
    }

    let resp = wallet_add_address(
        btc.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let msg = resp.error.expect("error message");
    assert!(
        msg.contains("Address generation not implemented for Litecoin"),
        "got: {msg}"
    );
}

/// db_path 坏文件/坏目录时 wallet 命令大声报连接或迁移错误（sqlx 惰性
/// 连接：from_file 不检查文件内容，migrate 才暴露 "not a database"）。
#[tokio::test]
async fn wallet_commands_report_db_path_failures_loudly() {
    let (app, identity_id) = app_with_identity().await;

    // 指向不存在目录 → 连接失败。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some("/nonexistent-dir-for-persona-tests/bad.db".to_string());
    }
    // 连接失败：基础设施错误走 Ok(ApiResponse::error)，不逃出命令边界。
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Database connection failed")),
        "got: {:?}",
        resp.error
    );

    // 垃圾文件：from_file 的 connect 能打开任意可读文件，migrate 执行时
    // 才撞上 (code: 26) file is not a database → "Database migration failed"。
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"definitely not a sqlite database").unwrap();
    let junk_path = junk.to_string_lossy().to_string();
    // 保留 tempdir 到测试结束（list/addresses/import/generate 均复用）。
    std::mem::forget(dir);
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk_path.clone());
    }

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Database migration failed") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "g".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );
}

/// PERSONA_AGENT_STATE_DIR 未设置时 agent_state_dir 回落 ~/.persona。
#[test]
fn agent_state_dir_falls_back_to_home_when_env_unset() {
    let _guard = crate::command_layer_tests::StateDirGuard::without_env();
    let dir = agent_state_dir();
    assert!(
        dir.ends_with(".persona"),
        "fallback should be ~/.persona, got {dir:?}"
    );
}

/// agent key-count 协议：服务端 accept 后立即断开 → 客户端读响应
/// 长度时命中 EOF，返回 Err 而非挂死。
#[test]
fn query_agent_key_count_fails_on_dead_socket() {
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("dead.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    // 服务端：接受连接后立刻丢弃，制造对端 EOF。
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("client connects");
        drop(stream);
    });

    let result = query_agent_key_count(sock_path.to_str().unwrap());
    assert!(result.is_err(), "dead socket must error, not hang");

    server.join().unwrap();
}

// ---------------------------------------------------------------------------
// 第十一批：active_identity DB 失败、默认 db_path、活跃身份清理、
// 锁定态凭据/审计错误、wallet_generate 类型拒绝、pending 交易与缺 db_path
// ---------------------------------------------------------------------------

/// 互斥地把 XDG_DATA_HOME 指到临时目录（dirs::data_dir 的 Linux 读法），
/// 驱动 init_service 的默认 db_path 分支而不触碰真实用户目录。
struct XdgDataDirGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

impl XdgDataDirGuard {
    pub(crate) fn sandbox(dir: &tempfile::TempDir) -> Self {
        static XDG_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let mutex = XDG_LOCK.get_or_init(|| std::sync::Mutex::new(()));
        let lock = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev = std::env::var("XDG_DATA_HOME").ok();
        std::env::set_var("XDG_DATA_HOME", dir.path());
        XdgDataDirGuard {
            _lock: lock,
            prev: prev.map(Into::into),
        }
    }
}

impl Drop for XdgDataDirGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(prev) => std::env::set_var("XDG_DATA_HOME", prev),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
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

/// get/set/clear_active_identity 在 db_path 打不开时大声报错
///（from_file/migrate 错误臂）。
#[tokio::test]
async fn active_identity_commands_report_db_failures() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let state = || app.state::<AppState>();

    // 垃圾文件：connect 打开成功、migrate 才报 not a database。
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"still not a database").unwrap();
    std::mem::forget(dir);
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk.to_string_lossy().to_string());
    }

    // 基础设施失败一律 Ok(ApiResponse::error)：success=false + error 落消息。
    let resp = get_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = set_active_identity(uuid::Uuid::new_v4().to_string(), state())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = clear_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    // 不存在目录：from_file 的 connect 直接失败。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some("/nonexistent-dir-for-persona-tests/x.db".to_string());
    }
    let resp = get_active_identity(state()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Database connection failed")),
        "got: {:?}",
        resp.error
    );
}

/// 删除当前活跃的 identity 时，workspace 的 active_identity_id 指针被清空。
#[tokio::test]
async fn delete_active_identity_clears_workspace_pointer() {
    let (app, identity_id) = app_with_identity().await;

    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(Some(identity_id.clone())));

    let resp = delete_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(None),
        "deleting the active identity must clear the pointer"
    );
}

/// 锁定态下凭据/身份命令的 service 错误臂（这批臂输出普通错误消息，
/// 不映射错误码）+ 审计三命令的映射错误码臂。
#[tokio::test]
async fn locked_service_credential_error_surface() {
    let (app, identity_id) = app_with_identity().await;
    let existing = uuid::Uuid::new_v4().to_string();
    lock_service(app.state::<AppState>()).await.unwrap();

    // update_identity 的 get_identity Err 臂。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: existing.clone(),
            name: "n".to_string(),
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
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get identity"),
        "got: {:?}",
        resp.error
    );

    // toggle_credential_favorite 的 get_credential Err 臂。
    let resp = toggle_credential_favorite(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    // delete_credential 的 delete Err 臂。
    let resp = delete_credential(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    // 审计三命令的 query/statistics/cleanup Err 臂。
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
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
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // 解锁恢复后统计可正常返回（保证上面的失败只来自锁定）。
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // identity_id 仍在（上述操作都失败回滚）。
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().iter().any(|i| i.id == identity_id));
}

/// wallet_generate 拒绝未支持的 wallet_type。
#[tokio::test]
async fn wallet_generate_rejects_unsupported_wallet_type() {
    let (app, identity_id) = app_with_identity().await;
    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "ledger".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Unsupported wallet_type 'ledger'. Use 'hd'.")
    );
}

/// wallet_pending_transactions 列出未签名请求；db_path 缺失时报
/// "Database path unavailable"（wallet_db 的 None 臂）。
#[tokio::test]
async fn wallet_pending_transactions_round_trip_and_missing_db() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "Pending Wallet".to_string(),
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

    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id.clone(),
            to_address: "0x2222222222222222222222222222222222222222".to_string(),
            amount: "1000000000000000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("20000000000".to_string()),
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("pending request created");
    let request_id = created["id"].as_str().expect("request id").to_string();

    // 列出 pending：包含刚创建的请求。
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"].as_str(), Some(request_id.as_str()));

    // db_path 缺失：wallet_db 报 "Database path unavailable"。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = None;
    }
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id,
            to_address: "0x2222222222222222222222222222222222222222".to_string(),
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
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
}

/// 已解锁但 DB 是垃圾文件的 service：sqlx 连接惰性打开，任何 repo 查询才
/// 报错。init_service 到不了这个状态（migrate 会先失败），所以手工构造
/// service——用它驱动命令层不可绕过的 repo 错误臂。db_path 也指向同一
/// 垃圾文件，让自建连接的 workspace/wallet 命令共享同一错误路径。
async fn app_with_garbage_db_service() -> tauri::App<tauri::test::MockRuntime> {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("garbage.db");
    std::fs::write(&bad_path, "not a sqlite database").unwrap();
    // Leak the TempDir: the service keeps the file open for the whole test.
    std::mem::forget(dir);
    let db = persona_core::Database::from_file(&bad_path).await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("correct-horse", &salt).unwrap();
    *app.state::<AppState>().service.lock().await = Some(service);
    *app.state::<AppState>().db_path.lock().await = Some(bad_path.to_string_lossy().to_string());
    app
}

#[tokio::test]
async fn identity_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();
    let expect_db_err = |msg: &str| {
        assert!(
            msg.contains("file is not a database"),
            "expected sqlite error, got: {msg}"
        );
    };

    // list 走精确消息（探针验证过的形态），其余断言前缀 + 底层错误。
    let resp = get_identities(state.clone()).await.unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some(
            "Failed to get identities: Database operation failed: error returned from database: (code: 26) file is not a database"
        )
    );

    let resp = get_identity(bogus.clone(), state.clone()).await.unwrap();
    expect_db_err(resp.error.as_deref().unwrap_or_default());

    let resp = create_identity(
        CreateIdentityRequest {
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref().map(|m| &m[..17]),
        Some("Failed to create ")
    );
    expect_db_err(resp.error.as_deref().unwrap_or_default());

    let resp = update_identity(
        UpdateIdentityRequest {
            id: bogus.clone(),
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get identity"),
        "got: {:?}",
        resp.error
    );

    let resp = delete_identity(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to delete identity"),
        "got: {:?}",
        resp.error
    );

    let resp = export_identity(bogus.clone(), state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to export identity"),
        "got: {:?}",
        resp.error
    );

    let resp = get_statistics(state.clone()).await.unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get statistics"),
        "got: {:?}",
        resp.error
    );

    let resp = search_credentials("needle".to_string(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to search credentials"),
        "got: {:?}",
        resp.error
    );

    // touch 只动内存时间戳，坏库也必须成功。
    let resp = touch_activity(state).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));
}

#[tokio::test]
async fn credential_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    let resp = get_credentials_for_identity(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credentials"),
        "got: {:?}",
        resp.error
    );

    let resp = create_credential(password_credential_request(&bogus), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to create credential"),
        "got: {:?}",
        resp.error
    );

    let resp = toggle_credential_favorite(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    let resp = delete_credential(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    let resp = get_credential_data(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential data"),
        "got: {:?}",
        resp.error
    );

    // totp 与其他命令同纪律：基础设施错误落 Ok(ApiResponse::error)。
    let resp = get_totp_code(bogus.clone(), state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("file is not a database")),
        "expected sqlite error, got: {:?}",
        resp.error
    );

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: bogus.clone(),
            field: "password".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to reveal secret"),
        "got: {:?}",
        resp.error
    );

    // 扫描靠 repo 拉全量凭据，坏库必须给出错误报告（Ok 包错误体）。
    let resp = health_scan(None, state).await.unwrap();
    assert!(!resp.success);
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
async fn missing_and_malformed_ids_take_their_own_error_arms() {
    let app = mock_app();

    // 未初始化：各命令的 None service 臂。
    let resp = get_identity(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = create_identity(
        CreateIdentityRequest {
            name: "X".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = create_credential(
        password_credential_request("00000000-0000-0000-0000-000000000000"),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = toggle_credential_favorite(
        "00000000-0000-0000-0000-000000000000".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 初始化后：合法 UUID 但不存在的资源。
    let (app, _identity_id) = app_with_identity().await;
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    // get 对缺失 id 返回 Ok(None)（success=true，无 error）。
    let resp = get_identity(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success);
    assert!(
        matches!(resp.data, Some(None)),
        "missing identity returns Ok(None)"
    );

    // update 先查再改：缺失 id 在查询步就被拒。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: bogus.clone(),
            name: "X".to_string(),
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
    assert_eq!(resp.error.as_deref(), Some("Identity not found"));

    let resp = create_credential(
        password_credential_request("not-a-uuid"),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    let resp = toggle_credential_favorite(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));

    let resp = delete_credential(bogus.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.data, Some(false), "delete of missing id is a no-op");

    // 非法 UUID 先于 repo 到达自己的错误臂。
    let resp = delete_credential("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
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
async fn get_active_identity_without_db_path_degrades_loudly() {
    let app = mock_app();

    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
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
        },
        state,
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp);
    assert_eq!(resp.data.expect("reveal").value, "s3cret-password");
}

// ---------------------------------------------------------------------------
// 第十六批：active identity / wallet / ssh 命令的前置条件与死库矩阵
// ---------------------------------------------------------------------------

/// active identity 三命令的前置臂：未初始化、锁定、非法 UUID、db_path 缺失，
/// 外加 clear_active_identity 的成功路径（此前只有失败路径有覆盖）。
#[tokio::test]
async fn active_identity_precondition_matrix() {
    // 未初始化：None service 臂在 UUID 解析之前拦下 set。
    let app = mock_app();
    let resp = set_active_identity("not-even-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 锁定态：unlock 检查在 UUID 解析之前。
    let (app, identity_id) = app_with_identity().await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = set_active_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    // 已解锁：UUID 解析在 db_path 检查之前，非法 UUID 走自己的错误臂。
    let (app, identity_id) = app_with_identity().await;
    let resp = set_active_identity("bad-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // db_path 缺失：set/clear 都落同一句 ApiResponse 错误。
    let original_db_path = {
        let state = app.state::<AppState>();
        let path = state.db_path.lock().await.clone();
        *state.db_path.lock().await = None;
        path.expect("init_service_ok set a db path")
    };
    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );

    // 恢复路径后 clear 走完整成功链（ensure_workspace → 清指针 → 落库）。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(original_db_path);
    }
    let resp = set_active_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = clear_active_identity(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_active_identity(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(None), "clear must remove the pointer");
}

/// 五个此前只覆盖成功/半覆盖路径的 wallet 命令（add_address/delete/export/
/// create_transaction/sign_transaction）的前置臂与死库矩阵：
/// None service → Ok(error)（wallet_db 路径为 Err）、locked → 同型、
/// 短密码专属臂、db_path 缺失 → Err、垃圾库 → migrate 失败。
#[tokio::test]
async fn wallet_five_commands_precondition_and_dead_db_matrix() {
    let export_request = || WalletExportRequest {
        wallet_id: uuid::Uuid::new_v4().to_string(),
        format: "json".to_string(),
        include_private: false,
        password: None,
    };
    let create_request = |wallet_id: &str| WalletCreateTransactionRequest {
        wallet_id: wallet_id.to_string(),
        to_address: "0x2222222222222222222222222222222222222222".to_string(),
        amount: "1".to_string(),
        fee: "21000".to_string(),
        gas_price: None,
        gas_limit: None,
        nonce: None,
        memo: None,
        expires_in_minutes: None,
    };
    let sign_request = |wallet_id: &str| WalletSignTransactionRequest {
        transaction_id: wallet_id.to_string(),
        password: "wallet-pass-123".to_string(),
    };

    // 场景 A：未初始化。add/delete/export 返回 Ok 包错误体；
    // create/sign 先解析 UUID 再走 wallet_db 的 Err 臂。
    let app = mock_app();
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "pw".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_create_transaction(
        create_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_sign_transaction(
        sign_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 场景 B：锁定。同型消息，wallet_db 路径的锁定语义带码落 ApiResponse。
    let (app, _identity_id) = app_with_identity().await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "pw".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_create_transaction(
        create_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
    let resp = wallet_sign_transaction(
        sign_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // 场景 C/D：已解锁。短密码专属臂、db_path 缺失、垃圾库 migrate 失败。
    let (app, _identity_id) = app_with_identity().await;

    // add_address：合法 UUID 但密码太短（UUID 解析之后、db_path 之前）。
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "short".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );
    // delete 的 UUID 解析在 db_path 之后——用非法 UUID 顺带钉住顺序。
    let resp = wallet_delete("bad-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet UUID format"));

    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"junk for wallet matrix").unwrap();
    let junk_path = junk.to_string_lossy().to_string();
    std::mem::forget(dir);

    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = None;
    }
    let wallet_uuid = uuid::Uuid::new_v4().to_string();
    fn expect_db_path_err<T>(resp: &ApiResponse<T>) {
        assert!(!resp.success);
        assert_eq!(
            resp.error.as_deref(),
            Some("Database path unavailable. Initialize the service first.")
        );
    }
    let resp = wallet_add_address(
        wallet_uuid.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_delete(wallet_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_sign_transaction(sign_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);

    // 垃圾库：migrate 才撞 not a database。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk_path);
    }
    fn expect_junk_err<T>(resp: &ApiResponse<T>) {
        assert!(!resp.success);
        assert!(
            resp.error
                .as_deref()
                .is_some_and(|e| e.contains("not a database")),
            "got: {:?}",
            resp.error
        );
    }
    let resp = wallet_add_address(
        wallet_uuid.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Database migration failed") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );
    let resp = wallet_delete(wallet_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_sign_transaction(sign_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_create_transaction(create_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
}

/// get_ssh_keys 的未初始化/死库臂与 stop_ssh_agent 的空转臂（无 agent 可停
/// 也要返回成功并清理环境变量）。
#[tokio::test]
async fn ssh_key_listing_and_agent_stop_small_arms() {
    let app = mock_app();
    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = stop_ssh_agent(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));

    // 已解锁但 DB 是垃圾文件：get_identities 的 repo 错误落 ApiResponse。
    let app = app_with_garbage_db_service().await;
    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Failed to load identities") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );
}

/// create_identity 的 identity_type 大写/自定义全臂（354-359 的 match）。
#[tokio::test]
async fn create_identity_type_match_arms_all_reachable() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // 大写形式走专用枚举臂，任意其他字符串走 Custom 原样回显。
    for label in [
        "Personal",
        "Work",
        "Social",
        "Financial",
        "Gaming",
        "banking-alt",
    ] {
        let resp = create_identity(
            CreateIdentityRequest {
                name: format!("Typed {label}"),
                identity_type: label.to_string(),
                description: None,
                email: None,
                phone: None,
            },
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{label}: {:?}", resp.error);
        let identity = resp.data.expect("identity created");
        assert_eq!(identity.name, format!("Typed {label}"));
    }
}

/// ensure_workspace_for_path 的 create 分支：workspace_path 无 file_name
/// （如 "/"）时工作区名叫 "Persona"。需要空库——已有单个 workspace 时
/// 先走 len==1 迁移分支（改写 path 返回），到不了 name 计算。
#[tokio::test]
async fn workspace_name_falls_back_to_persona_for_root_paths() {
    assert_eq!(workspace_path_for_db_path("/"), ".");

    let dir = tempfile::tempdir().unwrap();
    let db = persona_core::Database::from_file(dir.path().join("w.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();

    let ws = ensure_workspace_for_path(&db, "/").await.unwrap();
    assert_eq!(ws.name, "Persona");
    assert_eq!(ws.path.to_string_lossy(), "/");

    // 同路径二次调用走 find 分支，名字不被重建覆盖。
    let ws = ensure_workspace_for_path(&db, "/").await.unwrap();
    assert_eq!(ws.name, "Persona");
}

/// wallet_list_addresses 的 AddressType 标签全臂（命令内联 match，与
/// serialize_wallet_address 单测不共享）；wallet_generate 的非法 UUID 臂；
/// passkey_create 的非法 base64 两臂。
#[tokio::test]
async fn wallet_address_labels_and_passkey_create_base64_gates() {
    let (app, identity_id) = app_with_identity().await;

    // wallet_generate：非法 identity_id 在任何 db 操作前拦下。
    let resp = wallet_generate(
        "bad-uuid".to_string(),
        WalletGenerateRequest {
            name: "g".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // 手工插一个七种地址类型齐全的钱包，驱动命令内联 match 全臂。
    let db_path = {
        let state = app.state::<AppState>();
        let guard = state.db_path.lock().await;
        guard.clone().expect("db path set")
    };
    let db = Arc::new(persona_core::Database::from_file(&db_path).await.unwrap());
    db.migrate().await.unwrap();
    let mut wallet = persona_core::models::wallet::CryptoWallet::new(
        uuid::Uuid::parse_str(&identity_id).unwrap(),
        "All Address Types".to_string(),
        persona_core::models::wallet::BlockchainNetwork::Bitcoin,
        persona_core::models::wallet::WalletType::HierarchicalDeterministic {
            bip_version: persona_core::models::wallet::BipVersion::Bip84,
            address_count: 7,
            gap_limit: 20,
        },
        vec![1, 2, 3],
    );
    let cases = [
        (persona_core::models::wallet::AddressType::P2PKH, "P2PKH"),
        (persona_core::models::wallet::AddressType::P2SH, "P2SH"),
        (persona_core::models::wallet::AddressType::P2WPKH, "P2WPKH"),
        (persona_core::models::wallet::AddressType::P2TR, "P2TR"),
        (persona_core::models::wallet::AddressType::Ethereum, "ETH"),
        (persona_core::models::wallet::AddressType::Solana, "SOL"),
    ];
    for (i, (address_type, _)) in cases.iter().enumerate() {
        wallet
            .addresses
            .push(persona_core::models::wallet::WalletAddress {
                address: format!("addr-{i}"),
                address_type: address_type.clone(),
                derivation_path: Some(format!("m/0/{i}")),
                index: i as u32,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: chrono::Utc::now(),
            });
    }
    // Custom 变体的标签就是自定义名本身。
    wallet
        .addresses
        .push(persona_core::models::wallet::WalletAddress {
            address: "addr-custom".to_string(),
            address_type: persona_core::models::wallet::AddressType::Custom(
                "my-custom-chain".to_string(),
            ),
            derivation_path: None,
            index: 99,
            used: false,
            balance: Some("1.5".to_string()),
            last_activity: None,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        });
    persona_core::storage::wallet_repository::CryptoWalletRepository::new(db.clone())
        .create(&wallet)
        .await
        .unwrap();

    let resp = wallet_list_addresses(wallet.id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addresses = resp.data.expect("addresses").addresses;
    assert_eq!(addresses.len(), cases.len() + 1);
    for (addr, (_, label)) in addresses.iter().zip(cases.iter()) {
        assert_eq!(addr.address_type, *label);
    }
    assert_eq!(
        addresses.last().unwrap().address_type,
        "my-custom-chain",
        "custom type renders its own name"
    );

    // passkey_create：client_data_json_b64 非法 base64 → 专属错误体。
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id: identity_id.clone(),
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: "!!!not-base64!!!".to_string(),
            user_handle_b64: None,
            user_name: None,
            user_display_name: None,
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Invalid client_data_json_b64")),
        "got: {:?}",
        resp.error
    );

    // user_handle_b64 非法 base64 → 第二道门。
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id,
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: "e30=".to_string(), // "{}"
            user_handle_b64: Some("@@@".to_string()),
            user_name: None,
            user_display_name: None,
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Invalid user_handle_b64")),
        "got: {:?}",
        resp.error
    );
}

// ---------------------------------------------------------------------------
// Workspace settings / feature flags / passkey 审批服务端门禁
// ---------------------------------------------------------------------------

#[tokio::test]
async fn workspace_settings_round_trip_through_get_and_set_feature_flags() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // 全新 vault：flags 默认全关，其余字段保持 core 默认
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

    // 窄写 features，返回更新后的全量 settings
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

    // get 反映持久化结果
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.features.ssh_agent);

    // 部分开启：只动 features 四个位
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

    // 未初始化：set 拒绝
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

    // get 免解锁约束（解锁屏也要按 flags 裁剪 UI），set 需要解锁
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

/// set_feature_flags 的开关联动：开 passkeys → 审批服务端本会话即时拉起
/// （不再等 lock→unlock）；关 passkeys → 发送关停信号、复位幂等标记、
/// 丢弃残留审批；关 ssh_agent → 运行中的 agent 被停止。
#[tokio::test]
async fn set_feature_flags_toggles_passkey_server_and_ssh_agent_lifecycle() {
    use std::sync::atomic::Ordering;

    // 联动启动会真 spawn 服务端 bind 真 socket：重定向 agent state dir
    let state_dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&state_dir);

    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 开 passkeys + ssh_agent：即时拉起（fresh vault 默认全关，prev 全 false）
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

    // 造残留状态：一条未应答审批 + 一个运行中的 agent handle + confirm env
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

    // 关 passkeys + ssh_agent：联动停止
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

// ---------------------------------------------------------------------------
// 同步服务器配置（settings.sync）与审计事件上报器接线
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_sync_config_stores_token_in_keyring_and_remembers_on_blank() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // 全新 vault：sync 段为 None、keyring 无 token
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.sync.is_none(), "fresh vault has no sync config");
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "fresh vault has no stored token");

    // 窄写 sync 段：token 进 keyring，vault JSON 恒存空串
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let sync = resp.data.expect("updated settings").sync.expect("sync set");
    assert!(sync.enabled);
    assert_eq!(sync.server_url, "http://127.0.0.1:1");
    assert_eq!(sync.server_token, "", "vault JSON never holds the token");
    assert_eq!(
        app.state::<AppState>()
            .token_store
            .get(&db_path)
            .unwrap()
            .as_deref(),
        Some("tok-1")
    );

    // get 反映持久化结果：sync 段可见，token 不经 IPC 回读
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let sync = resp.data.expect("settings present").sync.expect("sync set");
    assert_eq!(sync.server_token, "");
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true));

    // token 空串 = 保留 keyring 既有令牌
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:2".to_string(),
        String::new(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let sync = resp.data.expect("updated settings").sync.expect("sync set");
    assert_eq!(sync.server_url, "http://127.0.0.1:2");
    assert_eq!(
        app.state::<AppState>()
            .token_store
            .get(&db_path)
            .unwrap()
            .as_deref(),
        Some("tok-1"),
        "blank token keeps the stored one"
    );

    // 关闭 sync：enabled=false 持久化，keyring 令牌一并清除
    let resp = set_sync_config(
        false,
        "http://127.0.0.1:2".to_string(),
        String::new(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let sync = resp.data.expect("updated settings").sync.expect("sync set");
    assert!(!sync.enabled);
    assert_eq!(
        app.state::<AppState>().token_store.get(&db_path).unwrap(),
        None,
        "disabling sync clears the stored token"
    );
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false));
}

/// keyring 不可用（headless/无 secret service）时提交非空 token：
/// 拒绝保存，vault 不落任何明文配置。
#[tokio::test]
async fn set_sync_config_refuses_save_when_keyring_unavailable() {
    struct FailingTokenStore;
    impl TokenStore for FailingTokenStore {
        fn set(&self, _: &str, _: &str) -> Result<(), String> {
            Err("no secret service".to_string())
        }
        fn get(&self, _: &str) -> Result<Option<String>, String> {
            Err("no secret service".to_string())
        }
        fn delete(&self, _: &str) -> Result<(), String> {
            Err("no secret service".to_string())
        }
    }

    let app = mock_app_with_token_store(Arc::new(FailingTokenStore));
    init_service_ok(&app, "master-pw-123").await;

    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Cannot store sync token in OS keyring")),
        "unexpected error: {:?}",
        resp.error
    );

    // 保存被拒：vault 里不写任何 sync 配置（token 与 url 都不落）
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.sync.is_none(), "refused save must not persist");

    // 关闭路径不写 keyring：禁用（尽力删除失败仅 warn）仍可保存
    let resp = set_sync_config(false, String::new(), String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

/// keyring 里没有 token 时 attach fail-closed（不挂上报器）；
/// token 就位后同一配置恢复挂载。
#[tokio::test]
async fn attach_sync_emitter_fails_closed_without_keyring_token() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // 配置 enabled + url，token 也在 keyring：正常挂载
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_some());

    // 模拟 keyring 条目丢失（他机恢复 vault / 手工删除）：attach 摘除
    app.state::<AppState>()
        .token_store
        .delete(&db_path)
        .unwrap();
    attach_sync_emitter(&app.state::<AppState>()).await;
    assert!(
        app.state::<AppState>().sync_emitter.lock().await.is_none(),
        "missing keyring token must fail closed"
    );

    // token 恢复：同一配置重新挂载
    app.state::<AppState>()
        .token_store
        .set(&db_path, "tok-restored")
        .unwrap();
    attach_sync_emitter(&app.state::<AppState>()).await;
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_some());
}

/// legacy vault（keyring 批次前 DB 里存明文 token）：attach 一次性迁移
/// 进 keyring、DB 清为空串，上报正常挂载。
#[tokio::test]
async fn legacy_sync_token_migrates_to_keyring_on_attach() {
    use persona_core::models::SyncConfig;
    use persona_core::storage::{Database, Repository, WorkspaceRepository};

    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // 直接往 DB 写 keyring 批次之前的 legacy 明文配置
    let db = Database::from_file(&db_path).await.unwrap();
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = ensure_workspace_for_path(&db, &workspace_path)
        .await
        .unwrap();
    ws.settings.sync = Some(SyncConfig {
        enabled: true,
        server_url: "http://127.0.0.1:1".to_string(),
        server_token: "legacy-plaintext".to_string(),
    });
    ws.touch();
    repo.update(&ws).await.unwrap();

    attach_sync_emitter(&app.state::<AppState>()).await;

    // token 搬进 keyring，DB 清为空串，上报挂载
    assert_eq!(
        app.state::<AppState>()
            .token_store
            .get(&db_path)
            .unwrap()
            .as_deref(),
        Some("legacy-plaintext")
    );
    let db = Database::from_file(&db_path).await.unwrap();
    let repo = WorkspaceRepository::new(db);
    let ws = repo
        .find_by_path(&workspace_path)
        .await
        .unwrap()
        .expect("workspace row");
    let sync = ws.settings.sync.expect("sync set");
    assert!(sync.enabled);
    assert_eq!(sync.server_token, "", "legacy plaintext cleared from vault");
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_some());
}

#[tokio::test]
async fn set_sync_config_requires_unlocked_service() {
    let app = mock_app();

    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "t".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "master-pw-123").await;
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "t".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}

#[tokio::test]
async fn set_sync_config_rejects_blank_url_when_enabled() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    let resp = set_sync_config(
        true,
        "   ".to_string(),
        "t".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Server URL is required when sync is enabled")
    );

    // disabled + 空 url 合法（关闭上报但清掉 url）
    let resp = set_sync_config(false, String::new(), String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}

#[tokio::test]
async fn attach_sync_emitter_follows_saved_config() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // 未配置 sync：init 后槽位为 None，service 正常工作
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_none());

    // 保存 enabled 配置后立即重挂：槽位持有 emitter
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_some());

    // 关闭配置：槽位摘除（旧 emitter 已 stop，不构成双任务）
    let resp = set_sync_config(
        false,
        "http://127.0.0.1:1".to_string(),
        String::new(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_none());
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

    // set 在解锁检查处先拒绝（Service not initialized）
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

    // token 存在性查询同样要 db_path
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

    // 未初始化：fetch 报错、get 静默空数组
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

    // 锁定：fetch 报锁、get 静默空数组
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

    // 解锁但 flag 关（默认）：fetch 被后端兜底拒绝、get 静默空数组
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

    // flag 关时藏按钮不够——这里显式开后端才放行后续用例
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

    // 坏 UUID → Invalid UUID format（flag 检查通过后才轮到参数校验）
    let resp = fetch_credential_favicon("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // flag 开 + 凭据无 url → 拒绝（绝不外联）
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

    // flag 开的批量读是纯本地：空 hosts / 未缓存 host 都回成功 + 空数组
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

// ---------------------------------------------------------------------------
// Forced master-password rotation（PASSWORD_CHANGE_REQUIRED 码 / 改密命令 /
// password_expiry_days 窄写）
// ---------------------------------------------------------------------------

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
async fn change_master_password_command_rotates_and_allows_reinit() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "old-master-pw").await;

    // 锁定态轮换：命令自建全新 service（state.service 保持 None/旧实例不碰），
    // 前端随后用新密码重新 init
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

    // 旧密码从此被拒
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

    // 新密码 init 成功且服务解锁（会话照常建立）
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

    // 失败尝试不得损坏 vault：真密码依旧能建会话
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

// ---------------------------------------------------------------------------
// 旅行模式（Travel Mode）命令族
// ---------------------------------------------------------------------------

/// 初始化服务并建一个 identity，返回其 id。
async fn seeded_identity(app: &tauri::App<tauri::test::MockRuntime>, name: &str) -> String {
    let resp = create_identity(
        CreateIdentityRequest {
            name: name.to_string(),
            identity_type: "work".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    resp.data.expect("created identity returned").id
}

#[tokio::test]
async fn travel_status_starts_inactive_and_reports_sidecar_absent() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;

    let resp = get_travel_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(!status.active);
    assert!(!status.sidecar_exists);
    assert!(!status.inconsistent);
    assert_eq!(status.entered_at, None);
}

#[tokio::test]
async fn travel_mark_command_persists_and_lists_in_dto() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;
    let id = seeded_identity(&app, "Work").await;

    let resp = set_travel_marked(id.clone(), true, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));

    // DTO 透出 travel_marked（编辑表单开关的数据源）
    let resp = get_identity(id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.data.unwrap().map(|i| i.travel_marked), Some(true));

    // unmark 回 false；未标记即 enter 的前置条件由 core 拒绝
    let resp = set_travel_marked(id.clone(), false, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_identity(id, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data.unwrap().map(|i| i.travel_marked), Some(false));

    // 不存在的 id：报错而非静默成功
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = set_travel_marked(ghost, true, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not found"));
}

#[tokio::test]
async fn travel_enter_exit_round_trip_and_password_change_gate() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let id = seeded_identity(&app, "Work").await;

    let resp = set_travel_marked(id.clone(), true, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // enter：身份从主库消失、status 转活动、sidecar 落盘
    let resp = enter_travel_mode("travel-pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let counts = resp.data.expect("counts present");
    assert_eq!(counts.identities, 1);

    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(
        !resp.data.unwrap().iter().any(|i| i.id == id),
        "marked identity must be gone from the vault"
    );
    let resp = get_travel_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(status.active && status.sidecar_exists && !status.inconsistent);

    // 旅行模式开启期间改密被拒，且带机器可读码
    let resp = change_master_password(
        ChangeMasterPasswordRequest {
            old_password: "master-pw-123".to_string(),
            new_password: "new-master-pw".to_string(),
            db_path: Some(db_path.clone()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_TRAVEL_MODE_ACTIVE),
        "password change during travel mode must surface the typed code"
    );

    // exit 错口令：sidecar 保留、数据不回来
    let resp = exit_travel_mode("wrong-pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.unwrap().contains("passphrase is wrong"),
        "wrong travel passphrase error"
    );
    let resp = get_travel_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.expect("status present").sidecar_exists);

    // exit 对口令：恢复 + sidecar 删除
    let resp = exit_travel_mode("travel-pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let counts = resp.data.expect("counts present");
    assert_eq!(counts.identities, 1);

    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().iter().any(|i| i.id == id));
    let resp = get_travel_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.active && !status.sidecar_exists);
}

#[tokio::test]
async fn travel_enter_without_marks_is_rejected() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;

    let resp = enter_travel_mode("travel-pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("marked"));
}

#[tokio::test]
async fn travel_commands_degrade_loudly_before_init() {
    let app = mock_app();
    // 未 init：db_path 缺失 → 明确报错而非 panic
    let resp = get_travel_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);

    let resp = enter_travel_mode("pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);

    let resp = exit_travel_mode("pw".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
}

#[tokio::test]
async fn set_password_expiry_narrow_write_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // 全新 vault：默认不过期
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("settings present");
    assert_eq!(settings.password_expiry_days, None);

    // 窄写 90 天；返回的全量 settings 里其它字段不被 clobber
    let resp = set_password_expiry(Some(90), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("updated settings returned");
    assert_eq!(settings.password_expiry_days, Some(90));
    assert!(settings.encryption_enabled);
    assert_eq!(settings.session_timeout_seconds, 3600);

    // 与 features 位互不干扰（两条窄写路径共用一行 settings）
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

    // Some(0) 无意义，显式拒绝
    let resp = set_password_expiry(Some(0), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Password expiry must be at least 1 day")
    );
}

// ---------------------------------------------------------------------------
// Attachments（1Password 对齐）：加密附件经凭据 item key 封存，
// 命令层四命令全链路（list / attach / save / delete）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_commands_round_trip_encrypted() {
    let (app, identity_id) = app_with_identity().await;

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 命令测试的 db 在 leaked tempdir 里；附件 blob 跟随同一目录
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("recovery-codes.txt");
    std::fs::write(&source, b"attachment-round-trip-payload").unwrap();

    // 加密挂载：元数据回读（is_encrypted / 文件名 / 大小）
    let resp = attach_file_to_credential(
        cred.id.clone(),
        source.to_string_lossy().to_string(),
        true,
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let attachment = resp.data.expect("attachment metadata returned");
    assert_eq!(attachment.filename, "recovery-codes.txt");
    assert!(attachment.is_encrypted);
    assert_eq!(
        attachment.size,
        b"attachment-round-trip-payload".len() as u64
    );
    let attachment_id = attachment.id;

    // 列表
    let resp = list_attachments(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let listed = resp.data.expect("attachments listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, attachment_id);

    // 解密保存：读回与源字节一致（凭据 item key 封存的核心保障）
    let out = source_dir.path().join("restored.txt");
    let resp = save_attachment_to_file(
        attachment_id.clone(),
        out.to_string_lossy().to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"attachment-round-trip-payload".to_vec()
    );

    // 删除 → 列表清空
    let resp = delete_attachment(attachment_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = list_attachments(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.expect("list after delete").is_empty());
}

#[tokio::test]
async fn attachment_commands_validate_uuid_and_delete_credential_cascades() {
    let (app, identity_id) = app_with_identity().await;

    // 坏 UUID 在四命令上都得到统一错误
    let resp = list_attachments("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = delete_attachment("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // 凭据删除级联清附件（命令层只验证可见效果：列表清空）
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let cred = resp.data.expect("credential created");

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("cascade.bin");
    std::fs::write(&source, b"cascade-payload").unwrap();
    let resp = attach_file_to_credential(
        cred.id.clone(),
        source.to_string_lossy().to_string(),
        true,
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = delete_credential(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = list_attachments(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.expect("cascade cleared").is_empty());
}

// ---------------------------------------------------------------------------
// Biometric unlock：四命令命令层矩阵（provider 用 Mock 的
// available/force_fail 组合分支；store 用 InMemoryTokenStore 直接断言条目）
// ---------------------------------------------------------------------------

fn mock_provider(available: bool, force_fail: bool) -> Arc<persona_core::MockBiometricProvider> {
    Arc::new(persona_core::MockBiometricProvider {
        available,
        force_fail,
        platform: persona_core::BiometricPlatform::Unknown,
    })
}

/// set 恒失败、get/delete 委托内部 InMemory 的 keyring fake——测"写失败
/// 不留半态 / 改密联动 fail-closed 删条目"两条路径（条目需预先放进内部
/// store 模拟既有配置）。
struct FailingSetStore(Arc<InMemoryTokenStore>);
impl TokenStore for FailingSetStore {
    fn set(&self, _: &str, _: &str) -> Result<(), String> {
        Err("no secret service".to_string())
    }
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.0.get(key)
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.0.delete(key)
    }
}

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
    // 托管条目随改密联动更新
    assert_eq!(
        store.get(&db_path).unwrap().as_deref(),
        Some("new-password")
    );

    // 闭环：用新托管条目 biometric 解锁成功
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
    // 预置条目（绕过注入的 FailingSetStore.set）：改密成功后联动写失败
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
    // fail-closed：写失败 → 删条目（宁可重新启用也不留坏条目）
    assert_eq!(inner.get(&db_path).unwrap(), None);
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

#[tokio::test]
async fn report_frontend_error_never_fails_on_any_input_shape() {
    // 上报路径永不失败：空参数
    let resp = report_frontend_error(String::new(), None, None);
    assert!(resp.success);

    // 常规参数
    let resp = report_frontend_error(
        "boom".to_string(),
        Some("at Foo (bar.tsx:1)".to_string()),
        Some("in ErrorBoundary".to_string()),
    );
    assert!(resp.success);

    // 超长字段（> 8 KiB，含多字节字符）：按 char 边界截断不 panic
    let long_message = "错".repeat(10_000);
    let long_stack = "x".repeat(50_000);
    let resp = report_frontend_error(long_message, Some(long_stack), None);
    assert!(resp.success);
}

// ---------------------------------------------------------------------------
// E2EE sync 设备管理命令族：协议层在 core（SyncAdminApi 真 TCP 测试在
// server），这里锁宿主编排——keyring 身份三态、门禁、失败不留半态。
// 网络路径一律不可达服务器（http://127.0.0.1:1，同 set_sync_config 族口径）。
// ---------------------------------------------------------------------------

/// 直写 device_store 造一条合法本机身份（join 的网络路径测不了，身份
/// 落 keyring 后的后续命令全靠它驱动）。
async fn seed_device_identity(
    app: &tauri::App<tauri::test::MockRuntime>,
    db_path: &str,
) -> persona_core::sync::device::DeviceIdentity {
    let identity = persona_core::sync::device::DeviceIdentity::generate("seeded-laptop").unwrap();
    app.state::<AppState>()
        .device_store
        .set(db_path, &identity.to_stored_json())
        .unwrap();
    identity
}

#[tokio::test]
async fn sync_device_status_tracks_keyring_record_lifecycle() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入：干净三无
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(!status.corrupted);
    assert_eq!(status.device_id, None);

    // 手写合法记录 → joined + 身份可见
    let identity = persona_core::sync::device::DeviceIdentity::generate("laptop").unwrap();
    state
        .device_store
        .set(&db_path, &identity.to_stored_json())
        .unwrap();
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(status.joined);
    assert!(!status.corrupted);
    assert_eq!(status.device_id, Some(identity.device_id.to_string()));
    assert_eq!(status.device_name, Some("laptop".to_string()));

    // 记录损坏（手改半截）→ corrupted 引导重新 join，不猜不带病运行
    state.device_store.set(&db_path, "{\"device_id\":").unwrap();
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(status.corrupted);
}

#[tokio::test]
async fn sync_join_gates_and_never_leaves_partial_state_on_failure() {
    let app = mock_app();

    // 未初始化 service → 拒绝
    let resp = sync_join("laptop".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 服务器未配置 → 拒绝（业务失败，不 panic）
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 配置不可达服务器：登记失败 → error 且 keyring 不留半态
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 名字校验先于网络（省一轮注定失败的 HTTP）
    let resp = sync_join("   ".to_string(), state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("1..=128"));
    let overlong = "d".repeat(129);
    let resp = sync_join(overlong, state.clone()).await.unwrap();
    assert!(!resp.success);

    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success, "unreachable server must fail the join");
    assert!(resp.error.unwrap().contains("registration"));
    assert!(
        state.device_store.get(&db_path).unwrap().is_none(),
        "failed join must not leave a keyring record"
    );

    // 已加入（含损坏记录）→ 拒绝重复 join
    seed_device_identity(&app, &db_path).await;
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("already joined"));
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("already joined"));
}

#[tokio::test]
async fn sync_leave_clears_local_identity_even_when_server_unreachable() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入 → 拒绝
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(!resp.success);

    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 服务器不可达：本地清理优先（吊销失败仅 warn），keyring 必须清干净
    seed_device_identity(&app, &db_path).await;
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(state.device_store.get(&db_path).unwrap().is_none());

    // 二次 leave → 已未加入
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(!resp.success);
}

#[tokio::test]
async fn sync_list_authorize_revoke_require_membership() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入：三条管理命令一律拒绝（先于任何网络访问）
    let resp = sync_list_devices(state.clone()).await.unwrap();
    assert!(!resp.success);
    let resp = sync_authorize(Uuid::new_v4().to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    let resp = sync_revoke(Uuid::new_v4().to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);

    // 加入后：目标 id 格式校验先于网络
    // （身份种子只是为了过门禁；不可达服务器下格式错误先报）
    let db_path = {
        let guard = state.db_path.lock().await;
        guard.clone().unwrap()
    };
    seed_device_identity(&app, &db_path).await;
    let resp = sync_revoke("not-a-uuid".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));
    let resp = sync_authorize("not-a-uuid".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));
}

#[tokio::test]
async fn sync_now_gates_before_any_network_or_crypto() {
    let app = mock_app();

    // 未初始化 service → 拒绝
    let resp = sync_now(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入 → 拒绝（本地检查先于网络/密码学）
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // 损坏身份记录 → 拒绝（不猜不带病运行）
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("corrupted"));

    // 已加入但服务器未配置 → 拒绝
    seed_device_identity(&app, &db_path).await;
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 已配置但不可达：open 拉信封失败（网络错误冒泡，不留半态——
    // capture 只在整轮周期成功后挂载）
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);

    // 锁定后 → 拒绝（门禁在编排之前；lock 同时 detach 捕获缝）
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
