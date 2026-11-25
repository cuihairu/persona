//! Command-layer integration tests — `settings_sync` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn set_sync_config_stores_token_in_keyring_and_remembers_on_blank() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // Fresh vault: sync section is None, no token in keyring
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.sync.is_none(), "fresh vault has no sync config");
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "fresh vault has no stored token");

    // Narrow write of the sync section: token goes into keyring, vault JSON always stores an empty string
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

    // get reflects the persisted result: sync section visible, token never read back over IPC
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let sync = resp.data.expect("settings present").sync.expect("sync set");
    assert_eq!(sync.server_token, "");
    let resp = sync_token_present(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(true));

    // Empty token string = keep the existing keyring token
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

    // Disabling sync: enabled=false is persisted, and the keyring token is cleared along with it
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
/// Submitting a non-empty token when keyring is unavailable (headless / no
/// secret service): the save is refused and the vault stores no plaintext config.
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

    // Save refused: no sync config is written to the vault (neither token nor url lands)
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    let settings = resp.data.expect("settings present");
    assert!(settings.sync.is_none(), "refused save must not persist");

    // The disable path does not write keyring: disabling (best-effort delete failures only warn) still saves
    let resp = set_sync_config(false, String::new(), String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// When the keyring has no token, attach fails closed (no emitter attached);
/// once the token is in place the same config mounts again.
#[tokio::test]
async fn attach_sync_emitter_fails_closed_without_keyring_token() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // Config with enabled + url and the token also in keyring: mounts normally
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

    // Simulate a lost keyring entry (vault restored on another machine / manual delete): attach detaches
    app.state::<AppState>()
        .token_store
        .delete(&db_path)
        .unwrap();
    attach_sync_emitter(&app.state::<AppState>()).await;
    assert!(
        app.state::<AppState>().sync_emitter.lock().await.is_none(),
        "missing keyring token must fail closed"
    );

    // Token restored: the same config remounts
    app.state::<AppState>()
        .token_store
        .set(&db_path, "tok-restored")
        .unwrap();
    attach_sync_emitter(&app.state::<AppState>()).await;
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_some());
}
/// Legacy vault (plaintext token stored in the DB before the keyring batch):
/// attach migrates it one-time into keyring, clears the DB to an empty string,
/// and reports a normal mount.
#[tokio::test]
async fn legacy_sync_token_migrates_to_keyring_on_attach() {
    use persona_core::models::SyncConfig;
    use persona_core::storage::{Database, Repository, WorkspaceRepository};

    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;

    // Write the pre-keyring-batch legacy plaintext config straight into the DB
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
        cloud_drive_dir: None,
        sync_transport: persona_core::SyncTransport::default(),
    });
    ws.touch();
    repo.update(&ws).await.unwrap();

    attach_sync_emitter(&app.state::<AppState>()).await;

    // Token moved into keyring, DB cleared to empty string, mount reported
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

    // disabled + blank url is valid (turns off reporting but clears the url)
    let resp = set_sync_config(false, String::new(), String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
#[tokio::test]
async fn attach_sync_emitter_follows_saved_config() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // Sync not configured: after init the slot is None and the service works normally
    assert!(app.state::<AppState>().sync_emitter.lock().await.is_none());

    // Saving an enabled config remounts immediately: the slot holds the emitter
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

    // Disabling the config: the slot is detached (the old emitter has stopped; no double task)
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
