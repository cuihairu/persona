//! Command-layer integration tests — `settings_backup` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn backup_export_command_round_trip_and_records_evidence() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    // Create one credential first, asserting the backup file really carries vault content (verified by reading back in the restore path)
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
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
    let identity_id = resp.data.expect("identity id").id.to_string();
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("vault-backup.enc");
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "backup-pass-Δ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let outcome = resp.data.expect("outcome");

    // File on disk is PERSENC1 ciphertext (not plaintext SQLite), size reconciled with sha256
    let blob = std::fs::read(&dest).expect("backup file written");
    assert_eq!(blob.len() as u64, outcome.size_bytes);
    assert!(
        blob.starts_with(b"PERSENC1"),
        "file must be PERSENC1 ciphertext"
    );
    assert_eq!(outcome.sha256.len(), 64);
    assert!(outcome.sha256.chars().all(|c| c.is_ascii_hexdigit()));

    // Restore path decodes: backup bytes -> SQLite plaintext (header checks pass) -> openable as a DB
    let restored = dir.path().join("restored.db");
    persona_core::backup::restore_backup_bytes(&blob, "backup-pass-Δ", &restored)
        .expect("restore round trip");
    let plain = std::fs::read(&restored).unwrap();
    assert!(plain.starts_with(b"SQLite format 3\0"));

    // Export evidence lands in workspace settings (non-sensitive metadata; no passphrase in any structure)
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("settings");
    let evidence = settings.backup.expect("backup evidence recorded");
    assert_eq!(evidence.destination, "file");
    assert_eq!(evidence.size_bytes, blob.len() as u64);
    assert_eq!(evidence.exported_at, outcome.exported_at);

    // Overwriting export: a second export to the same path atomically replaces it successfully, evidence refreshed each time
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "new-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "overwrite export failed: {:?}", resp.error);
    let blob2 = std::fs::read(&dest).unwrap();
    assert!(blob2.starts_with(b"PERSENC1"));
    // New passphrase decrypts (GCM check fails against the old passphrase's key) -- changing the passphrase really takes effect
    let restored2 = dir.path().join("restored2.db");
    persona_core::backup::restore_backup_bytes(&blob2, "new-pass", &restored2)
        .expect("second export uses new passphrase");
}
#[tokio::test]
async fn backup_export_command_rejects_empty_passphrase_path_and_locked_state() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("v.enc");

    // Service not initialized -> reject
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    init_service_ok(&app, "correct-horse").await;

    // Empty passphrase -> reject (no file produced)
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: String::new(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(!dest.exists(), "failed export must not leave a file");

    // Blank path -> reject
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: "   ".to_string(),
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    // Locked state -> reject
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    assert!(!dest.exists());
}
#[tokio::test]
async fn backup_restore_command_swaps_vault_and_keeps_bak() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "correct-horse").await;

    // Snapshot baseline: identity A + its credentials, exported as a backup
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let identity_id = resp.data.expect("identity id").id.to_string();
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("vault-backup.enc");
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "backup-pass-Δ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Vault keeps changing after the export: the current DB now has 2 identities -- restore should return to the snapshot's 1
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Personal".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Restore: DB file swap succeeds + the original DB kept as .bak + the staged file consumed
    let resp = backup_restore_from_file(
        BackupRestoreRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "backup-pass-Δ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let outcome = resp.data.expect("outcome");
    let bak = outcome.backup_copy.expect("pre-restore copy kept");
    assert!(std::path::Path::new(&bak).is_file(), ".bak must exist");
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    assert!(!staged.exists(), "staged file must be consumed by rename");

    // After the DB swap the service is taken down (the master password may come from the backup; unlocking must be redone)
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(false), "restore must take the session down");

    // Re-unlock (the backup was created in this session = same master password; init_service_ok cannot be used --
    // it opens a fresh tempdir each time, pointing at an empty DB), and the vault is back to the snapshot shape
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
    assert!(resp.success, "re-init on restored vault: {:?}", resp.error);
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let names: Vec<String> = resp
        .data
        .expect("identities")
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names, vec!["Work"], "restored vault matches the snapshot");
}
#[tokio::test]
async fn backup_restore_command_wrong_passphrase_leaves_vault_and_session_intact() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "correct-horse").await;
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("vault-backup.enc");
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "right-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Wrong passphrase: fails at the staged revalidation stage -- the DB is untouched and the session does not drop its lock
    let resp = backup_restore_from_file(
        BackupRestoreRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "wrong-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not touched")),
        "{:?}",
        resp.error
    );

    // Session still unlocked, DB untouched down to the byte, no .bak / staged leftovers
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(true),
        "failed restore must not drop the session"
    );
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data.expect("identities").len(), 1, "vault untouched");
    let mut bak = std::path::PathBuf::from(&db_path);
    bak.set_extension("bak");
    assert!(!bak.exists(), "no .bak on failed restore");
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    assert!(!staged.exists(), "no staged leftover on failed restore");
}
#[tokio::test]
async fn backup_restore_command_rejects_bad_inputs_and_rescues_from_locked_state() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("v.enc");

    // Service never initialized (no db_path) -> reject (only with a file present and valid inputs does it reach the DB path check)
    std::fs::write(&dest, b"placeholder").unwrap();
    let resp = backup_restore_from_file(
        BackupRestoreRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "x".to_string(),
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

    let db_path = init_service_ok(&app, "correct-horse").await;

    // Empty passphrase / blank path / missing file -> reject (all before the DB is touched)
    for bad in [
        BackupRestoreRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: String::new(),
        },
        BackupRestoreRequest {
            path: "   ".to_string(),
            passphrase: "x".to_string(),
        },
        BackupRestoreRequest {
            path: dir.path().join("missing.enc").to_string_lossy().to_string(),
            passphrase: "x".to_string(),
        },
    ] {
        let resp = backup_restore_from_file(bad, app.state::<AppState>())
            .await
            .unwrap();
        assert!(!resp.success);
    }

    // A file that is not PERSENC1: staged revalidation fails -> the DB is untouched
    let garbage = dir.path().join("garbage.enc");
    std::fs::write(&garbage, b"not a backup").unwrap();
    let resp = backup_restore_from_file(
        BackupRestoreRequest {
            path: garbage.to_string_lossy().to_string(),
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not touched")),
        "{:?}",
        resp.error
    );

    // Rescue works from the locked state too (the device was not lost -- only the session is locked / the DB is broken -- the self-rescue hatch does not require unlocking):
    // export while unlocked -> lock -> restore succeeds (the service is taken down with it)
    let resp = backup_export_to_file(
        BackupExportRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "rescue-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = backup_restore_from_file(
        BackupRestoreRequest {
            path: dest.to_string_lossy().to_string(),
            passphrase: "rescue-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "restore from locked state: {:?}", resp.error);
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "service taken down after swap");
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    assert!(!staged.exists());
}
#[tokio::test]
async fn backup_server_push_round_trip_and_records_evidence() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let base_url = spawn_mock_backup_server();
    configure_backup_server(&app, &base_url, "tok-persona-1").await;

    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "backup-pass-Δ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let outcome = resp.data.expect("outcome");
    assert_eq!(outcome.backup_id, "bk-1");
    assert_eq!(outcome.device_name, "stub-device");
    assert!(!outcome.deduplicated);
    assert_eq!(outcome.sha256.len(), 64);
    assert_eq!(outcome.created_at, "2026-10-08T00:00:00Z");

    // List reconciliation: the server-side metadata matches the push response (the snapshot is encrypted before pushing,
    // and the server only ever sees ciphertext -- size_bytes is reconciled via the ciphertext length on the download endpoint)
    let resp = backup_list_server_versions(
        BackupServerListRequest { limit: Some(10) },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let list = resp.data.expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].backup_id, "bk-1");
    assert_eq!(list[0].device_name, "stub-device");
    assert_eq!(list[0].sha256, outcome.sha256);
    assert_eq!(list[0].size_bytes, outcome.size_bytes);

    // An empty passphrase is rejected before the server is even contacted (no download is initiated)
    let resp = backup_restore_from_server(
        BackupServerRestoreRequest {
            backup_id: "bk-1".to_string(),
            passphrase: String::new(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "empty passphrase rejected before download");

    // Evidence written back with destination=server (the same BackupEvidence slot as file export)
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let evidence = resp.data.expect("settings").backup.expect("evidence");
    assert_eq!(evidence.destination, "server");
    assert_eq!(evidence.exported_at, outcome.exported_at);
    assert_eq!(evidence.size_bytes, outcome.size_bytes as u64);
}
#[tokio::test]
async fn backup_server_commands_gate_on_init_config_token_and_lock() {
    let app = mock_app();
    let base_url = spawn_mock_backup_server();

    // Not initialized (no db_path) -> reject
    let resp = backup_list_server_versions(
        BackupServerListRequest { limit: None },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );

    init_service_ok(&app, "correct-horse").await;

    // Sync server not configured -> reject (push and list share the same gate semantics)
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Sync server URL is not configured")
    );
    let resp = backup_list_server_versions(
        BackupServerListRequest { limit: None },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Sync server URL is not configured")
    );

    // Empty passphrase -> reject (before the server is contacted)
    configure_backup_server(&app, &base_url, "tok-persona-1").await;
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: String::new(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    // Wrong token -> server 401, envelope message passed through
    configure_backup_server(&app, &base_url, "wrong-token").await;
    let resp = backup_list_server_versions(
        BackupServerListRequest { limit: None },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("401")),
        "{:?}",
        resp.error
    );

    // push requires being unlocked; locked state -> reject
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "x".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
#[tokio::test]
async fn backup_restore_from_server_swaps_vault_and_rescues_from_locked_state() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "correct-horse").await;

    // Snapshot baseline: 1 identity "Work", pushed to the server
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let base_url = spawn_mock_backup_server();
    configure_backup_server(&app, &base_url, "tok-persona-1").await;
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "rescue-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Changes keep happening after the snapshot: the current DB has 2 identities -- restore should return to the snapshot's 1
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Personal".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Lock screen -> restore from the server (the self-rescue hatch does not require unlocking)
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = backup_restore_from_server(
        BackupServerRestoreRequest {
            backup_id: "bk-1".to_string(),
            passphrase: "rescue-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let outcome = resp.data.expect("outcome");
    let bak = outcome.backup_copy.expect("pre-restore copy kept");
    assert!(std::path::Path::new(&bak).is_file(), ".bak must exist");
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    assert!(!staged.exists(), "staged file must be consumed by rename");

    // After the DB swap the service is taken down; after re-unlocking the vault is back to the snapshot shape
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data, Some(false), "restore must take the session down");
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
    assert!(resp.success, "re-init on restored vault: {:?}", resp.error);
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let names: Vec<String> = resp
        .data
        .expect("identities")
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names, vec!["Work"], "restored vault matches the snapshot");
}
#[tokio::test]
async fn backup_restore_from_server_wrong_passphrase_leaves_vault_intact() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "correct-horse").await;
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Work".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let base_url = spawn_mock_backup_server();
    configure_backup_server(&app, &base_url, "tok-persona-1").await;
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "right-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Wrong passphrase: fails at the staged revalidation stage -- the DB is untouched and the session does not drop its lock
    let resp = backup_restore_from_server(
        BackupServerRestoreRequest {
            backup_id: "bk-1".to_string(),
            passphrase: "wrong-pass".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not touched")),
        "{:?}",
        resp.error
    );

    // Session still unlocked, DB untouched down to the byte, no .bak / staged leftovers
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert_eq!(
        resp.data,
        Some(true),
        "failed restore must not drop the session"
    );
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data.expect("identities").len(), 1, "vault untouched");
    let mut bak = std::path::PathBuf::from(&db_path);
    bak.set_extension("bak");
    assert!(!bak.exists(), "no .bak on failed restore");
    let mut staged = std::path::PathBuf::from(&db_path);
    staged.set_extension("restore.tmp");
    assert!(!staged.exists(), "no staged leftover on failed restore");
}
#[tokio::test]
async fn backup_server_delete_is_idempotent_and_deleted_versions_stop_serving() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    let base_url = spawn_mock_backup_server();
    configure_backup_server(&app, &base_url, "tok-persona-1").await;
    let resp = backup_push_to_server(
        BackupPushRequest {
            passphrase: "pass-1".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Blank ID -> reject (before the server is contacted)
    let resp = backup_delete_server_version(
        BackupServerDeleteRequest {
            backup_id: "  ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    // Delete succeeds; deleting the same ID again still succeeds (server 404 -> the client is idempotent)
    for _ in 0..2 {
        let resp = backup_delete_server_version(
            BackupServerDeleteRequest {
                backup_id: "bk-1".to_string(),
            },
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.expect("outcome").deleted);
    }

    // Deleted version: the list is empty and restore/download 404s are passed through
    let resp = backup_list_server_versions(
        BackupServerListRequest { limit: None },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.expect("list").is_empty());
    let resp = backup_restore_from_server(
        BackupServerRestoreRequest {
            backup_id: "bk-1".to_string(),
            passphrase: "pass-1".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("404")),
        "{:?}",
        resp.error
    );
}
