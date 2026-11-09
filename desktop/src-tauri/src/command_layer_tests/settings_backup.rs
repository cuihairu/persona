//! Command-layer integration tests — `settings_backup` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn backup_export_command_round_trip_and_records_evidence() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    // 先放一条凭据，断言备份文件确实携带库内容（恢复链路读回验证）
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

    // 文件在盘上、是 PERSENC1 密文（不是明文 SQLite）、尺寸与 sha256 对账
    let blob = std::fs::read(&dest).expect("backup file written");
    assert_eq!(blob.len() as u64, outcome.size_bytes);
    assert!(
        blob.starts_with(b"PERSENC1"),
        "file must be PERSENC1 ciphertext"
    );
    assert_eq!(outcome.sha256.len(), 64);
    assert!(outcome.sha256.chars().all(|c| c.is_ascii_hexdigit()));

    // 恢复链路互解：备份字节 → SQLite 明文（头校验过）→ 可当库打开
    let restored = dir.path().join("restored.db");
    persona_core::backup::restore_backup_bytes(&blob, "backup-pass-Δ", &restored)
        .expect("restore round trip");
    let plain = std::fs::read(&restored).unwrap();
    assert!(plain.starts_with(b"SQLite format 3\0"));

    // 导出凭证落入 workspace settings（非敏感元数据；口令不在任何结构里）
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let settings = resp.data.expect("settings");
    let evidence = settings.backup.expect("backup evidence recorded");
    assert_eq!(evidence.destination, "file");
    assert_eq!(evidence.size_bytes, blob.len() as u64);
    assert_eq!(evidence.exported_at, outcome.exported_at);

    // 覆盖导出：同路径二次导出原子替换成功，凭证时刻更新
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
    // 新口令可解（GCM 校验会失败于旧口令的 key）——换口令真生效
    let restored2 = dir.path().join("restored2.db");
    persona_core::backup::restore_backup_bytes(&blob2, "new-pass", &restored2)
        .expect("second export uses new passphrase");
}
#[tokio::test]
async fn backup_export_command_rejects_empty_passphrase_path_and_locked_state() {
    let app = mock_app();
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("v.enc");

    // 未初始化服务 → 拒
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

    // 空口令 → 拒（不产生文件）
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

    // 空路径 → 拒
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

    // 锁定态 → 拒
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

    // 快照基线：身份 A + 其凭据，导出成备份
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

    // 导出后继续变化：当前库变成 2 身份——恢复应回到快照的 1 身份
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

    // 恢复：换文件成功 + 原库留 .bak + staged 已消费
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

    // 换库后 service 已取下（主密码可能来自备份，必须重新走解锁）
    let resp = is_service_unlocked(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(false), "restore must take the session down");

    // 重新解锁（同一会话建的备份 = 同主密码；不能用 init_service_ok——
    // 它每次开新 tempdir，会指到空库），库回到快照形态
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

    // 口令错：staged 复验阶段就失败——库未动、会话不降锁
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

    // 会话仍解锁、库分毫未动、无 .bak / staged 残留
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

    // 服务从未初始化（无 db_path）→ 拒（文件在、输入合法才轮到库路径检查）
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

    // 空口令 / 空路径 / 文件不存在 → 拒（都在动库之前）
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

    // 不是 PERSENC1 的文件：staged 复验失败 → 库未动
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

    // 锁定态也能救（设备没丢，只是会话锁着/库坏了——自救口不要求解锁）：
    // 解锁态导出 → 锁定 → 恢复成功（service 随之取下）
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

    // 列表对账：服务器侧元数据与推送响应一致（快照加密在推送前完成，
    // 服务器只见密文——通过下载端点密文长度对账 size_bytes）
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

    // 空口令在碰服务器之前就被拒（下载都不发起）
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

    // 凭证回写 destination=server（与文件导出同一 BackupEvidence 槽）
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

    // 未初始化（无 db_path）→ 拒
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

    // 未配置 sync 服务器 → 拒（push 与 list 同门禁口径）
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

    // 空口令 → 拒（在碰服务器之前）
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

    // 错 token → 服务器 401，信封消息透传
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

    // push 要求解锁；锁定态 → 拒
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

    // 快照基线：1 身份 "Work"，推送到服务器
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

    // 快照后继续变化：当前库 2 身份——恢复应回到快照的 1 身份
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

    // 锁屏 → 从服务器恢复（自救口不要求解锁）
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

    // 换库后 service 已取下；重新解锁后库回到快照形态
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

    // 口令错：staged 复验阶段就失败——库未动、会话不降锁
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

    // 会话仍解锁、库分毫未动、无 .bak / staged 残留
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

    // 空 ID → 拒（在碰服务器之前）
    let resp = backup_delete_server_version(
        BackupServerDeleteRequest {
            backup_id: "  ".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    // 删除成功；再删同 ID 仍成功（服务器 404 → 客户端幂等）
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

    // 已删版本：列表清空、恢复/下载 404 透传
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
