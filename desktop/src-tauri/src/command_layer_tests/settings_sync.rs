//! Command-layer integration tests — `settings_sync` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

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
