//! Command-layer integration tests — `settings` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

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
async fn set_locale_rejects_bad_values_and_gates_on_lock() {
    let app = mock_app();

    // 非法 locale 优先拒绝（无需初始化——参数校验先于解锁门禁）
    let resp = set_locale("fr".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Unsupported locale: fr"));

    // 未初始化：Service not initialized
    let resp = set_locale("en".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 已初始化但锁定：Service is locked
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

        // get 反映持久化结果（新连接读库，非进程内缓存）
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

    // 测试环境无托盘（tray_by_id 找不到）：应报成功而非报错——降级运行不该
    // 把语言切换炸红
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
/// `set_account_binding`：写 vault JSON（get_workspace_settings 直出可读），
/// None 解绑；锁户拒绝。
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

    // 解绑
    let resp = set_account_binding(None, state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().account, None);

    // 锁户拒绝
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = set_account_binding(Some(binding), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
