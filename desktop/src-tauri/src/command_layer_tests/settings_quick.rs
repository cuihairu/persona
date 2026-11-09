//! Command-layer integration tests — `settings_quick` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// 未初始化的库：status 走"缺 db_path"错误，不 panic
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
/// 写配置要过解锁门禁（同 set_locale / set_feature_flags）；读状态免解锁
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

    // 锁上：读仍然可以（设置页要显示"热键到底生效没有"），写拒绝
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

    // 锁定态的写入不得落库
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.expect("settings").quick_access_hotkey.is_none());
}
/// 默认档（2026-09-28 起默认关）：开关关、绑定落到平台默认值；显式
/// 开启后测试环境（mock context）没有 quick-access 浮窗，抢注必然
/// 失败 → registered 为空且带原因（这就是设置页要显示的面）
#[tokio::test]
async fn quick_access_status_reports_defaults_and_missing_registration() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // 默认关：新装/缺键不抢注任何全局热键，registered 空、无错误
    let resp = quick_access_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status present");
    assert!(!status.enabled, "全局热键默认关闭（与云备份同口径）");
    assert!(status.registered_accelerator.is_none());
    assert!(status.error.is_none(), "默认关不是失败，不带原因");

    // 显式开启（设置页开关）后才有"抢注失败"面
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

    // 运行态确实被记下了（解锁时的 apply_quick_access 走的是同一条路径）
    let state = app.state::<AppState>();
    let runtime = state.quick_access.lock().unwrap();
    assert!(runtime.registered.is_none());
    assert!(runtime.last_error.is_some());
}
/// 改绑落库并回读（DB 是真值源）；非法加速键**不落库**
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

    // 落库回读
    let resp = get_workspace_settings(app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.data.expect("settings").quick_access_hotkey.as_deref(),
        Some("Control+Alt+K")
    );

    // 非法串：命令失败且 DB 不动
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
/// 关开关 + 空串恢复默认：hotkey 存回 None（不把默认值钉进 DB）
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
/// 关开关后运行态不得残留"已注册"（否则 UI 会显示一个其实已失效的绑定）
#[tokio::test]
async fn quick_access_set_disable_clears_registered_state() {
    let app = mock_app();
    init_service_ok(&app, "master-pw-123").await;

    // 先手工置一个"曾抢注成功"的运行态，模拟改绑前的进程内状态
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
/// 未初始化的库：status 走"缺 db_path"错误，不 panic（与 quick_access 同因）
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
/// 写配置要过解锁门禁（读免解锁）；锁定态的写入不得落库
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
/// 默认关；显式开启后 mock context 没有 generator-panel 浮窗 → 抢注
/// 必然失败且带原因。**改检索绑定不得动生成器槽位**（独立运行态）
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
/// 改绑落库并回读；非法加速键不落库；与检索绑定互不影响
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

    // 落库回读
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

    // 检索绑定写入后，生成器的 DB 值与运行态槽位都不被带跑
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
    // 锁的作用域止步于块尾：后面还有 await（clippy::await_holding_lock）
    {
        let runtime = state.quick_access.lock().unwrap();
        assert!(runtime.generator_last_error.is_some());
        assert!(
            runtime.last_error.is_some(),
            "两条绑定各自带自己的抢注失败原因"
        );
    }

    // 非法串：命令失败且 DB 不动
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
/// 关开关 + 空串恢复默认：hotkey 存回 None（不把默认值钉进 DB）
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
/// 跨窗跳转的入参校验：非法 UUID 直接拒（主窗口拿到非法 id 只会静默不选中）
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

    // 主窗口不存在（mock context 无窗口）→ 明确报错，不静默
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
