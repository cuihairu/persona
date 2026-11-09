//! Command-layer integration tests — `connect` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn connect_token_commands_degrade_when_service_not_initialized() {
    let app = mock_app();

    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = connect_token_create(app.state::<AppState>(), "x".to_string(), read_scope())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = connect_token_revoke(app.state::<AppState>(), Uuid::new_v4().to_string())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
}
#[tokio::test]
async fn connect_token_commands_round_trip_create_list_revoke() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // create：明文 token 只在响应里出现一次，info 视图剥哈希
    let resp = connect_token_create(
        app.state::<AppState>(),
        "desktop-pairing".to_string(),
        read_scope(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("created view");
    assert!(created.token.starts_with("pconn_"), "{}", created.token);
    assert_eq!(created.info.label, "desktop-pairing");
    assert_eq!(created.info.fingerprint.len(), 16);
    assert!(created.info.revoked_at.is_none());

    // list：刚创建的 token 处于 active 态
    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let rows = resp.data.expect("token rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, created.info.id);
    assert!(rows[0].revoked_at.is_none());

    // revoke：合法 UUID 生效；重复吊销幂等返回 false
    let resp = connect_token_revoke(app.state::<AppState>(), created.info.id.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));
    let resp = connect_token_revoke(app.state::<AppState>(), created.info.id.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(false));

    // list：revoked_at 已盖章
    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    let rows = resp.data.expect("token rows");
    assert!(rows[0].revoked_at.is_some());

    // revoke：非法 UUID 走参数错误分支
    let resp = connect_token_revoke(app.state::<AppState>(), "not-a-uuid".to_string())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("Invalid token id"),
        "{:?}",
        resp.error
    );
}
#[tokio::test]
async fn connect_server_start_requires_unlocked_vault() {
    let app = mock_app();

    // 未初始化：unlocked 检查走 None → false，同样落 SERVICE_LOCKED 门禁
    let resp = connect_server_start(app.state::<AppState>(), None)
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_SERVICE_LOCKED)
    );

    // 已初始化但锁定：is_unlocked() = false → 同一门禁
    init_service_ok(&app, "correct-horse").await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = connect_server_start(app.state::<AppState>(), None)
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_SERVICE_LOCKED)
    );
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("must be unlocked"),
        "{:?}",
        resp.error
    );
}
#[tokio::test]
async fn connect_server_start_status_stop_lifecycle_round_trip() {
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // 空态 status：未运行、无端口
    let resp = connect_server_status(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status");
    assert!(!status.running);
    assert_eq!(status.port, None);

    // 启动（None = OS 分配端口）：127.0.0.1 bind，真实端口非 0
    let resp = connect_server_start(app.state::<AppState>(), None)
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("started status");
    assert!(status.running);
    let port = status.port.expect("OS-assigned port");
    assert_ne!(port, 0);

    // 已运行再 start：明确报错（前端按 status 渲染，不该走到这）
    let resp = connect_server_start(app.state::<AppState>(), Some(port))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("already running"),
        "{:?}",
        resp.error
    );

    // status 反映运行态
    let resp = connect_server_status(app.state::<AppState>())
        .await
        .unwrap();
    let status = resp.data.expect("status");
    assert!(status.running);
    assert_eq!(status.port, Some(port));

    // stop → 停止并复位；再 stop 幂等；status 回到空态
    let resp = connect_server_stop(app.state::<AppState>()).await.unwrap();
    assert!(resp.success);
    let status = resp.data.expect("stopped status");
    assert!(!status.running);
    assert_eq!(status.port, None);

    let resp = connect_server_stop(app.state::<AppState>()).await.unwrap();
    assert!(resp.success);
    assert!(!resp.data.expect("status").running);

    let resp = connect_server_status(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.expect("status").running);
}
#[tokio::test]
async fn connect_token_commands_surface_locked_and_db_errors() {
    // 锁定的真实库：core 抛 AuthenticationFailed("Service is locked")
    // → map_persona_error 命中 SERVICE_LOCKED（Some(code) 臂）
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;
    lock_service(app.state::<AppState>()).await.unwrap();

    let resp = connect_token_create(
        app.state::<AppState>(),
        "locked-out".to_string(),
        persona_core::connect::ConnectTokenScope {
            identities: vec![],
            item_types: vec![],
            verbs: vec![persona_core::connect::ConnectVerb::Read],
        },
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_SERVICE_LOCKED)
    );

    // 垃圾库：repo 层 sqlite 错误 → 无错误码（None 臂），三命令都降级
    let app = app_with_garbage_db_service().await;
    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error_code.is_none(), "sqlite 错误不带业务码");
    assert!(
        resp.error
            .as_deref()
            .unwrap_or("")
            .contains("not a database"),
        "{:?}",
        resp.error
    );

    let resp = connect_token_revoke(app.state::<AppState>(), Uuid::new_v4().to_string())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error_code.is_none());
}
