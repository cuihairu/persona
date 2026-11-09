//! Command-layer integration tests — `settings_travel` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

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
