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

    // DTO exposes travel_marked (data source for the edit-form toggle)
    let resp = get_identity(id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.data.unwrap().map(|i| i.travel_marked), Some(true));

    // unmark flips back to false; "not marked" is the precondition core rejects for enter
    let resp = set_travel_marked(id.clone(), false, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = get_identity(id, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.data.unwrap().map(|i| i.travel_marked), Some(false));

    // nonexistent id: error rather than silent success
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

    // enter: identity disappears from the main vault, status turns active, sidecar written to disk
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

    // password change while travel mode is on is rejected, with a machine-readable code
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

    // exit with wrong passphrase: sidecar kept, data not restored
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

    // exit with the right passphrase: restore + sidecar deleted
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
    // not initialized: db_path missing -> explicit error instead of panic
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
