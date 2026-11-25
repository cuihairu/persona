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

    // create: the plaintext token appears only once, in the response; the info view strips the hash
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

    // list: the just-created token is in the active state
    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let rows = resp.data.expect("token rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, created.info.id);
    assert!(rows[0].revoked_at.is_none());

    // revoke: a valid UUID takes effect; revoking twice is idempotent and returns false
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

    // list: revoked_at is stamped
    let resp = connect_token_list(app.state::<AppState>()).await.unwrap();
    let rows = resp.data.expect("token rows");
    assert!(rows[0].revoked_at.is_some());

    // revoke: an invalid UUID goes down the argument-error branch
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

    // Not initialized: the unlocked check takes the None -> false path, which also lands on the SERVICE_LOCKED gate
    let resp = connect_server_start(app.state::<AppState>(), None)
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error_code.as_deref(),
        Some(crate::error::CODE_SERVICE_LOCKED)
    );

    // Initialized but locked: is_unlocked() = false -> the same gate
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

    // Idle status: not running, no port
    let resp = connect_server_status(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("status");
    assert!(!status.running);
    assert_eq!(status.port, None);

    // Start (None = OS-assigned port): binds 127.0.0.1 with a real non-zero port
    let resp = connect_server_start(app.state::<AppState>(), None)
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.expect("started status");
    assert!(status.running);
    let port = status.port.expect("OS-assigned port");
    assert_ne!(port, 0);

    // start while already running: an explicit error (the frontend renders from status, so it should never hit this)
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

    // status reflects the running state
    let resp = connect_server_status(app.state::<AppState>())
        .await
        .unwrap();
    let status = resp.data.expect("status");
    assert!(status.running);
    assert_eq!(status.port, Some(port));

    // stop -> stops and resets; a second stop is idempotent; status returns to the idle state
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
    // Locked real vault: core throws AuthenticationFailed("Service is locked")
    // -> map_persona_error hits SERVICE_LOCKED (the Some(code) arm)
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

    // Garbage vault: a repo-layer sqlite error -> no error code (the None arm); all three commands degrade
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
