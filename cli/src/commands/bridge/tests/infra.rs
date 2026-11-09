use super::*;

#[test]
fn path_resolvers_honor_override_and_environment() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_DB_PATH");
    std::env::remove_var("PERSONA_BRIDGE_STATE_DIR");

    // explicit override wins
    let override_path = std::path::PathBuf::from("/tmp/custom.db");
    assert_eq!(resolve_db_path(Some(override_path.clone())), override_path);
    let override_state = std::path::PathBuf::from("/tmp/bridge-state");
    assert_eq!(
        resolve_state_dir(Some(override_state.clone())),
        override_state
    );

    // environment fallback
    std::env::set_var("PERSONA_DB_PATH", "/tmp/env.db");
    assert_eq!(
        resolve_db_path(None),
        std::path::PathBuf::from("/tmp/env.db")
    );
    std::env::remove_var("PERSONA_DB_PATH");

    std::env::set_var("PERSONA_BRIDGE_STATE_DIR", "/tmp/env-state");
    assert_eq!(
        resolve_state_dir(None),
        std::path::PathBuf::from("/tmp/env-state")
    );
    std::env::remove_var("PERSONA_BRIDGE_STATE_DIR");

    // default: ~/.persona
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    assert_eq!(
        resolve_db_path(None),
        home.join(".persona").join("identities.db")
    );
    assert_eq!(
        resolve_state_dir(None),
        home.join(".persona").join("bridge")
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bridge_status_reports_lock_state_and_active_identity() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let (_dir, db_path, state_dir, identity_id) = seeded_bridge().await;

    // A fresh database without user rows is locked with no identity.
    let empty_dir = tempfile::tempdir().unwrap();
    let empty_db = empty_dir.path().join("empty.db");
    let resp = handle_request(
        &empty_db,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert!(resp.ok, "status must succeed: {:?}", resp.error);
    let payload = resp.payload.unwrap();
    assert_eq!(payload["locked"], true);
    assert!(payload["active_identity"].is_null());

    // Seeded vault without a master password: locked, identity reported.
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    let payload = resp.payload.unwrap();
    assert_eq!(payload["locked"], true);
    assert_eq!(payload["active_identity"], identity_id.to_string());

    // Correct master password reports the vault as unlocked.
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert_eq!(resp.payload.unwrap()["locked"], false);

    // Wrong password is locked again.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert_eq!(resp.payload.unwrap()["locked"], true);

    // A blank password counts as absent.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "   ");
    let resp = handle_request(
        &db_path,
        &state_dir,
        request("status", serde_json::json!({})),
    )
    .await
    .unwrap();
    assert_eq!(resp.payload.unwrap()["locked"], true);

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn open_db_and_unlocked_service_report_precise_errors() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let (dir, db_path, _state_dir, identity_id) = seeded_bridge().await;

    // A database in a nonexistent directory fails to open.
    let missing = dir.path().join("no-such-dir").join("missing.db");
    assert!(open_db(&missing).await.is_err(), "missing file must fail");

    // No password in the environment -> locked.
    let err = match open_unlocked_service(&db_path).await {
        Err(e) => e,
        Ok(_) => panic!("locked vault must not open"),
    };
    assert!(err.to_string().starts_with("locked:"), "got: {err}");

    // Wrong password -> authentication_failed.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
    let err = match open_unlocked_service(&db_path).await {
        Err(e) => e,
        Ok(_) => panic!("wrong password must not unlock"),
    };
    assert!(
        err.to_string().starts_with("authentication_failed"),
        "got: {err}"
    );

    // Correct password returns the active identity.
    std::env::set_var("PERSONA_MASTER_PASSWORD", PASSWORD);
    let (_service, active) = open_unlocked_service(&db_path).await.unwrap();
    assert_eq!(active, Some(identity_id));
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    // get_active_identity_id is None when no workspace row exists.
    let db = open_db(&db_path).await.unwrap();
    sqlx::query("DELETE FROM workspaces")
        .execute(db.pool())
        .await
        .unwrap();
    drop(db);
    let db = open_db(&db_path).await.unwrap();
    assert_eq!(get_active_identity_id(&db).await, None);
}
