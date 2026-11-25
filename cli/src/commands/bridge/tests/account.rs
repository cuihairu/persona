use super::*;

/// The user_gesture gate of account_login: a pairing session is present but there is no gesture → refuse.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // same terms as the existing env-gate tests: ENV_LOCK is exclusive for the whole duration
async fn account_login_requires_user_gesture() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-acct", "inst-acct").await;
    let req = signed_request(
        "account_login",
        serde_json::json!({
            "account_id": "acct-1",
            "password": "pw",
            "device_name": "dev",
            "user_gesture": false
        }),
        "req-1",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-acct-gesture",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("account_login without gesture must fail");
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );
}

/// Server not configured → sync_not_configured (reuses the sync-side classification; the
/// gesture gate has passed and config parsing precedes any network/key action).
#[tokio::test]
async fn account_login_fails_closed_when_server_not_configured() {
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-acct2", "inst-acct2").await;
    let req = signed_request(
        "account_login",
        serde_json::json!({
            "account_id": "acct-1",
            "password": "pw",
            "device_name": "dev",
            "user_gesture": true
        }),
        "req-2",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-acct-noconfig",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("account_login without server URL must fail");
    assert!(
        err.to_string().starts_with("sync_not_configured"),
        "got: {err}"
    );
}

/// The server is present but unreachable → account_login_failed (the SRP orchestration error
/// is passed through as its classification; connecting to a dead port is enough to walk the
/// whole chain — no SRP mock needed).
#[tokio::test]
async fn account_login_reports_srp_failure_against_dead_server() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let settings =
        workspace_settings_json(Some(("http://127.0.0.1:1".to_string(), "".to_string())));
    insert_workspace_row(&db, dir.path().to_string_lossy().as_ref(), &settings).await;

    let store = InMemoryAccountTokenStore::new();
    let err = run_account_login(&db_path, "acct-1", "pw", "dev", &store)
        .await
        .expect_err("dead server must fail");
    assert!(
        err.to_string().starts_with("account_login_failed"),
        "got: {err}"
    );
    // A failure stores no token
    assert_eq!(store.get_token(&db_path.to_string_lossy()).unwrap(), None);
}

/// account_status reflects the token store's current state (has_session) and the server
/// configuration (server_configured); with an injected in-memory store the whole path is
/// testable without touching the real keyring.
#[tokio::test]
async fn account_status_reflects_store_and_server_config() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let settings =
        workspace_settings_json(Some(("http://127.0.0.1:8080".to_string(), "".to_string())));
    insert_workspace_row(&db, dir.path().to_string_lossy().as_ref(), &settings).await;

    let store = InMemoryAccountTokenStore::new();
    let status = run_account_status(&db_path, &store).await.unwrap();
    assert!(!status.has_session);
    assert!(status.server_configured);

    store
        .set_token(&db_path.to_string_lossy(), "tok-15m")
        .unwrap();
    let status = run_account_status(&db_path, &store).await.unwrap();
    assert!(status.has_session);

    // A blank token counts as signed out (same terms as the read-side filter)
    store.set_token(&db_path.to_string_lossy(), "   ").unwrap();
    let status = run_account_status(&db_path, &store).await.unwrap();
    assert!(!status.has_session);
}

/// No token → sign-out is an idempotent success (revoked_on_server=false), the same terms
/// as the desktop account_sign_out.
#[tokio::test]
async fn account_logout_is_idempotent_without_token() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();

    let store = InMemoryAccountTokenStore::new();
    let payload = run_account_logout(&db_path, "acct-1", &store)
        .await
        .unwrap();
    assert!(!payload.revoked_on_server);
}

/// A token present + the server unreachable → the local token is deleted anyway (sign-out
/// never stalls on server unreachability), with revoked_on_server honestly reported false.
#[tokio::test]
async fn account_logout_clears_local_token_even_when_server_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = open_db(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let settings =
        workspace_settings_json(Some(("http://127.0.0.1:1".to_string(), "".to_string())));
    insert_workspace_row(&db, dir.path().to_string_lossy().as_ref(), &settings).await;

    let db_key = db_path.to_string_lossy().to_string();
    let store = InMemoryAccountTokenStore::new();
    store.set_token(&db_key, "tok-15m").unwrap();

    let payload = run_account_logout(&db_path, "acct-1", &store)
        .await
        .unwrap();
    assert!(!payload.revoked_on_server);
    assert_eq!(store.get_token(&db_key).unwrap(), None);
}
