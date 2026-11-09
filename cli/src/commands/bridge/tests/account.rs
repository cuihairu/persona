use super::*;

/// account_login 的 user_gesture 门禁：配对会话在场但无手势 → 拒。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 与既有 env 门禁测试同口径：ENV_LOCK 全程互斥
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

/// 服务器未配置 → sync_not_configured（复用 sync 侧分类；手势门禁
/// 已过，配置解析先于任何网络/密钥动作）。
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

/// 服务器在场但不可达 → account_login_failed（SRP 编排错误如实
/// 透传分类；连不上一台死端口即可走通全链，不需要 SRP mock）。
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
    // 失败不落地任何令牌
    assert_eq!(store.get_token(&db_path.to_string_lossy()).unwrap(), None);
}

/// account_status 反映令牌仓现状（has_session）与服务器配置
/// （server_configured），注入内存仓全路径可测、不碰真 keyring。
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

    // 空白令牌视同未登录（与读侧 filter 同口径）
    store.set_token(&db_path.to_string_lossy(), "   ").unwrap();
    let status = run_account_status(&db_path, &store).await.unwrap();
    assert!(!status.has_session);
}

/// 无令牌 → 登出幂等成功（revoked_on_server=false），与桌面
/// account_sign_out 同口径。
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

/// 有令牌 + 服务器不可达 → 本地令牌照删（登出不因服务器失联卡死），
/// revoked_on_server 如实报 false。
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
