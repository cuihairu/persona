use super::*;

// ---- sync_push_now（协议 v7，M5 批3）----

/// sync_push_now 的 user_gesture 门禁：写路径推云，无手势 → 拒
/// （门禁在会话之后、任何 keyring/网络动作之前）。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 与既有 env 门禁测试同口径：ENV_LOCK 全程互斥
async fn sync_push_now_requires_user_gesture() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-push", "inst-push").await;
    let req = signed_request(
        "sync_push_now",
        serde_json::json!({ "user_gesture": false }),
        "req-1",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-push-gesture",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("sync_push_now without gesture must fail");
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );
}

/// sync_resolve_conflict 的 user_gesture 门禁：裁决覆盖落选副本，
/// 写操作，无手势 → 拒。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 与既有 env 门禁测试同口径：ENV_LOCK 全程互斥
async fn sync_resolve_conflict_requires_user_gesture() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-resolve", "inst-resolve").await;
    let req = signed_request(
        "sync_resolve_conflict",
        serde_json::json!({
            "item_id": uuid::Uuid::new_v4().to_string(),
            "adopt_op_id": uuid::Uuid::new_v4().to_string(),
            "user_gesture": false
        }),
        "req-1",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-resolve-gesture",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("sync_resolve_conflict without gesture must fail");
    assert!(
        err.to_string().starts_with("user_gesture_required"),
        "got: {err}"
    );
}

/// 非 UUID 的 item_id → invalid_payload（解析在会话装配之前，免
/// keyring/网络即可锚定分类）。
#[tokio::test]
async fn sync_resolve_conflict_rejects_malformed_ids() {
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-resolve2", "inst-resolve2").await;
    let req = signed_request(
        "sync_resolve_conflict",
        serde_json::json!({
            "item_id": "not-a-uuid",
            "adopt_op_id": uuid::Uuid::new_v4().to_string(),
            "user_gesture": true
        }),
        "req-2",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-resolve-badid",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("malformed item_id must fail");
    assert!(err.to_string().starts_with("invalid_payload"), "got: {err}");
}

/// 服务器未配置 → sync_not_configured（配置解析在解锁/信封之前，
/// 免解锁免 keyring 即可锚定分类——与 sync_connect 同口径）。
#[tokio::test]
async fn sync_push_now_fails_closed_when_server_not_configured() {
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-push2", "inst-push2").await;
    let req = signed_request(
        "sync_push_now",
        serde_json::json!({ "user_gesture": true }),
        "req-2",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-push-noconfig",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("sync_push_now without server URL must fail");
    assert!(
        err.to_string().starts_with("sync_not_configured"),
        "got: {err}"
    );
}
