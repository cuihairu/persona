use super::*;

// ---- sync_push_now (protocol v7, M5 batch 3) ----

/// The user_gesture gate of sync_push_now: the write path pushes to the cloud; no gesture
/// → refuse (the gate sits after the session and before any keyring/network action).
#[tokio::test]
#[allow(clippy::await_holding_lock)] // same terms as the existing env-gate tests: ENV_LOCK is exclusive for the whole duration
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

/// The user_gesture gate of sync_resolve_conflict: the resolution overwrites the losing
/// replica — a write operation; no gesture → refuse.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // same terms as the existing env-gate tests: ENV_LOCK is exclusive for the whole duration
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

/// A non-UUID item_id → invalid_payload (parsing happens before session assembly, so the
/// classification can be anchored without the keyring/network).
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

/// Server not configured → sync_not_configured (config parsing comes before unlock/envelope,
/// so the classification can be anchored without unlock or the keyring — the same terms as sync_connect).
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

// ---- Wire-protocol anchoring: the serde behavior of requests/payloads (the run_sync_*
// happy paths need a real keyring and sync server, so this group anchors the wire contract
// with direct (de)serialization, covering the derive branches) ----

/// SyncPushNowRequest.user_gesture defaults to false: the extension omitting the field means
/// "no gesture", closing the loop with handle_request's gate (user_gesture_required).
#[test]
fn sync_push_now_request_defaults_gesture_to_false() {
    let req: SyncPushNowRequest = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(
        !req.user_gesture,
        "absent user_gesture must default to false"
    );

    let req: SyncPushNowRequest =
        serde_json::from_value(serde_json::json!({ "user_gesture": true })).unwrap();
    assert!(req.user_gesture);
}

/// SyncResolveConflictRequest three-field parsing: both UUIDs are required, and
/// user_gesture likewise defaults to false (snake_case wire shape).
#[test]
fn sync_resolve_conflict_request_parses_ids_and_defaults_gesture() {
    let req: SyncResolveConflictRequest =
        serde_json::from_value(serde_json::json!({ "item_id": "a", "adopt_op_id": "b" })).unwrap();
    assert_eq!(req.item_id, "a");
    assert_eq!(req.adopt_op_id, "b");
    assert!(
        !req.user_gesture,
        "absent user_gesture must default to false"
    );
}

/// SyncPushNowPayload's Serialize is aligned field-by-field with core SyncNowReport — the
/// extension reads the counts by the same key names, so any key-name/order drift goes red
/// here (the response payload's derive only runs on the session happy path; unit tests pin it).
#[test]
fn sync_push_now_payload_serializes_all_report_fields() {
    let payload = SyncPushNowPayload {
        pulled: 2,
        materialized: 1,
        conflicts: 1,
        pending_identity: 1,
        pushed: 4,
        backfilled: 8,
    };
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(json["pulled"], 2);
    assert_eq!(json["materialized"], 1);
    assert_eq!(json["conflicts"], 1);
    assert_eq!(json["pending_identity"], 1);
    assert_eq!(json["pushed"], 4);
    assert_eq!(json["backfilled"], 8);
}

/// A non-UUID adopt_op_id → invalid_payload: the same front validation as item_id (parsed
/// before session assembly), but an independent branch (unreachable on the happy path, no
/// keyring needed).
#[tokio::test]
async fn sync_resolve_conflict_rejects_malformed_adopt_op_id() {
    let (_dir, db_path, state_dir, _identity) = seeded_bridge().await;
    let (session_id, key_b64) = pair_extension(&state_dir, "ext-resolve3", "inst-resolve3").await;
    let req = signed_request(
        "sync_resolve_conflict",
        serde_json::json!({
            "item_id": uuid::Uuid::new_v4().to_string(),
            "adopt_op_id": "not-a-uuid",
            "user_gesture": true
        }),
        "req-3",
        &session_id,
        &key_b64,
        now_ms(),
        "nonce-resolve-badadopt",
    );
    let err = handle_request(&db_path, &state_dir, req)
        .await
        .expect_err("malformed adopt_op_id must fail");
    assert!(err.to_string().starts_with("invalid_payload"), "got: {err}");
}
