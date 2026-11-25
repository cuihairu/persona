//! Command-layer integration tests — `sync` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn sync_device_status_tracks_keyring_record_lifecycle() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined: clean triple-none
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(!status.corrupted);
    assert_eq!(status.device_id, None);

    // A hand-written legal record -> joined + identity visible
    let identity = persona_core::sync::device::DeviceIdentity::generate("laptop").unwrap();
    state
        .device_store
        .set(&db_path, &identity.to_stored_json())
        .unwrap();
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(status.joined);
    assert!(!status.corrupted);
    assert_eq!(status.device_id, Some(identity.device_id.to_string()));
    assert_eq!(status.device_name, Some("laptop".to_string()));

    // A corrupted record (half rewritten by hand) -> corrupted leads to re-joining, never guessing or running in a broken state
    state.device_store.set(&db_path, "{\"device_id\":").unwrap();
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(status.corrupted);
}
#[tokio::test]
async fn sync_join_gates_and_never_leaves_partial_state_on_failure() {
    let app = mock_app();

    // Uninitialized service -> rejected
    let resp = sync_join("laptop".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Server not configured -> rejected (a business failure, not a panic)
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // Configured an unreachable server: registration fails -> error and keyring keeps no half state
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Name validation precedes the network (saves one round of an HTTP call doomed to fail)
    let resp = sync_join("   ".to_string(), state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("1..=128"));
    let overlong = "d".repeat(129);
    let resp = sync_join(overlong, state.clone()).await.unwrap();
    assert!(!resp.success);

    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success, "unreachable server must fail the join");
    assert!(resp.error.unwrap().contains("registration"));
    assert!(
        state.device_store.get(&db_path).unwrap().is_none(),
        "failed join must not leave a keyring record"
    );

    // Already joined (including a corrupted record) -> a repeated join is rejected
    seed_device_identity(&app, &db_path).await;
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("already joined"));
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("already joined"));
}
#[tokio::test]
async fn sync_leave_clears_local_identity_even_when_server_unreachable() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined -> rejected
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(!resp.success);

    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // Server unreachable: local cleanup comes first (a failed revocation is only a warn), and keyring must be wiped clean
    seed_device_identity(&app, &db_path).await;
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(state.device_store.get(&db_path).unwrap().is_none());

    // A second leave -> already not joined
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(!resp.success);
}
#[tokio::test]
async fn sync_list_authorize_revoke_require_membership() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined: all three admin commands are rejected (before any network access)
    let resp = sync_list_devices(state.clone()).await.unwrap();
    assert!(!resp.success);
    let resp = sync_authorize(Uuid::new_v4().to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    let resp = sync_revoke(Uuid::new_v4().to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);

    // After joining: target id format validation precedes the network
    // (the identity seed is only there to get past the gate; under an unreachable server a format error is reported first)
    let db_path = {
        let guard = state.db_path.lock().await;
        guard.clone().unwrap()
    };
    seed_device_identity(&app, &db_path).await;
    let resp = sync_revoke("not-a-uuid".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));
    let resp = sync_authorize("not-a-uuid".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));
}
#[tokio::test]
async fn sync_now_gates_before_any_network_or_crypto() {
    let app = mock_app();

    // Uninitialized service -> rejected
    let resp = sync_now(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined -> rejected (local checks precede networking/cryptography)
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // A corrupted identity record -> rejected (no guessing, no running in a broken state)
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("corrupted"));

    // Joined but the server is not configured -> rejected
    seed_device_identity(&app, &db_path).await;
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // Configured but unreachable: open fails to fetch the envelope (the network error bubbles up, no half state is left —
    // capture only mounts after the whole cycle succeeds)
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);

    // After locking -> rejected (the gate sits ahead of orchestration; lock also detaches the capture seam)
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// sync_status (section 2.5.5 status display) shares the same gate as sync_now
/// — both go through open_sync_session: the read-only snapshot also never
/// crosses any of "uninitialized / not joined / not configured / locked", and
/// a failure is reported honestly (never a fake 0 watermark). The aggregation
/// semantics (head/watermark/behind/pending push/last sync) are covered by the
/// core engine tests; the host layer only verifies the gate.
#[tokio::test]
async fn sync_status_shares_sync_now_gates() {
    let app = mock_app();

    // Uninitialized service -> rejected
    let resp = sync_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined -> rejected
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // Joined but the server is not configured -> rejected (no network touched)
    seed_device_identity(&app, &db_path).await;
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // Locked -> rejected
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// The conflict command family (phase 3c) shares the same gate as sync_now —
/// both go through open_sync_session: uninitialized / not joined / not
/// configured / locked are each rejected before any network or cryptographic
/// access; resolve's argument format validation precedes session assembly
/// (Malformed never touches the network). The full semantics of adjudication
/// (adopt/evict/idempotency surface) are covered by the core resolve + runtime
/// tests; the host layer only verifies the gate and the argument plane.
#[tokio::test]
async fn sync_conflict_commands_share_sync_now_gates() {
    let app = mock_app();

    // Uninitialized service -> rejected
    let resp = sync_conflicts_list(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));
    let resp = sync_conflict_resolve(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined -> rejected (local checks precede networking/cryptography)
    let resp = sync_conflicts_list(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));
    let resp = sync_conflict_resolve(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // Argument format validation precedes session assembly (Malformed never touches the network — the server is not configured at this point,
    // so with the order wrong it would report not configured instead of Malformed)
    seed_device_identity(&app, &db_path).await;
    let resp = sync_conflict_resolve(
        "not-a-uuid".to_string(),
        Uuid::new_v4().to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));
    let resp = sync_conflict_resolve(
        Uuid::new_v4().to_string(),
        "not-a-uuid".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Malformed"));

    // Joined and configured but the server is unreachable: open fails to fetch the envelope -> rejected (no half state)
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_conflicts_list(state.clone()).await.unwrap();
    assert!(!resp.success);
    let resp = sync_conflict_resolve(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    // Locked -> rejected
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_conflicts_list(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// The rotation command (phase 3d) shares the same gate as sync_now — both go
/// through open_sync_session: uninitialized / not joined / corrupted / not
/// configured / unreachable / locked are each rejected before any network or
/// cryptographic access. The full semantics of rotation (envelope swap /
/// repackaging / boundaries) are covered by the core runtime + real-TCP server
/// tests; the host layer only verifies the gate and the orchestration.
#[tokio::test]
async fn sync_rotate_gates_before_any_network_or_crypto() {
    let app = mock_app();

    // Uninitialized service -> rejected
    let resp = sync_rotate(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // Not joined -> rejected (local checks precede networking/cryptography)
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // A corrupted identity record -> rejected
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("corrupted"));

    // Joined but the server is not configured -> rejected
    seed_device_identity(&app, &db_path).await;
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // Configured but unreachable: open fails to fetch the envelope -> rejected (no half state)
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);

    // Locked -> rejected
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
#[tokio::test]
async fn sync_group_status_gates_on_db_path_and_reports_keyring_entry() {
    let app = mock_app();
    let resp = sync_group_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "no db path yet");

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let resp = sync_group_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success);
    assert!(!resp.data.unwrap(), "fresh vault not in a sync group");

    app.state::<AppState>()
        .sync_group_store
        .set(&db_path, &"ab".repeat(32))
        .unwrap();
    let resp = sync_group_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap(), "keyring entry = joined");
}
#[tokio::test]
async fn sync_group_pairing_create_requires_server_config() {
    let app = mock_app();
    let resp = sync_group_pairing_create(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "not unlocked / no db path");

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let resp = sync_group_pairing_create(app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "server url not configured");

    let base = spawn_mock_pairing_relay();
    set_sync_server_url(&app, &db_path, &base).await;
    let resp = sync_group_pairing_create(app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "create failed: {:?}", resp.error);
    let outcome = resp.data.unwrap();
    assert_eq!(outcome.code.len(), 9, "Crockford base32 9-char code");
    assert!(outcome.invite_link.starts_with("persona-pair-1."));
    assert_eq!(outcome.session_id, "sess-1");
    assert!(
        app.state::<AppState>()
            .pairing_sessions
            .lock()
            .unwrap()
            .contains_key("sess-1"),
        "host session held in memory"
    );
}
#[tokio::test]
async fn sync_group_join_begin_rejects_already_joined_vault() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    app.state::<AppState>()
        .sync_group_store
        .set(&db_path, &"cd".repeat(32))
        .unwrap();
    let resp = sync_group_join_begin("persona-pair-1.x".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("already joined"));
}
#[tokio::test]
async fn sync_group_pairing_cancel_is_idempotent_without_session() {
    let app = mock_app();
    let resp = sync_group_pairing_cancel("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success && resp.data.unwrap(), "cancel is idempotent");
}
/// Full two-side chain: host create -> poll and guest join_begin -> confirm run
/// concurrently to completion, asserting that both sides' short fingerprints
/// match, both sides' keyring group keys match, and the session is cleaned
/// up.
#[tokio::test]
async fn sync_group_full_pairing_lands_same_group_key_on_both_sides() {
    let host_app = mock_app();
    let guest_app = mock_app();
    let host_db = init_service_ok(&host_app, "master-pw-123").await;
    let guest_db = init_service_ok(&guest_app, "master-pw-456").await;

    let base = spawn_mock_pairing_relay();
    set_sync_server_url(&host_app, &host_db, &base).await;

    let created = sync_group_pairing_create(host_app.state::<AppState>())
        .await
        .unwrap();
    assert!(created.success, "create failed: {:?}", created.error);
    let invite = created.data.unwrap();

    let link = invite.invite_link.clone();
    let session_id = invite.session_id.clone();
    let guest_flow = async {
        let begun = sync_group_join_begin(link, guest_app.state::<AppState>())
            .await
            .unwrap();
        assert!(begun.success, "join_begin failed: {:?}", begun.error);
        let begun = begun.data.unwrap();
        let confirmed = sync_group_join_confirm(session_id, guest_app.state::<AppState>())
            .await
            .unwrap();
        (begun, confirmed)
    };
    let (polled, (begun, confirmed)) = tokio::join!(
        sync_group_pairing_poll(invite.session_id.clone(), host_app.state::<AppState>()),
        guest_flow,
    );

    let polled = polled.unwrap();
    assert!(polled.success, "poll failed: {:?}", polled.error);
    let poll_outcome = polled.data.unwrap();
    assert!(poll_outcome.completed);
    let host_fp = poll_outcome.fingerprint.expect("host fingerprint");
    assert_eq!(
        host_fp, begun.fingerprint,
        "both sides see the same fingerprint"
    );

    assert!(confirmed.success, "confirm failed: {:?}", confirmed.error);

    let host_hex = host_app
        .state::<AppState>()
        .sync_group_store
        .get(&host_db)
        .unwrap()
        .expect("host group key stored");
    let guest_hex = guest_app
        .state::<AppState>()
        .sync_group_store
        .get(&guest_db)
        .unwrap()
        .expect("guest group key stored");
    assert_eq!(host_hex, guest_hex, "both sides hold the same group key");
    assert_eq!(host_hex.len(), 64, "hex-encoded 32-byte key");

    assert!(
        !host_app
            .state::<AppState>()
            .pairing_sessions
            .lock()
            .unwrap()
            .contains_key("sess-1"),
        "host session cleaned after completion"
    );
    assert!(
        !guest_app
            .state::<AppState>()
            .pairing_sessions
            .lock()
            .unwrap()
            .contains_key("sess-1"),
        "guest session cleaned after completion"
    );
}
