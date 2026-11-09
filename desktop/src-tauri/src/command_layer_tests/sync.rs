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

    // 未加入：干净三无
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(!status.corrupted);
    assert_eq!(status.device_id, None);

    // 手写合法记录 → joined + 身份可见
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

    // 记录损坏（手改半截）→ corrupted 引导重新 join，不猜不带病运行
    state.device_store.set(&db_path, "{\"device_id\":").unwrap();
    let resp = sync_device_status(state.clone()).await.unwrap();
    let status = resp.data.expect("status present");
    assert!(!status.joined);
    assert!(status.corrupted);
}
#[tokio::test]
async fn sync_join_gates_and_never_leaves_partial_state_on_failure() {
    let app = mock_app();

    // 未初始化 service → 拒绝
    let resp = sync_join("laptop".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 服务器未配置 → 拒绝（业务失败，不 panic）
    let resp = sync_join("laptop".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 配置不可达服务器：登记失败 → error 且 keyring 不留半态
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 名字校验先于网络（省一轮注定失败的 HTTP）
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

    // 已加入（含损坏记录）→ 拒绝重复 join
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

    // 未加入 → 拒绝
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

    // 服务器不可达：本地清理优先（吊销失败仅 warn），keyring 必须清干净
    seed_device_identity(&app, &db_path).await;
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(state.device_store.get(&db_path).unwrap().is_none());

    // 二次 leave → 已未加入
    let resp = sync_leave(state.clone()).await.unwrap();
    assert!(!resp.success);
}
#[tokio::test]
async fn sync_list_authorize_revoke_require_membership() {
    let app = mock_app();
    let _db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入：三条管理命令一律拒绝（先于任何网络访问）
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

    // 加入后：目标 id 格式校验先于网络
    // （身份种子只是为了过门禁；不可达服务器下格式错误先报）
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

    // 未初始化 service → 拒绝
    let resp = sync_now(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入 → 拒绝（本地检查先于网络/密码学）
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // 损坏身份记录 → 拒绝（不猜不带病运行）
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("corrupted"));

    // 已加入但服务器未配置 → 拒绝
    seed_device_identity(&app, &db_path).await;
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 已配置但不可达：open 拉信封失败（网络错误冒泡，不留半态——
    // capture 只在整轮周期成功后挂载）
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

    // 锁定后 → 拒绝（门禁在编排之前；lock 同时 detach 捕获缝）
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_now(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// sync_status（§二.5.5 状态显示）与 sync_now 同门禁——共用 open_sync_session：
/// 只读快照也不越过「未初始化/未加入/未配置/锁定」任何一道，且失败如实
/// 报错（不返回假 0 水位）。聚合语义（head/水位/落后/待推/最近同步）在
/// core engine 测试覆盖，宿主层只验门禁。
#[tokio::test]
async fn sync_status_shares_sync_now_gates() {
    let app = mock_app();

    // 未初始化 service → 拒绝
    let resp = sync_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入 → 拒绝
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // 已加入但服务器未配置 → 拒绝（不触网）
    seed_device_identity(&app, &db_path).await;
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 锁定后 → 拒绝
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_status(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// 冲突命令族（阶段 3c）与 sync_now 同门禁——共用 open_sync_session：
/// 未初始化/未加入/未配置/锁定各态先于任何网络或密码学访问被拒；
/// resolve 的参数格式校验先于会话装配（Malformed 不触网）。裁决的完整
/// 语义（采纳/淘汰/幂等面）在 core resolve + runtime 测试覆盖，宿主层
/// 只验门禁与参数面。
#[tokio::test]
async fn sync_conflict_commands_share_sync_now_gates() {
    let app = mock_app();

    // 未初始化 service → 拒绝
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

    // 未加入 → 拒绝（本地检查先于网络/密码学）
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

    // 参数格式校验先于会话装配（Malformed 不触网——此时服务器未配置，
    // 若顺序错误会报 not configured 而非 Malformed）
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

    // 已加入已配置但服务器不可达：open 拉信封失败 → 拒绝（无半态）
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

    // 锁定后 → 拒绝
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = sync_conflicts_list(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
/// 轮换命令（阶段 3d）与 sync_now 同门禁——共用 open_sync_session：
/// 未初始化/未加入/损坏/未配置/不可达/锁定各态先于任何网络或密码学访问
/// 被拒。轮换的完整语义（换信封/重包/边界）在 core runtime + server 真
/// TCP 测试覆盖，宿主层只验门禁与编排。
#[tokio::test]
async fn sync_rotate_gates_before_any_network_or_crypto() {
    let app = mock_app();

    // 未初始化 service → 拒绝
    let resp = sync_rotate(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // 未加入 → 拒绝（本地检查先于网络/密码学）
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not joined"));

    // 损坏身份记录 → 拒绝
    state.device_store.set(&db_path, "{broken").unwrap();
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("corrupted"));

    // 已加入但服务器未配置 → 拒绝
    seed_device_identity(&app, &db_path).await;
    let resp = sync_rotate(state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not configured"));

    // 已配置但不可达：open 拉信封失败 → 拒绝（无半态）
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

    // 锁定后 → 拒绝
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
/// 双端全链路：host create → poll 与 guest join_begin → confirm 并发跑完，
/// 断言两端短指纹一致、两端 keyring 组密钥一致、会话清理干净。
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
