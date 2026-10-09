//! M6 多设备实链走查（离线可完成部分）：真 persona-server router + 两个真
//! core 客户端（`SyncAdminApi`/`SyncSession<HttpSyncRemote>` + 各自临时库），
//! 走完 join → 授权 → 单向同步 → 并发编辑真冲突 → 裁决收敛 → 吊销 的全链路。
//!
//! 与 core/src/sync/runtime.rs 的 MemRemote 单测互补：那里锚定引擎逻辑，
//! 这里锚定 HTTP 线格式与服务器真实现（鉴权、注册、信封、oplog 中继、
//! epoch）。桌面/插件 UI 走查（截图）仍需实机，见 TODO M6。

use persona_core::crypto::key_hierarchy::KeyHierarchy;
use persona_core::crypto::EncryptionService;
use persona_core::models::credential::{
    CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
};
use persona_core::models::identity::{Identity, IdentityType};
use persona_core::storage::database::Database;
use persona_core::storage::repository::{CredentialRepository, IdentityRepository};
use persona_core::sync::capture::SyncCapture;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::envelope;
use persona_core::sync::oplog::{ItemKind, OpType};
use persona_core::sync::remote::SyncAdminApi;
use persona_core::sync::runtime::SyncSession;
use persona_core::sync::snapshot::SyncItemSnapshot;
use persona_core::Repository;
use persona_server::auth::AuthTokens;
use persona_server::build_router;
use persona_server::metrics::Metrics;
use persona_server::state::{self, AppState};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN_A: &str = "e2e-token-device-a";
const TOKEN_B: &str = "e2e-token-device-b";

/// 返回 (base_url, TempDir)：TempDir 必须由调用方持有——sqlite 文件随
/// drop 删除，提前 drop 会让后续请求 500。
async fn spawn_server() -> (String, sqlx::SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("server.db");
    let pool = state::init_pool(db_path.to_str().unwrap()).await.unwrap();
    state::run_migrations(&pool).await.unwrap();
    let auth = AuthTokens::parse(&format!("device-a:{TOKEN_A},device-b:{TOKEN_B}")).unwrap();
    let start_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let app = AppState::new(pool.clone(), Some(auth), Arc::new(Metrics::new(start_unix)));
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), pool.clone(), dir)
}

/// 一台"设备"：独立临时库 + 独立主密钥。两个库种入同一 identity 行 id
/// ——快照携带发起方的 identity_id，materialize 找不到该身份就按
/// pending_identity 跳过，因此双端必须共享同一身份 id。
struct Device {
    db: Database,
    master: EncryptionService,
    identity_id: Uuid,
    cred_repo: CredentialRepository,
}

async fn make_device(shared_identity_id: Uuid) -> Device {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut identity = Identity::new("e2e-seed".to_string(), IdentityType::Personal);
    identity.id = shared_identity_id;
    IdentityRepository::new(db.clone())
        .create(&identity)
        .await
        .unwrap();
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db.clone());
    Device {
        db,
        master,
        identity_id: shared_identity_id,
        cred_repo,
    }
}

fn no_travel() -> Box<dyn Fn() -> bool + Send + Sync> {
    Box::new(|| false)
}

fn password_data(password: &str) -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: password.to_string(),
        email: None,
        security_questions: vec![],
    })
}

fn snapshot(identity_id: Uuid, name: &str, password: &str) -> SyncItemSnapshot {
    SyncItemSnapshot {
        identity_id,
        name: name.to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::High,
        url: None,
        username: Some("e2e@example.com".to_string()),
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data(password),
    }
}

/// 本地编辑 → capture 入 oplog（与桌面 service 装配链同一入口）。
async fn local_put(
    session: &SyncSession<persona_core::sync::remote::HttpSyncRemote>,
    identity_id: Uuid,
    item_id: Uuid,
    name: &str,
    password: &str,
) {
    let item_key = EncryptionService::generate_key();
    let snap = snapshot(identity_id, name, password);
    session
        .capture()
        .capture(
            item_id,
            ItemKind::Credential,
            OpType::Put,
            Some(snap.seal(&item_key).unwrap()),
            Some(Zeroizing::new(item_key)),
        )
        .await;
}

/// 注册一台设备并返回（身份，token）。首台设备自举 group key，
/// 后续设备注册后停在待授权。
async fn register_device(
    admin: &SyncAdminApi,
    name: &str,
    token: &str,
    bootstrap: bool,
) -> (DeviceIdentity, Uuid) {
    let identity = DeviceIdentity::generate(name).unwrap();
    let device_id = admin
        .register_device(name, identity.key_pair.public_bytes())
        .await
        .unwrap();
    let identity = identity.with_device_id(device_id);
    if bootstrap {
        admin
            .bootstrap_group_if_empty(device_id, identity.key_pair.public_bytes())
            .await
            .unwrap();
    }
    let _ = token;
    (identity, device_id)
}

/// 首台设备授权后续设备：拆自己的信封得 group key，为对方包新信封上传
/// （与桌面 sync_authorize 同编排）。
async fn authorize(admin: &SyncAdminApi, me: &DeviceIdentity, target: Uuid) {
    let keys = admin.group_keys().await.unwrap();
    let own = keys
        .iter()
        .find(|k| k.device_id == me.device_id)
        .expect("own envelope must exist after bootstrap");
    let group = envelope::open_group_key(&own.envelope, me.key_pair.secret_bytes()).unwrap();
    let target_device = admin
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.id == target)
        .expect("target device registered");
    let sealed = envelope::seal_group_key(&group, &target_device.public_key);
    admin.put_group_key(target, &sealed).await.unwrap();
}

/// A 建一个凭据（capture → oplog → push），返回 item_id。
async fn device_a_creates_item(
    session_a: &SyncSession<persona_core::sync::remote::HttpSyncRemote>,
    device: &Device,
    name: &str,
    password: &str,
) -> Uuid {
    let item_id = Uuid::new_v4();
    local_put(session_a, device.identity_id, item_id, name, password).await;
    let report = session_a.run_cycle(&device.master).await.unwrap();
    assert_eq!(report.pushed, 1, "v1 should push to the server");
    item_id
}

#[tokio::test]
async fn join_authorize_and_single_direction_sync() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    // 双端共享同一 identity 行 id（materialize 的身份外键）
    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    // join：A 自举，B 待授权
    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;

    // B 未授权：开不了会话（fail-closed）
    let pending = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel()).await;
    assert!(
        pending.is_err(),
        "device B must not open a session before authorization"
    );

    // A 授权 B，B 重开会话成功
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // A 建凭据并推送
    let item_id = device_a_creates_item(&session_a, &a, "来自A的凭据", "secret-a").await;

    // B 拉取并物化：主库出现同名条目
    let report_b = session_b.run_cycle(&b.master).await.unwrap();
    assert!(
        report_b.materialized >= 1,
        "B should materialize A's credential, got {report_b:?}"
    );
    let names: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert!(
        names.contains(&"来自A的凭据".to_string()),
        "B's vault should contain A's credential, got {names:?}"
    );
    let _ = item_id;
}

#[tokio::test]
async fn concurrent_edits_conflict_then_resolution_converges() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // 基线：A 建 v1，B 同步到手（双方 lamport 对齐在 v1）
    let item_id = device_a_creates_item(&session_a, &a, "并发条目", "v1").await;
    let baseline = session_b.run_cycle(&b.master).await.unwrap();
    assert!(baseline.materialized >= 1);

    // 离线并发编辑：双端各改同名条目（同 lamport、不同 device = 真冲突）
    local_put(&session_a, identity_id, item_id, "并发条目", "edit-from-A").await;
    local_put(&session_b, identity_id, item_id, "并发条目", "edit-from-B").await;

    // 双方先后上线推拉
    session_a.run_cycle(&a.master).await.unwrap();
    session_b.run_cycle(&b.master).await.unwrap();
    session_a.run_cycle(&a.master).await.unwrap();

    // 双端都看到真冲突待裁决
    assert_eq!(
        session_a.conflict_item_count().await.unwrap(),
        1,
        "A must see the concurrent conflict"
    );
    assert_eq!(
        session_b.conflict_item_count().await.unwrap(),
        1,
        "B must see the concurrent conflict"
    );

    // A 裁决：采纳落选副本（adopt_op_id = copies 里的 op id；谁是 LWW
    // 胜者由 device_id 字典序随机决定，落选者内容决定断言期望）
    let conflicts = session_a.list_conflicts().await.unwrap();
    assert_eq!(conflicts.len(), 1);
    let loser = &conflicts[0].copies[0];
    let expected_password = if loser.device_id == identity_b.device_id {
        "edit-from-B"
    } else {
        "edit-from-A"
    };
    session_a
        .resolve_conflict(&a.master, item_id, loser.op_id)
        .await
        .unwrap();

    // 裁决后 A 的主库内容翻转为被采纳副本
    let a_creds = a.cred_repo.find_by_identity(&identity_id).await.unwrap();
    assert!(
        a_creds.iter().any(|c| c.name == "并发条目"),
        "adopted item stays in A's vault, got {:?}",
        a_creds.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    let adopted = a_creds.iter().find(|c| c.id == item_id).unwrap();
    let plain = KeyHierarchy::new(&a.master)
        .decrypt_with_wrapped_key(
            adopted.wrapped_item_key.as_ref().unwrap(),
            &adopted.encrypted_data,
        )
        .unwrap();
    match CredentialData::from_bytes(&plain).unwrap() {
        CredentialData::Password(pw) => assert_eq!(
            pw.password, expected_password,
            "A's vault must adopt the losing copy's content"
        ),
        other => panic!("expected password credential, got {other:?}"),
    }
    // 收敛：B 再跑一轮，双端不再有未裁决冲突
    session_a.run_cycle(&a.master).await.unwrap();
    session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(
        session_a.conflict_item_count().await.unwrap(),
        0,
        "A's conflict should be cleared after resolution"
    );
    assert_eq!(
        session_b.conflict_item_count().await.unwrap(),
        0,
        "B's conflict should be cleared after the resolution cycle"
    );
}

#[tokio::test]
async fn revoke_device_drops_envelope_and_blocks_new_sessions() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let _a = make_device(shared_identity.id).await;
    let b = make_device(shared_identity.id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;

    // 吊销前 B 能正常开会话
    assert!(
        SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
            .await
            .is_ok()
    );

    // A 吊销 B（与桌面 sync_revoke 同语义：删登记+信封，幂等）
    admin_a.delete_device(device_id_b).await.unwrap();

    // 信封随吊销消失：新会话开不出来（fail-closed）
    let fresh_b = make_device(shared_identity.id).await;
    let blocked = SyncSession::open(&fresh_b.db, &identity_b, &url, TOKEN_B, no_travel()).await;
    assert!(
        blocked.is_err(),
        "revoked device must not open a new sync session"
    );

    // 设备清单里不再有 B
    let devices = admin_a.list_devices().await.unwrap();
    assert!(
        devices.iter().all(|d| d.id != device_id_b),
        "revoked device must disappear from the roster, got {devices:?}"
    );
}

/// S4 设备自备注：各端写各自令牌名下的 remark（无跨设备路径），全员
/// 可读；空串/纯空白清除；吊销后原设备写不进（404 fail-closed）。
#[tokio::test]
async fn device_remark_self_service_and_isolation() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();
    let admin_b = SyncAdminApi::new(&url, TOKEN_B).unwrap();

    let (_identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (_identity_b, device_id_b) = register_device(&admin_b, "device-b", TOKEN_B, false).await;

    // 各写各的（服务端 trim 规整后回显）
    let stored_a = admin_a.set_device_remark("  书房的主力机  ").await.unwrap();
    assert_eq!(stored_a, "书房的主力机", "server must trim the remark");
    let stored_b = admin_b.set_device_remark("口袋里的备用机").await.unwrap();
    assert_eq!(stored_b, "口袋里的备用机");

    // 清单双向可见，值各归各（B 的写入动不了 A 的行）
    let names: Vec<(String, String)> = admin_a
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| (d.device_name, d.remark))
        .collect();
    assert!(
        names.contains(&("device-a".to_string(), "书房的主力机".to_string()))
            && names.contains(&("device-b".to_string(), "口袋里的备用机".to_string())),
        "both remarks must be visible with their own values, got {names:?}"
    );

    // 纯空白 = 清除
    assert_eq!(admin_b.set_device_remark("   ").await.unwrap(), "");
    let b_row = admin_b
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.device_name == "device-b")
        .unwrap();
    assert_eq!(b_row.remark, "", "whitespace must clear the remark");

    // 吊销 B 后其令牌写不进 remark（登记行已删 → 404 absent）
    admin_a.delete_device(device_id_b).await.unwrap();
    let err = admin_b.set_device_remark("复活").await.unwrap_err();
    assert!(
        err.to_string().contains("HTTP 404"),
        "revoked device must fail closed, got: {err}"
    );
}

// 快照起步 + 点后增量 == 全量重放（E2EE_SYNC_DESIGN §5 测试锚点）：
// 双真 TCP 设备，B 初同步走快照路径——A 推满阈值（>1000 ops）触发
// run_cycle 尾部的打包上传（真实生产触发路径，无测试专用旁路），服务器
// 事务内压缩覆盖区间；B 首轮 pulled==0 且物化全量 = 只能来自快照装包
// （全量重放路径必然 pulled==1001），水位落在覆盖位点；点后增量照常续拉。
#[tokio::test]
async fn snapshot_bootstrap_plus_increment_converges_over_real_tcp() {
    let (url, _server_pool, _server_dir) = spawn_server().await;
    let admin_a = SyncAdminApi::new(&url, TOKEN_A).unwrap();

    let shared_identity = Identity::new("e2e".to_string(), IdentityType::Personal);
    let identity_id = shared_identity.id;
    let a = make_device(identity_id).await;
    let b = make_device(identity_id).await;

    let (identity_a, _device_id_a) = register_device(&admin_a, "device-a", TOKEN_A, true).await;
    let (identity_b, device_id_b) = register_device(&admin_a, "device-b", TOKEN_B, false).await;
    authorize(&admin_a, &identity_a, device_id_b).await;
    let session_a = SyncSession::open(&a.db, &identity_a, &url, TOKEN_A, no_travel())
        .await
        .unwrap();
    let session_b = SyncSession::open(&b.db, &identity_b, &url, TOKEN_B, no_travel())
        .await
        .unwrap();

    // A 推满 1001 条（> UPLOAD_THRESHOLD_OPS=1000）：push 每周期一批
    // （≤500），跑到待推清零——最后一个周期越过阈值触发打包上传（服务器
    // 压缩 seq ≤ 1001 全部 ops）
    for i in 1..=1001 {
        local_put(
            &session_a,
            identity_id,
            Uuid::new_v4(),
            &format!("item-{i}"),
            &format!("secret-{i}"),
        )
        .await;
    }
    let mut total_pushed = 0;
    for _ in 0..5 {
        let report_a = session_a.run_cycle(&a.master).await.unwrap();
        total_pushed += report_a.pushed;
        if report_a.pushed == 0 {
            break;
        }
    }
    assert_eq!(total_pushed, 1001, "all ops must reach the server");

    // B 首轮同步：bootstrap 装快照起步，pull 零增量、物化全量
    let report_b = session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(
        report_b.pulled, 0,
        "server oplog was fully compressed; anything B got must come from the snapshot"
    );
    assert_eq!(
        report_b.materialized, 1001,
        "B must materialize the whole library from the snapshot"
    );
    let status_b = session_b.status().await.unwrap();
    assert_eq!(
        status_b.head_seq, 1001,
        "head is snapshot-aware: oplog emptied by compression must not regress the group version"
    );
    assert_eq!(
        status_b.local_watermark, 1001,
        "cursor must sit at the snapshot coverage point"
    );
    assert_eq!(status_b.behind, 0);

    // 快照装包内容与 A 主库逐条一致（抽全量名字 + 抽一条解密比对）
    let mut b_names: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    b_names.sort();
    assert_eq!(b_names.len(), 1001);
    assert_eq!(b_names[0], "item-1");
    assert_eq!(b_names[1000], "item-999");
    let b_row = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "item-42")
        .expect("item-42 must materialize from the snapshot");
    let plain = KeyHierarchy::new(&b.master)
        .decrypt_with_wrapped_key(
            b_row.wrapped_item_key.as_ref().unwrap(),
            &b_row.encrypted_data,
        )
        .unwrap();
    match CredentialData::from_bytes(&plain).unwrap() {
        CredentialData::Password(pw) => assert_eq!(pw.password, "secret-42"),
        other => panic!("expected password credential, got {other:?}"),
    }

    // 点后增量：A 追加一条，B 照常续拉（游标在覆盖位点，只拿新段）
    local_put(
        &session_a,
        identity_id,
        Uuid::new_v4(),
        "item-1002",
        "secret-1002",
    )
    .await;
    session_a.run_cycle(&a.master).await.unwrap();
    let report_b2 = session_b.run_cycle(&b.master).await.unwrap();
    assert_eq!(report_b2.pulled, 1, "only the post-snapshot op is new");
    assert!(report_b2.materialized >= 1);
    let b_names2: Vec<String> = b
        .cred_repo
        .find_by_identity(&identity_id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(
        b_names2.len(),
        1002,
        "increment must converge on the snapshot base"
    );
    assert!(b_names2.contains(&"item-1002".to_string()));
}
