use super::*;

// E2EE_SYNC_DESIGN 阶段 2 批 4 验收「两端收敛测试」：真 HTTP 栈 +
// 客户端 wire 层（core HttpSyncRemote）+ 两份独立 oplog（各挂
// SyncEngine）。覆盖：单向 push→pull、双端同 lamport 离线编辑的真
// 冲突（两端收敛到同一主位 + 双版本保留）、重建 engine 实例（状态全
// 在库：local_lamport/游标/pending 不随实例走——换主密码零影响同步
// 的构造性证明：SyncEngine 全链路无主密码参数，实例可弃可换）。
#[tokio::test(flavor = "multi_thread")]
async fn two_devices_converge_over_real_tcp_conflict_keeps_both_versions() {
    use persona_core::storage::sync_repository::SyncRepository;
    use persona_core::storage::Database;
    use persona_core::sync::engine::SyncEngine;
    use persona_core::sync::oplog::{item_view, ItemKind, OpType, SyncPayload};
    use persona_core::sync::remote::HttpSyncRemote;

    const TOKEN: &str = "sync-e2e-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    async fn fresh_repo() -> (SyncRepository, Database) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let repo = SyncRepository::new(db.clone());
        (repo, db)
    }

    fn engine_for(
        db: Database,
        base: &str,
        token: &str,
        device_id: Uuid,
    ) -> SyncEngine<HttpSyncRemote> {
        SyncEngine::new(
            SyncRepository::new(db),
            HttpSyncRemote::new(base, token).unwrap(),
            device_id,
            Box::new(|| false),
        )
    }

    fn payload(tag: u8) -> Option<SyncPayload> {
        Some(SyncPayload {
            ciphertext: vec![tag; 8],
            wrapped_item_key: vec![tag; 32],
        })
    }

    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let (repo_a, db_a) = fresh_repo().await;
    let (repo_b, db_b) = fresh_repo().await;
    let engine_a = engine_for(db_a.clone(), &base, TOKEN, device_a);
    let engine_b = engine_for(db_b, &base, TOKEN, device_b);

    // A 离线写 lamport 1 并 push
    let item = Uuid::new_v4();
    let a1 = engine_a
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA1))
        .await
        .unwrap();
    assert_eq!(a1.lamport, 1);
    assert_eq!(engine_a.push_cycle().await.unwrap().pushed, 1);

    // B 上线拉到 A1，看到的主位就是 A 的版本
    let pull = engine_b.pull_cycle().await.unwrap();
    assert_eq!(pull.applied, 1);
    assert_eq!(repo_b.get_state().await.unwrap().local_lamport, 1);
    let view_b = item_view(repo_b.item_ops(item).await.unwrap());
    assert_eq!(view_b.primary.as_ref().unwrap().device_id, device_a);
    assert!(view_b.conflicts.is_empty());

    // 双端离线同 lamport 编辑：B 从 lamport 1 出发写 2 并 push；A 不
    // 知情（没拉过 B2），也从 1 出发写 2——真冲突的典型形态
    let b2 = engine_b
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xB2))
        .await
        .unwrap();
    assert_eq!(b2.lamport, 2);
    assert_eq!(engine_b.push_cycle().await.unwrap().pushed, 1);

    // A 端重建 engine 实例（同一库句柄）：时钟延续正确——下一条仍接
    // lamport 2（local_lamport 在库不在实例）
    let engine_a2 = engine_for(db_a, &base, TOKEN, device_a);
    let a2 = engine_a2
        .record_local_change(item, ItemKind::Credential, OpType::Put, payload(0xA2))
        .await
        .unwrap();
    assert_eq!(a2.lamport, 2);
    assert_eq!(engine_a2.push_cycle().await.unwrap().pushed, 1);

    // 双端各拉一轮 → 各自 oplog 持有 {A1, B2, A2} 全集
    let pull_a = engine_a2.pull_cycle().await.unwrap();
    assert_eq!(pull_a.applied, 1); // A1 是自己的本地 op，去重跳过
    let pull_b = engine_b.pull_cycle().await.unwrap();
    assert_eq!(pull_b.applied, 1);

    // 收敛断言：两端 oplog 全集一致，主位收敛到同一 op（全序裁决），
    // 冲突区恰一条，胜者/负者双版本密文都在（数据不丢）
    let ops_a = repo_a.item_ops(item).await.unwrap();
    let ops_b = repo_b.item_ops(item).await.unwrap();
    assert_eq!(ops_a.len(), 3);
    assert_eq!(ops_b.len(), 3);
    let view_a = item_view(ops_a);
    let view_b = item_view(ops_b);
    let primary_a = view_a.primary.as_ref().unwrap();
    let primary_b = view_b.primary.as_ref().unwrap();
    assert_eq!(primary_a.op_id, primary_b.op_id);
    assert_eq!(primary_a.device_id, device_a.max(device_b)); // 字典序大者胜
    assert_eq!(view_a.conflicts.len(), 1);
    assert_eq!(view_b.conflicts.len(), 1);
    assert_eq!(view_a.conflicts[0].op_id, view_b.conflicts[0].op_id);
    // 双版本密文都可读且可区分（胜者/负者都不丢——数据不丢的落库证明）
    let primary_tag = primary_a.payload.as_ref().unwrap().ciphertext[0];
    let conflict_tag = view_a.conflicts[0].payload.as_ref().unwrap().ciphertext[0];
    assert_ne!(primary_tag, conflict_tag);

    task.abort();
}

// SyncAdminApi（core 客户端 wire 层）与 server 契约的真 TCP 对齐测试：
// handler 语义已由上面的单测覆盖（409/422/级联等），这里验证客户端侧
// 类型转换（device_id Uuid、public_key [u8;32]、envelope 字节原样往返）
// 与错误路径（409 message 透传到 Err、幽灵设备 fail-closed）。
#[tokio::test(flavor = "multi_thread")]
async fn admin_api_client_manages_devices_and_group_keys_over_real_tcp() {
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-admin-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // 注册两台设备
    let laptop_id = admin
        .register_device("laptop", &[7u8; 32])
        .await
        .expect("register laptop");
    let phone_id = admin
        .register_device("phone", &[9u8; 32])
        .await
        .expect("register phone");
    assert_ne!(laptop_id, phone_id);

    // 重名 → 409，message 透传到 Err（客户端不吞服务器语义）
    let dup = admin
        .register_device("laptop", &[1u8; 32])
        .await
        .unwrap_err();
    assert!(
        dup.to_string().contains("already registered"),
        "unexpected error: {dup:#}"
    );

    // 列表：名称 + 公钥字节级还原
    let devices = admin.list_devices().await.expect("list devices");
    assert_eq!(devices.len(), 2);
    let laptop = devices
        .iter()
        .find(|d| d.id == laptop_id)
        .expect("laptop in list");
    assert_eq!(laptop.device_name, "laptop");
    assert_eq!(laptop.public_key, [7u8; 32]);
    assert!(!laptop.created_at.is_empty());

    // 起始无信封
    assert!(admin.group_keys().await.expect("empty keys").is_empty());

    // 上传信封（恰 80B）→ 原样取回，sealed_by = AuthTokens::single 的设备名
    let envelope: Vec<u8> = (0..80).map(|i| i as u8).collect();
    admin
        .put_group_key(laptop_id, &envelope)
        .await
        .expect("put group key");
    // 幽灵设备 fail-closed → Err
    admin
        .put_group_key(Uuid::new_v4(), &[0u8; 80])
        .await
        .expect_err("ghost device must be rejected");
    // 同设备覆盖（upsert）不报错
    admin
        .put_group_key(laptop_id, &[0xAA; 80])
        .await
        .expect("overwrite group key");

    let keys = admin.group_keys().await.expect("group keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, laptop_id);
    assert_eq!(keys[0].envelope, vec![0xAA; 80]);
    assert_eq!(keys[0].sealed_by, "default");

    // 吊销 laptop：幂等（二次删除同 204）+ 信封级联消失
    admin.delete_device(laptop_id).await.expect("revoke laptop");
    admin
        .delete_device(laptop_id)
        .await
        .expect("revoke laptop twice is idempotent");
    let devices = admin.list_devices().await.expect("list after revoke");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, phone_id);
    assert!(admin
        .group_keys()
        .await
        .expect("keys after revoke")
        .is_empty());

    task.abort();
}

// 首设备自举：全新服务器上第一台设备 join 时无人能授权它（信封由
// 「既有设备」封出，而此刻不存在既有设备）——bootstrap_group_if_empty
// 在空组上自建组密钥 + 自封信封，第二台设备起恢复「等既有设备授权」
// 流程。这是 join 流程能在真机上跑通的前提（阶段 3 演示脚本第一步）。
#[tokio::test(flavor = "multi_thread")]
async fn admin_api_bootstrap_creates_group_on_fresh_server_and_second_device_still_pends() {
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-bootstrap-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // 首设备：登记后空组自举 → true，且本机能拆开自己的信封
    let laptop = DeviceIdentity::generate("laptop").unwrap();
    let laptop_id = admin
        .register_device("laptop", laptop.key_pair.public_bytes())
        .await
        .expect("register first device");
    let bootstrapped = admin
        .bootstrap_group_if_empty(laptop_id, laptop.key_pair.public_bytes())
        .await
        .expect("bootstrap on fresh server");
    assert!(bootstrapped);
    let keys = admin.group_keys().await.expect("keys after bootstrap");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, laptop_id);
    let group = open_group_key(&keys[0].envelope, laptop.key_pair.secret_bytes())
        .expect("own envelope opens");

    // 第二台设备：组已非空 → 不自举（false），等首设备授权
    let phone = DeviceIdentity::generate("phone").unwrap();
    let phone_id = admin
        .register_device("phone", phone.key_pair.public_bytes())
        .await
        .expect("register second device");
    let bootstrapped = admin
        .bootstrap_group_if_empty(phone_id, phone.key_pair.public_bytes())
        .await
        .expect("bootstrap on non-empty group");
    assert!(!bootstrapped);

    // 首设备代授权：拆自己的 group key → 用对方公钥封新信封上传
    let envelope = seal_group_key(&group, phone.key_pair.public_bytes()).unwrap();
    admin
        .put_group_key(phone_id, &envelope)
        .await
        .expect("authorize phone");
    let keys = admin.group_keys().await.expect("keys after authorize");
    assert_eq!(keys.len(), 2);
    let phone_entry = keys.iter().find(|k| k.device_id == phone_id).unwrap();
    let group_phone = open_group_key(&phone_entry.envelope, phone.key_pair.secret_bytes())
        .expect("phone opens its envelope");
    assert_eq!(group, group_phone, "both devices hold the same group key");

    task.abort();
}

// group key 轮换全流程（真 TCP，阶段 3d）：A 自举建组并授权 B → A
// rotate（换信封 + 全量重包）→ 信封集仍恰好覆盖两台授权设备、全部拆出
// **新** key；随后 B 与后入组的 C 各自开会话拉全量——重包 op 全部可读
// 物化（旧 key 批次按「严格旧版本」忽略，当前态由重包 op 补齐）。
#[tokio::test(flavor = "multi_thread")]
async fn rotate_group_key_swaps_envelopes_and_new_devices_read_rewrapped_ops() {
    use persona_core::crypto::encryption::EncryptionService;
    use persona_core::crypto::key_hierarchy::KeyHierarchy;
    use persona_core::models::credential::{
        Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::models::identity::{Identity, IdentityType};
    use persona_core::storage::repository::IdentityRepository;
    use persona_core::storage::{CredentialRepository, Database, Repository};
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::remote::SyncAdminApi;
    use persona_core::sync::runtime::SyncSession;

    const TOKEN: &str = "sync-rotate-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");
    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // A 自举建组；授权 B（旧组密钥信封）。登记后 with_device_id 回填
    // 服务器分配的 UUID（与桌面版 sync_join 同序）。
    let dev_a = DeviceIdentity::generate("rotator-a").unwrap();
    let id_a = admin
        .register_device("rotator-a", dev_a.key_pair.public_bytes())
        .await
        .expect("register A");
    let dev_a = dev_a.with_device_id(id_a);
    assert!(admin
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .expect("bootstrap A"));
    let group_old = open_group_key(
        &admin.group_keys().await.unwrap()[0].envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .expect("A opens own envelope");

    let dev_b = DeviceIdentity::generate("member-b").unwrap();
    let id_b = admin
        .register_device("member-b", dev_b.key_pair.public_bytes())
        .await
        .expect("register B");
    let dev_b = dev_b.with_device_id(id_b);
    admin
        .put_group_key(
            id_b,
            &seal_group_key(&group_old, dev_b.key_pair.public_bytes()).unwrap(),
        )
        .await
        .expect("authorize B");

    // A 的本地库：两条凭据 + 真会话（HttpSyncRemote）
    let db_a = Database::in_memory().await.unwrap();
    db_a.migrate().await.unwrap();
    let owner = Identity::new("seed".to_string(), IdentityType::Personal);
    IdentityRepository::new(db_a.clone())
        .create(&owner)
        .await
        .unwrap();
    let master_a = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db_a.clone());
    for (name, secret) in [("cred-one", "one"), ("cred-two", "two")] {
        let item_key = EncryptionService::generate_key();
        let wrapped = master_a.encrypt(&item_key).unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let ciphertext = KeyHierarchy::new(&master_a)
            .encrypt_with_item_key(&item_key, &plaintext)
            .unwrap();
        cred_repo
            .create(&Credential::new(
                owner.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                ciphertext,
                Some(wrapped),
            ))
            .await
            .unwrap();
    }

    let session_a = SyncSession::open(&db_a, &dev_a, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session A");
    assert_eq!(session_a.backfill_existing(&master_a).await.unwrap(), 2);

    // 轮换：前置 drain（旧 key 批次 2 条）+ 重包（2 条）+ 再 drain
    let report = session_a.rotate_group_key(&master_a, &admin).await.unwrap();
    assert_eq!((report.rewrapped, report.skipped), (2, 0));
    assert_eq!(report.pushed, 4);

    // 信封集：仍恰好两台授权设备，且都拆出**新** key（≠旧 key）
    let keys = admin.group_keys().await.unwrap();
    assert_eq!(keys.len(), 2);
    let group_new = open_group_key(
        &keys.iter().find(|k| k.device_id == id_a).unwrap().envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .expect("A opens rotated envelope");
    let group_new_b = open_group_key(
        &keys.iter().find(|k| k.device_id == id_b).unwrap().envelope,
        dev_b.key_pair.secret_bytes(),
    )
    .expect("B opens rotated envelope");
    assert_eq!(group_new, group_new_b);
    assert_ne!(group_new, group_old);

    // B（会话开在轮换后 → 只持新 key）拉全量：重包 op 全部物化
    let (db_b, master_b) = member_db(owner.id).await;
    let session_b = SyncSession::open(&db_b, &dev_b, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session B");
    let report_b = session_b.run_cycle(&master_b).await.unwrap();
    assert_eq!(report_b.pulled, 4);
    assert_eq!(report_b.materialized, 2);
    assert_eq!(report_b.conflicts, 0);
    assert_eq!(report_b.pending_identity, 0);
    assert_stored_credentials(&db_b, &master_b).await;

    // 后入组的 C：授权拿到新 key，拉全量同样全部可读
    let dev_c = DeviceIdentity::generate("late-c").unwrap();
    let id_c = admin
        .register_device("late-c", dev_c.key_pair.public_bytes())
        .await
        .expect("register C");
    let dev_c = dev_c.with_device_id(id_c);
    admin
        .put_group_key(
            id_c,
            &seal_group_key(&group_new, dev_c.key_pair.public_bytes()).unwrap(),
        )
        .await
        .expect("authorize C");
    let (db_c, master_c) = member_db(owner.id).await;
    let session_c = SyncSession::open(&db_c, &dev_c, &base, TOKEN, Box::new(|| false))
        .await
        .expect("session C");
    let report_c = session_c.run_cycle(&master_c).await.unwrap();
    assert_eq!(report_c.pulled, 4);
    assert_eq!(report_c.materialized, 2);
    assert_stored_credentials(&db_c, &master_c).await;

    task.abort();
}

/// 轮换中途崩溃 → 重试即重跑自愈（E2EE_SYNC_DESIGN §11-2 收口）：
/// 模拟「begin 抢到互斥 + 只给一台设备写了新信封就崩溃」——信封族
/// 停留混合态（A 拆得崩溃轮 key、B 仍是旧信封）。重启后完整
/// rotate_group_key 重读 epoch 重跑：崩溃轮残留信封被重试轮新信封
/// 覆盖（信封行不膨胀）、epoch 累计两轮 begin、全组（B 拉全量）收敛
/// 可解——崩溃轮重包不存在（未发生），残留只影响信封，被 upsert
/// 幂等覆盖即自愈。
#[tokio::test(flavor = "multi_thread")]
async fn crashed_mid_rotation_retry_rewrites_envelopes_and_converges() {
    use persona_core::crypto::encryption::EncryptionService;
    use persona_core::crypto::key_hierarchy::KeyHierarchy;
    use persona_core::models::credential::{
        Credential, CredentialData, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use persona_core::models::identity::{Identity, IdentityType};
    use persona_core::storage::repository::IdentityRepository;
    use persona_core::storage::{CredentialRepository, Database, Repository};
    use persona_core::sync::device::DeviceIdentity;
    use persona_core::sync::envelope::{open_group_key, seal_group_key};
    use persona_core::sync::keys::GroupKey;
    use persona_core::sync::remote::SyncAdminApi;
    use persona_core::sync::runtime::SyncSession;

    const TOKEN: &str = "sync-rotate-crash-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");
    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();

    // A 自举建组 + 授权 B（与既有 rotate 全流程测试同构）
    let dev_a = DeviceIdentity::generate("crashy-a").unwrap();
    let id_a = admin
        .register_device("crashy-a", dev_a.key_pair.public_bytes())
        .await
        .unwrap();
    let dev_a = dev_a.with_device_id(id_a);
    assert!(admin
        .bootstrap_group_if_empty(id_a, dev_a.key_pair.public_bytes())
        .await
        .unwrap());
    let group_old = open_group_key(
        &admin.group_keys().await.unwrap()[0].envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .unwrap();

    let dev_b = DeviceIdentity::generate("survivor-b").unwrap();
    let id_b = admin
        .register_device("survivor-b", dev_b.key_pair.public_bytes())
        .await
        .unwrap();
    let dev_b = dev_b.with_device_id(id_b);
    admin
        .put_group_key(
            id_b,
            &seal_group_key(&group_old, dev_b.key_pair.public_bytes()).unwrap(),
        )
        .await
        .unwrap();

    // A 的本地库：两条凭据 + backfill 入账
    let db_a = Database::in_memory().await.unwrap();
    db_a.migrate().await.unwrap();
    let owner = Identity::new("seed".to_string(), IdentityType::Personal);
    IdentityRepository::new(db_a.clone())
        .create(&owner)
        .await
        .unwrap();
    let master_a = EncryptionService::new(&EncryptionService::generate_key());
    let cred_repo = CredentialRepository::new(db_a.clone());
    for (name, secret) in [("cred-one", "one"), ("cred-two", "two")] {
        let item_key = EncryptionService::generate_key();
        let wrapped = master_a.encrypt(&item_key).unwrap();
        let plaintext = CredentialData::Password(PasswordCredentialData {
            password: secret.to_string(),
            email: None,
            security_questions: vec![],
        })
        .to_bytes()
        .unwrap();
        let ciphertext = KeyHierarchy::new(&master_a)
            .encrypt_with_item_key(&item_key, &plaintext)
            .unwrap();
        cred_repo
            .create(&Credential::new(
                owner.id,
                name.to_string(),
                CredentialType::Password,
                SecurityLevel::High,
                ciphertext,
                Some(wrapped),
            ))
            .await
            .unwrap();
    }
    let session_a = SyncSession::open(&db_a, &dev_a, &base, TOKEN, Box::new(|| false))
        .await
        .unwrap();
    assert_eq!(session_a.backfill_existing(&master_a).await.unwrap(), 2);

    // ---- 模拟崩溃半程：begin 抢到互斥，只给 A 写新信封就「崩溃」----
    let (keys, epoch) = admin.group_keys_with_epoch().await.unwrap();
    assert_eq!(epoch, 0);
    let authorized: std::collections::HashSet<Uuid> = keys.iter().map(|k| k.device_id).collect();
    assert_eq!(authorized.len(), 2);
    admin.begin_group_rotation(epoch).await.unwrap();
    let crashed_key = GroupKey::generate().unwrap();
    admin
        .put_group_key(
            id_a,
            &seal_group_key(crashed_key.as_bytes(), dev_a.key_pair.public_bytes()).unwrap(),
        )
        .await
        .unwrap();
    // 混合态显形：A 的信封已换崩溃轮 key，B 的信封仍是旧 key
    assert_ne!(
        open_group_key(
            &admin
                .group_keys()
                .await
                .unwrap()
                .iter()
                .find(|k| k.device_id == id_a)
                .unwrap()
                .envelope,
            dev_a.key_pair.secret_bytes()
        )
        .unwrap(),
        group_old
    );

    // ---- 重启后重试：完整 rotate_group_key 重跑自愈 ----
    let report = session_a.rotate_group_key(&master_a, &admin).await.unwrap();
    assert_eq!((report.rewrapped, report.skipped), (2, 0));
    assert_eq!(report.pushed, 4);

    // 信封行不膨胀（仍恰好两台授权设备）；两台拆出的都是重试轮 key
    // ——既非旧 key，也非崩溃轮 key（残留信封被 upsert 覆盖）
    let keys_after = admin.group_keys().await.unwrap();
    assert_eq!(keys_after.len(), 2);
    let retried_key_a = open_group_key(
        &keys_after
            .iter()
            .find(|k| k.device_id == id_a)
            .unwrap()
            .envelope,
        dev_a.key_pair.secret_bytes(),
    )
    .unwrap();
    let retried_key_b = open_group_key(
        &keys_after
            .iter()
            .find(|k| k.device_id == id_b)
            .unwrap()
            .envelope,
        dev_b.key_pair.secret_bytes(),
    )
    .unwrap();
    assert_eq!(retried_key_a, retried_key_b);
    assert_ne!(retried_key_a, group_old);
    assert_ne!(retried_key_a, *crashed_key.as_bytes());

    // epoch 累计两轮 begin（崩溃半程 +1、重试 +1）
    let (_, epoch_after) = admin.group_keys_with_epoch().await.unwrap();
    assert_eq!(epoch_after, 2);

    // 全组收敛：B 新开会话（拆得重试轮 key）拉全量，重包 op 全部物化
    let (db_b, master_b) = member_db(owner.id).await;
    let session_b = SyncSession::open(&db_b, &dev_b, &base, TOKEN, Box::new(|| false))
        .await
        .unwrap();
    let report_b = session_b.run_cycle(&master_b).await.unwrap();
    assert_eq!(report_b.pulled, 4);
    assert_eq!(report_b.materialized, 2);
    assert_eq!(report_b.conflicts, 0);
    assert_stored_credentials(&db_b, &master_b).await;

    task.abort();
}

// 设备吊销闭环（真 TCP）：同名 SRP 登记随同步设备吊销级联——既有
// 短期令牌**即刻**失效（不等 15 分钟 TTL），重新登录被拒（与未注册
// 同形 401）；吊销幂等。THREAT_MODEL「SRP 设备认证端点」已知限制
// 「auth_devices 无删除路径」由本路径关闭。
#[tokio::test(flavor = "multi_thread")]
async fn revoked_sync_device_loses_srp_access_and_outstanding_tokens() {
    use persona_core::auth::remote_http::HttpRemoteAuthProvider;
    use persona_core::sync::remote::SyncAdminApi;

    const TOKEN: &str = "sync-revoke-closure-token";
    let (router, _state) = setup(Some(TOKEN)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    let base = format!("http://{addr}");

    let admin = SyncAdminApi::new(&base, TOKEN).unwrap();
    let id = admin
        .register_device("laptop", &[7u8; 32])
        .await
        .expect("register sync device");

    // 同名 SRP 登记 + 登录拿短期令牌
    let provider = HttpRemoteAuthProvider::new(base.clone()).unwrap();
    provider
        .register_device(TOKEN, "laptop", "pw-for-device")
        .await
        .expect("SRP enroll");
    let outcome = provider
        .begin_login("laptop")
        .await
        .unwrap()
        .finish("pw-for-device")
        .await
        .expect("SRP login");

    // 令牌可用：过 require_bearer 访问 sync 端点
    let client = reqwest::Client::new();
    let probe = client
        .get(format!("{base}/api/v1/sync/devices"))
        .bearer_auth(&outcome.token)
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::OK, "{probe:?}");

    // 吊销同步设备：级联删 SRP 行 + 即吊内存令牌
    admin.delete_device(id).await.expect("revoke");

    // 既有令牌即刻 401（不等 TTL）
    let probe = client
        .get(format!("{base}/api/v1/sync/devices"))
        .bearer_auth(&outcome.token)
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::UNAUTHORIZED, "{probe:?}");
    // 重新 SRP 登录 401（登记行已删——challenge 与未注册同形 401，
    // 登录链路任一步失败均算闭包成立）
    let err = match provider.begin_login("laptop").await {
        Ok(handle) => handle
            .finish("pw-for-device")
            .await
            .err()
            .map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    };
    let err = err.expect("login must fail after revocation");
    assert!(err.contains("HTTP 401"), "{err}");
    // 二次吊销幂等
    admin.delete_device(id).await.expect("revoke twice");

    task.abort();
}
