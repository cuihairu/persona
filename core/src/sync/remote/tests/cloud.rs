//! 云盘传输（Phase 2）域测试：`CloudDriveRemote`（指令流/快照/游标）、
//! `CloudGroupKeyStore`（登记/信封）、`open_cloud` 双设备收敛。
//!
//! 全部走临时目录（无真实云盘、无网络）——传输语义（水位/合并/原子写）
//! 是纯本地文件逻辑，云盘代理只做跨设备分发，不在本测试面。

use crate::sync::engine::SyncRemote;
use crate::sync::oplog::{ItemKind, OpType, SyncOp, SyncPayload};
use crate::sync::remote::group_key_store::GroupKeyStore;
use crate::sync::remote::{CloudDriveRemote, CloudGroupKeyStore};
use uuid::Uuid;

fn op(device: Uuid, lamport: u64, item: Uuid) -> SyncOp {
    SyncOp {
        op_id: Uuid::new_v4(),
        item_id: item,
        kind: ItemKind::Credential,
        op: OpType::Put,
        lamport,
        device_id: device,
        timestamp: Some(chrono::Utc::now()),
        payload: Some(SyncPayload {
            ciphertext: vec![lamport as u8],
            wrapped_item_key: vec![0x5a; 32],
        }),
    }
}

// ---- CloudDriveRemote：指令流 ----

#[tokio::test]
async fn push_pull_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), dev_b);

    let item = Uuid::new_v4();
    let pushed = op(dev_a, 1, item);
    let (accepted, duplicates) = remote_a
        .push_ops(std::slice::from_ref(&pushed))
        .await
        .unwrap();
    assert_eq!((accepted, duplicates), (1, 0));

    let (ops, cursor) = remote_b.pull_ops(None, 200).await.unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].op_id, pushed.op_id);
    assert_eq!(ops[0].lamport, 1);
    assert!(cursor.is_some(), "非空页必须带游标，引擎才能推进水位");

    // 再 pull：无新增量 → 空页 + None（引擎「空页才停」）
    let (ops2, cursor2) = remote_b.pull_ops(cursor.as_deref(), 200).await.unwrap();
    assert!(ops2.is_empty());
    assert!(cursor2.is_none());
}

#[tokio::test]
async fn push_dedups_by_op_id() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), Uuid::new_v4());

    let item = Uuid::new_v4();
    let pushed = op(dev_a, 1, item);
    // 崩溃后重推同 op（引擎未 ack 前掉线）→ 第二次是重复
    let (a1, d1) = remote_a
        .push_ops(std::slice::from_ref(&pushed))
        .await
        .unwrap();
    let (a2, d2) = remote_a
        .push_ops(std::slice::from_ref(&pushed))
        .await
        .unwrap();
    assert_eq!((a1, d1), (1, 0));
    assert_eq!((a2, d2), (0, 1));

    // 分片只有一行（op_id 幂等）
    let (ops, _) = remote_b.pull_ops(None, 200).await.unwrap();
    assert_eq!(ops.len(), 1);
}

#[tokio::test]
async fn pull_cursor_resume_never_skips_late_lower_lamport() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), dev_b);

    // A 先推两条（lamport 7, 9）。B 拉到水位，游标记录每分片行数。
    let item = Uuid::new_v4();
    let a7 = op(dev_a, 7, item);
    let a9 = op(dev_a, 9, item);
    remote_a.push_ops(&[a7.clone(), a9.clone()]).await.unwrap();
    let (first, cursor) = remote_b.pull_ops(None, 200).await.unwrap();
    assert_eq!(first.len(), 2);

    // B 离线期间：B 自身写 lamport 3（低于 A 的 7、9）——晚到但更小。
    // rank 游标会把它当「已消费」跳过（插到已读 rank 前）；行数水位必须
    // 读到它（关键收敛性：低 lamport 晚到 op 永不丢）。
    let b3 = op(dev_b, 3, item);
    remote_b.push_ops(std::slice::from_ref(&b3)).await.unwrap();

    let (later, _) = remote_b.pull_ops(cursor.as_deref(), 200).await.unwrap();
    assert!(
        later.iter().any(|o| o.op_id == b3.op_id),
        "低 lamport 晚到 op 不得被游标跳过（rank 游标的已知收敛洞）"
    );
    // 合并按 (lamport, device_id) 全序：b3(3) 在 a7(7)、a9(9) 前
    assert_eq!(later[0].lamport, 3);
    assert_eq!(later[0].device_id, dev_b);
}

#[tokio::test]
async fn dual_device_merge_is_deterministic_and_totally_ordered() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), dev_b);
    let observer = CloudDriveRemote::new(dir.path(), Uuid::new_v4());

    let item = Uuid::new_v4();
    let a1 = op(dev_a, 1, item);
    let a5 = op(dev_a, 5, item);
    let b3 = op(dev_b, 3, item);
    let b4 = op(dev_b, 4, item);
    remote_a.push_ops(&[a1.clone(), a5.clone()]).await.unwrap();
    remote_b.push_ops(&[b3.clone(), b4.clone()]).await.unwrap();

    // 任意观察者（不同 device_id）对同一分片集算出同一全序
    let (ops, _) = observer.pull_ops(None, 200).await.unwrap();
    assert_eq!(ops.len(), 4);
    let keys: Vec<(u64, Uuid)> = ops.iter().map(|o| (o.lamport, o.device_id)).collect();
    assert_eq!(
        keys,
        vec![(1, dev_a), (3, dev_b), (4, dev_b), (5, dev_a),],
        "虚拟全序 = (lamport, device_id)，两端独立计算一致"
    );
    assert_eq!(
        observer.head_seq().await.unwrap(),
        4,
        "组版本号 = 全部分片行数（op_id 跨分片全局唯一）"
    );
}

// ---- CloudDriveRemote：库级快照 ----

#[tokio::test]
async fn snapshot_immutable_and_max_seq_wins() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), dev_b);

    // 并发多设备各写一份（不同 (seq, device) 文件名，无 CAS 冲突）
    remote_a
        .put_library_snapshot(5, &dev_a.to_string(), b"snap-5-a")
        .await
        .unwrap();
    remote_b
        .put_library_snapshot(3, &dev_b.to_string(), b"snap-3-b")
        .await
        .unwrap();

    // max-seq 是确定收敛点
    let (seq, bytes) = remote_b.get_library_snapshot().await.unwrap().unwrap();
    assert_eq!(seq, 5);
    assert_eq!(bytes, b"snap-5-a");

    // 同 (seq, device) 重传 = 不可变：不覆盖（内容寻址，幂等）
    let pruned = remote_a
        .put_library_snapshot(5, &dev_a.to_string(), b"different")
        .await
        .unwrap();
    assert_eq!(pruned, 0, "云盘不物理压缩（分片 append-only）");
    let (seq2, bytes2) = remote_b.get_library_snapshot().await.unwrap().unwrap();
    assert_eq!(seq2, 5);
    assert_eq!(bytes2, b"snap-5-a", "快照文件一旦写入不改（不可变）");

    // 更高 seq 覆盖收敛点
    remote_a
        .put_library_snapshot(8, &dev_a.to_string(), b"snap-8-a")
        .await
        .unwrap();
    let (seq3, bytes3) = remote_b.get_library_snapshot().await.unwrap().unwrap();
    assert_eq!(seq3, 8);
    assert_eq!(bytes3, b"snap-8-a");
}

#[tokio::test]
async fn no_snapshot_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let remote = CloudDriveRemote::new(dir.path(), Uuid::new_v4());
    assert!(remote.get_library_snapshot().await.unwrap().is_none());
}

// ---- CloudGroupKeyStore：登记 + 信封 ----

#[tokio::test]
async fn cloud_group_key_store_round_trip_and_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let store = CloudGroupKeyStore::new(dir.path());

    let identity = crate::sync::device::DeviceIdentity::generate("alpha")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    store.register_device(&identity).await.unwrap();

    // 空组自举：生成组密钥并密封给自己
    assert!(store
        .bootstrap_group_if_empty(identity.device_id, identity.key_pair.public_bytes())
        .await
        .unwrap());
    // 已有信封 → 不再自举
    assert!(!store
        .bootstrap_group_if_empty(identity.device_id, identity.key_pair.public_bytes())
        .await
        .unwrap());

    let keys = store.group_keys().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, identity.device_id);

    // 拆出组密钥可解（自举密封给自己）
    let group_bytes =
        crate::sync::envelope::open_group_key(&keys[0].envelope, identity.key_pair.secret_bytes())
            .unwrap();
    assert_eq!(group_bytes.len(), 32);

    // 第二台设备：登记 + 授权（第一台拆组密钥重封给 B）
    let identity_b = crate::sync::device::DeviceIdentity::generate("beta")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    store.register_device(&identity_b).await.unwrap();
    let env_b =
        crate::sync::envelope::seal_group_key(&group_bytes, identity_b.key_pair.public_bytes())
            .unwrap();
    store
        .put_group_key(identity_b.device_id, &env_b)
        .await
        .unwrap();

    let keys = store.group_keys().await.unwrap();
    assert_eq!(keys.len(), 2);
    let env_b_entry = keys
        .iter()
        .find(|k| k.device_id == identity_b.device_id)
        .unwrap();
    let b_group = crate::sync::envelope::open_group_key(
        &env_b_entry.envelope,
        identity_b.key_pair.secret_bytes(),
    )
    .unwrap();
    assert_eq!(b_group, group_bytes, "两端拆出同一组密钥");
}

#[tokio::test]
async fn put_group_key_fails_for_unregistered_device() {
    let dir = tempfile::tempdir().unwrap();
    let store = CloudGroupKeyStore::new(dir.path());
    let ghost = Uuid::new_v4();
    assert!(store.put_group_key(ghost, &[0u8; 80]).await.is_err());
}

// ---- open_cloud：双设备收敛（镜像 HTTP 收敛测试，文件版）----

#[tokio::test]
async fn open_cloud_two_devices_converge() {
    use crate::crypto::encryption::EncryptionService;
    use crate::crypto::key_hierarchy::KeyHierarchy;
    use crate::models::credential::{
        Credential, CredentialType, PasswordCredentialData, SecurityLevel,
    };
    use crate::models::identity::{Identity, IdentityType};
    use crate::storage::repository::IdentityRepository;
    use crate::storage::sync_repository::SyncRepository;
    use crate::storage::Repository;
    use crate::storage::{CredentialRepository, Database};
    use crate::sync::device::DeviceIdentity;
    use crate::sync::keys::GroupKey;

    let dir = tempfile::tempdir().unwrap();
    let store = CloudGroupKeyStore::new(dir.path());

    // 设备身份 + 共用的组密钥（跨设备配对 E2EE 产物，测试直接构造）
    let identity_a = DeviceIdentity::generate("alpha")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    let identity_b = DeviceIdentity::generate("beta")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    let group = GroupKey::generate().unwrap();
    store.register_device(&identity_a).await.unwrap();
    store.register_device(&identity_b).await.unwrap();
    store
        .put_group_key(
            identity_a.device_id,
            &crate::sync::envelope::seal_group_key(
                group.as_bytes(),
                identity_a.key_pair.public_bytes(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    store
        .put_group_key(
            identity_b.device_id,
            &crate::sync::envelope::seal_group_key(
                group.as_bytes(),
                identity_b.key_pair.public_bytes(),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // A：有库存量 + 主密码 → open_cloud → backfill → run_cycle（推上分片）
    let db_a = Database::in_memory().await.unwrap();
    db_a.migrate().await.unwrap();
    let identity_row_a = Identity::new("seed".to_string(), IdentityType::Personal);
    IdentityRepository::new(db_a.clone())
        .create(&identity_row_a)
        .await
        .unwrap();
    let master_a = EncryptionService::new(&EncryptionService::generate_key());
    let item_key = EncryptionService::generate_key();
    let wrapped_a = master_a.encrypt(&item_key).unwrap();
    let data_a = crate::models::credential::CredentialData::Password(PasswordCredentialData {
        password: "s1".to_string(),
        email: None,
        security_questions: vec![],
    });
    let ciphertext_a = KeyHierarchy::new(&master_a)
        .encrypt_with_item_key(&item_key, &data_a.to_bytes().unwrap())
        .unwrap();
    let cred_a = Credential::new(
        identity_row_a.id,
        "alpha-cred".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        ciphertext_a,
        Some(wrapped_a),
    );
    CredentialRepository::new(db_a.clone())
        .create(&cred_a)
        .await
        .unwrap();

    let session_a =
        crate::sync::runtime::SyncSession::open_cloud(&db_a, &identity_a, dir.path(), no_travel())
            .await
            .unwrap();
    session_a.backfill_existing(&master_a).await.unwrap();
    let report_a = session_a.run_cycle(&master_a).await.unwrap();
    assert_eq!(report_a.pushed, 1, "A 的存量 op 推上分片");

    // B：空库 + 同组密钥 → open_cloud → run_cycle（从分片拉回并物化）
    let db_b = Database::in_memory().await.unwrap();
    db_b.migrate().await.unwrap();
    // 身份行是设备本地可预置事实（配对流程已建）；走同步链的只有凭据 op
    IdentityRepository::new(db_b.clone())
        .create(&Identity {
            id: identity_row_a.id,
            ..Identity::new("seed".to_string(), IdentityType::Personal)
        })
        .await
        .unwrap();
    let master_b = EncryptionService::new(&EncryptionService::generate_key());
    let session_b =
        crate::sync::runtime::SyncSession::open_cloud(&db_b, &identity_b, dir.path(), no_travel())
            .await
            .unwrap();
    let report_b = session_b.run_cycle(&master_b).await.unwrap();
    assert_eq!(report_b.pulled, 1, "B 从云盘分片拉到 A 的 op");
    assert_eq!(report_b.materialized, 1, "B 主库物化出条目");

    let names: Vec<String> = CredentialRepository::new(db_b.clone())
        .list_all()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["alpha-cred".to_string()]);

    // B 的水位推到分片行数（不再重拉）
    let watermark = SyncRepository::new(db_b.clone())
        .local_watermark()
        .await
        .unwrap();
    assert_eq!(
        watermark, 1,
        "云盘游标 sum 槽 = 已消费行数，local_watermark 可读"
    );
}

fn no_travel() -> Box<dyn Fn() -> bool + Send + Sync> {
    Box::new(|| false)
}
