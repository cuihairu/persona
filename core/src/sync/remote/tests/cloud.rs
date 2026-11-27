//! Domain tests for the cloud-drive transport (Phase 2): `CloudDriveRemote` (instruction stream / snapshot /
//! cursor), `CloudGroupKeyStore` (registration / envelopes), and two-device convergence via `open_cloud`.
//!
//! Everything runs against temporary directories (no real cloud drive, no network) — the transport
//! semantics (watermarks / merging / atomic writes) are pure local file logic, and the cloud agent only does
//! cross-device distribution, which is outside this test surface.

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

// ---- CloudDriveRemote: instruction stream ----

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

    // Pull again: no new delta -> an empty page + None (the engine's "stop only on an empty page" rule)
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
    // Re-pushing the same op after a crash (dropped before the engine acked) -> the second push is a duplicate
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

    // The shard has only one line (op_id idempotency)
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

    // A pushes two ops first (lamport 7, 9). B pulls to a watermark; the cursor records the per-shard row counts.
    let item = Uuid::new_v4();
    let a7 = op(dev_a, 7, item);
    let a9 = op(dev_a, 9, item);
    remote_a.push_ops(&[a7.clone(), a9.clone()]).await.unwrap();
    let (first, cursor) = remote_b.pull_ops(None, 200).await.unwrap();
    assert_eq!(first.len(), 2);

    // While B is offline: B itself writes lamport 3 (lower than A's 7 and 9) — late-arriving but smaller.
    // A rank cursor would treat it as "already consumed" and skip it (it lands before a rank already read); the
    // row-count watermark must pick it up (key convergence property: a late op with a low lamport is never lost).
    let b3 = op(dev_b, 3, item);
    remote_b.push_ops(std::slice::from_ref(&b3)).await.unwrap();

    let (later, _) = remote_b.pull_ops(cursor.as_deref(), 200).await.unwrap();
    assert!(
        later.iter().any(|o| o.op_id == b3.op_id),
        "低 lamport 晚到 op 不得被游标跳过（rank 游标的已知收敛洞）"
    );
    // Merging follows the (lamport, device_id) total order: b3(3) comes before a7(7) and a9(9)
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

    // Any observer (a different device_id) derives the same total order from the same shard set
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

// ---- CloudDriveRemote: vault-level snapshots ----

#[tokio::test]
async fn snapshot_immutable_and_max_seq_wins() {
    let dir = tempfile::tempdir().unwrap();
    let dev_a = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let remote_a = CloudDriveRemote::new(dir.path(), dev_a);
    let remote_b = CloudDriveRemote::new(dir.path(), dev_b);

    // Several devices writing concurrently each produce one file (distinct (seq, device) filenames, no CAS conflict)
    remote_a
        .put_library_snapshot(5, &dev_a.to_string(), b"snap-5-a")
        .await
        .unwrap();
    remote_b
        .put_library_snapshot(3, &dev_b.to_string(), b"snap-3-b")
        .await
        .unwrap();

    // max-seq is the deterministic convergence point
    let (seq, bytes) = remote_b.get_library_snapshot().await.unwrap().unwrap();
    assert_eq!(seq, 5);
    assert_eq!(bytes, b"snap-5-a");

    // Re-sending the same (seq, device) = immutable: no overwrite (content-addressed, idempotent)
    let pruned = remote_a
        .put_library_snapshot(5, &dev_a.to_string(), b"different")
        .await
        .unwrap();
    assert_eq!(pruned, 0, "云盘不物理压缩（分片 append-only）");
    let (seq2, bytes2) = remote_b.get_library_snapshot().await.unwrap().unwrap();
    assert_eq!(seq2, 5);
    assert_eq!(bytes2, b"snap-5-a", "快照文件一旦写入不改（不可变）");

    // A higher seq takes over the convergence point
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

// ---- CloudGroupKeyStore: registration + envelopes ----

#[tokio::test]
async fn cloud_group_key_store_round_trip_and_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let store = CloudGroupKeyStore::new(dir.path());

    let identity = crate::sync::device::DeviceIdentity::generate("alpha")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    store.register_device(&identity).await.unwrap();

    // Bootstrapping an empty group: generate the group key and seal it to itself
    assert!(store
        .bootstrap_group_if_empty(identity.device_id, identity.key_pair.public_bytes())
        .await
        .unwrap());
    // Envelopes already exist -> no bootstrap
    assert!(!store
        .bootstrap_group_if_empty(identity.device_id, identity.key_pair.public_bytes())
        .await
        .unwrap());

    let keys = store.group_keys().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].device_id, identity.device_id);

    // Unwrapping the group key from it works (bootstrap sealed it to itself)
    let group_bytes =
        crate::sync::envelope::open_group_key(&keys[0].envelope, identity.key_pair.secret_bytes())
            .unwrap();
    assert_eq!(group_bytes.len(), 32);

    // Second device: registration + authorization (the first device unwraps the group key and reseals it for B)
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

// ---- Device management plane (consumed by host join/list/authorize/revoke/leave) ----

#[tokio::test]
async fn list_remove_and_remark_devices() {
    let dir = tempfile::tempdir().unwrap();
    let store = CloudGroupKeyStore::new(dir.path());

    let identity = crate::sync::device::DeviceIdentity::generate("alpha")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    let identity_b = crate::sync::device::DeviceIdentity::generate("beta")
        .unwrap()
        .with_device_id(Uuid::new_v4());
    store.register_device(&identity).await.unwrap();
    store.register_device(&identity_b).await.unwrap();

    // The listing carries the public key (needed when authorizing a target) and the fields needed to mark the local device
    let devices = store.list_devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    let alpha = devices
        .iter()
        .find(|d| d.device_id == identity.device_id.to_string())
        .unwrap();
    assert_eq!(alpha.device_name, "alpha");
    assert_eq!(alpha.public_key, {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(identity.key_pair.public_bytes())
    });

    // Writing a remark: trimmed normalization + persisted in the registry (readable back after reopening the store)
    let stored = store
        .set_device_remark(identity.device_id, "  laptop  ")
        .await
        .unwrap();
    assert_eq!(stored, "laptop");
    let reopened = CloudGroupKeyStore::new(dir.path());
    assert_eq!(
        reopened
            .list_devices()
            .await
            .unwrap()
            .iter()
            .find(|d| d.device_id == identity.device_id.to_string())
            .unwrap()
            .remark,
        "laptop"
    );
    // Not in the registry -> NotFound (fail-closed)
    assert!(reopened
        .set_device_remark(Uuid::new_v4(), "x")
        .await
        .is_err());

    // Removing a device: dropped from the registry + envelope files cleaned up + idempotent (a second removal returns false)
    let group_bytes = [7u8; 32];
    let env_b =
        crate::sync::envelope::seal_group_key(&group_bytes, identity_b.key_pair.public_bytes())
            .unwrap();
    store
        .put_group_key(identity_b.device_id, &env_b)
        .await
        .unwrap();
    assert!(store.remove_device(identity_b.device_id).await.unwrap());
    assert!(
        !store.remove_device(identity_b.device_id).await.unwrap(),
        "再删幂等 false"
    );
    let devices = store.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1, "只剩 alpha");
    assert!(
        !dir.path()
            .join(format!("env-{}.bin", identity_b.device_id))
            .exists(),
        "信封文件一并清理"
    );
    // group_keys trusts the registry: the removed device is not read even if it left an orphan envelope behind
    assert!(store
        .group_keys()
        .await
        .unwrap()
        .iter()
        .all(|k| k.device_id != identity_b.device_id));
}

// ---- open_cloud: two-device convergence (a file-based mirror of the HTTP convergence tests) ----

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

    // Device identities + a shared group key (an E2EE pairing artifact across devices, constructed directly in tests)
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

    // A: has an existing vault + primary key -> open_cloud -> backfill -> run_cycle (pushed onto the shard)
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

    // B: empty vault + the same group key -> open_cloud -> run_cycle (pulled back from the shard and materialized)
    let db_b = Database::in_memory().await.unwrap();
    db_b.migrate().await.unwrap();
    // The identity row is a pre-seedable device-local fact (already created by the pairing flow); only the credential op travels the sync chain
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

    // B's watermark has advanced to the shard row count (no re-pulling)
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

// ---- CloudDriveRemote: shard-rewrite GC (§9.3) ----

/// Registers `device_id` in the cloud registry so GC treats it as a member whose
/// committed watermark gates compaction.
async fn register(dir: &std::path::Path, device_id: Uuid) {
    let store = CloudGroupKeyStore::new(dir);
    let identity = crate::sync::device::DeviceIdentity::generate(device_id.to_string())
        .unwrap()
        .with_device_id(device_id);
    store.register_device(&identity).await.unwrap();
}

/// Writes a device's committed watermark file directly (simulating what
/// `pull_ops` publishes once the engine has persisted the cursor).
async fn commit_watermark(dir: &std::path::Path, device_id: Uuid, counts: &[(Uuid, u64)]) {
    let wm: std::collections::HashMap<Uuid, u64> = counts.iter().copied().collect();
    let path = dir.join(format!("watermark-{device_id}.json"));
    tokio::fs::write(&path, serde_json::json!({
        "device_id": device_id,
        "watermarks": wm.iter().map(|(k, v)| (k.to_string(), *v)).collect::<std::collections::HashMap<_, _>>(),
    }).to_string())
    .await
    .unwrap();
}

async fn shard_len(dir: &std::path::Path, device_id: Uuid) -> usize {
    let path = dir.join(format!("dev-{device_id}.jsonl"));
    let text = tokio::fs::read_to_string(path).await.unwrap_or_default();
    text.lines().filter(|l| !l.trim().is_empty()).count()
}

#[tokio::test]
async fn gc_is_blocked_until_every_device_commits() {
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    // A pushes 5 ops to its own shard.
    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[
        op(a, 1, item),
        op(a, 2, item),
        op(a, 3, item),
        op(a, 4, item),
        op(a, 5, item),
    ])
    .await
    .unwrap();

    // Only A commits a watermark; B never pulled (no file) -> GC must not drop anything.
    commit_watermark(dir.path(), a, &[(a, 5)]).await;
    let pruned = ra
        .put_library_snapshot(5, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(
        pruned, 0,
        "an un-pulled registered device blocks compaction"
    );
    assert_eq!(shard_len(dir.path(), a).await, 5, "shard untouched");
}

#[tokio::test]
async fn gc_drops_only_the_common_consumed_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[
        op(a, 1, item),
        op(a, 2, item),
        op(a, 3, item),
        op(a, 4, item),
        op(a, 5, item),
    ])
    .await
    .unwrap();

    // Both devices have durably consumed the first 3 rows of A's shard.
    commit_watermark(dir.path(), a, &[(a, 3)]).await;
    commit_watermark(dir.path(), b, &[(a, 3)]).await;

    let pruned = ra
        .put_library_snapshot(5, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(pruned, 3, "only the common consumed prefix is dropped");
    assert_eq!(
        shard_len(dir.path(), a).await,
        2,
        "the unconsumed suffix stays"
    );

    // The surviving rows are the last two (lamport 4, 5), and both can be re-read.
    let (ops, _cursor) = ra.pull_ops(None, 200).await.unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(
        ops.iter().map(|o| o.lamport).collect::<Vec<_>>(),
        vec![4, 5]
    );
}

#[tokio::test]
async fn gc_blocks_beyond_a_lagging_device() {
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[op(a, 1, item), op(a, 2, item), op(a, 3, item)])
        .await
        .unwrap();

    // A consumed all 3, but B only consumed 1 (B is behind, maybe offline mid-sync).
    commit_watermark(dir.path(), a, &[(a, 3)]).await;
    commit_watermark(dir.path(), b, &[(a, 1)]).await;

    let pruned = ra
        .put_library_snapshot(3, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(pruned, 1, "boundary is the min across devices");
    assert_eq!(shard_len(dir.path(), a).await, 2, "rows 2-3 remain for B");

    // B pulls from its committed position (1) and still gets rows 2 and 3.
    let cursor = crate::sync::cursor::encode_cursor(4, &format!("{{\"{a}\":{n}}}", n = 1));
    let (ops, _) = CloudDriveRemote::new(dir.path(), b)
        .pull_ops(Some(&cursor), 200)
        .await
        .unwrap();
    assert_eq!(
        ops.len(),
        2,
        "the lagging device never loses unconsumed rows"
    );
}

#[tokio::test]
async fn gc_never_loses_late_lower_lamport_ops() {
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let rb = CloudDriveRemote::new(dir.path(), b);
    let item = Uuid::new_v4();

    // A pushes 4 ops; B consumes the first 2 then goes offline.
    ra.push_ops(&[
        op(a, 9, item),
        op(a, 8, item),
        op(a, 7, item),
        op(a, 6, item),
    ])
    .await
    .unwrap();
    commit_watermark(dir.path(), b, &[(a, 2)]).await;
    // A itself has only consumed 2 as well (it does not pull its own tail yet).
    commit_watermark(dir.path(), a, &[(a, 2)]).await;

    // While both are at 2, B writes a late op with a lower lamport that lands
    // *before* the consumed rank — the exact op a rank cursor would skip.
    rb.push_ops(&[op(b, 1, item)]).await.unwrap();

    // GC runs: A's shard boundary is min(2,2)=2 -> drop the first 2 rows of A's shard.
    let pruned = ra
        .put_library_snapshot(6, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(pruned, 2);
    assert_eq!(shard_len(dir.path(), a).await, 2, "lamport 7,8 survive");

    // B (committed 2) pulls and must still see the late low-lamport op from B's
    // own shard, plus A's unconsumed rows — nothing was lost.
    let cursor = crate::sync::cursor::encode_cursor(
        4,
        &format!("{{\"{a}\":{ca},\"{b}\":{cb}}}", ca = 2, cb = 0),
    );
    let (ops, _) = rb.pull_ops(Some(&cursor), 200).await.unwrap();
    assert!(
        ops.iter().any(|o| o.device_id == b && o.lamport == 1),
        "late low-lamport op is never dropped by gc"
    );
}

#[tokio::test]
async fn gc_re_read_after_compaction_dedups() {
    // After GC drops the consumed prefix, a device that already landed those ops
    // re-reads them (its committed watermark is below the boundary) and must
    // dedup by op_id rather than produce duplicates.
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[op(a, 1, item), op(a, 2, item), op(a, 3, item)])
        .await
        .unwrap();
    commit_watermark(dir.path(), a, &[(a, 3)]).await;
    commit_watermark(dir.path(), b, &[(a, 3)]).await;

    let pruned = ra
        .put_library_snapshot(3, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(pruned, 3);
    assert_eq!(
        shard_len(dir.path(), a).await,
        0,
        "fully consumed shard empties"
    );

    // A re-pulls from its old committed position (0): nothing is left to read.
    let cursor = crate::sync::cursor::encode_cursor(3, &format!("{{\"{a}\":{n}}}", n = 0));
    let (ops, _) = ra.pull_ops(Some(&cursor), 200).await.unwrap();
    assert!(ops.is_empty(), "no rows left after full compaction");
}

#[tokio::test]
async fn gc_does_not_run_when_snapshot_already_exists() {
    // Re-sending the same (seq, device) snapshot is idempotent and must not
    // re-trigger GC (which would double-drop rows).
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[op(a, 1, item), op(a, 2, item), op(a, 3, item)])
        .await
        .unwrap();
    commit_watermark(dir.path(), a, &[(a, 3)]).await;
    commit_watermark(dir.path(), b, &[(a, 3)]).await;

    ra.put_library_snapshot(3, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(shard_len(dir.path(), a).await, 0);

    // A second upload of the same (seq, device) returns 0 and touches nothing.
    let pruned = ra
        .put_library_snapshot(3, &a.to_string(), b"other")
        .await
        .unwrap();
    assert_eq!(pruned, 0, "immutable snapshot never re-runs gc");
}

#[tokio::test]
async fn gc_ignores_removed_devices() {
    // A device that left the registry no longer gates compaction.
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    register(dir.path(), a).await;
    register(dir.path(), b).await;

    let ra = CloudDriveRemote::new(dir.path(), a);
    let item = Uuid::new_v4();
    ra.push_ops(&[op(a, 1, item), op(a, 2, item)])
        .await
        .unwrap();
    commit_watermark(dir.path(), a, &[(a, 2)]).await;
    // B committed 0 (never consumed); after removal it must not block GC.
    commit_watermark(dir.path(), b, &[(a, 0)]).await;

    assert!(CloudGroupKeyStore::new(dir.path())
        .remove_device(b)
        .await
        .unwrap());

    let pruned = ra
        .put_library_snapshot(2, &a.to_string(), b"snap")
        .await
        .unwrap();
    assert_eq!(pruned, 2, "a removed device no longer gates compaction");
}
