use super::*;

use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::models::{CredentialType, SecurityLevel};
use crate::sync::materialize::MaterializeOutcome;
use crate::sync::oplog::item_view;

#[tokio::test]
async fn remote_put_materializes_row_and_rewraps_key_under_local_master() {
    let (db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master_key = EncryptionService::generate_key();
    let master = EncryptionService::new(&master_key);

    let item_id = Uuid::new_v4();
    let snapshot = SyncItemSnapshot {
        identity_id,
        name: "远端邮箱".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::High,
        url: Some("https://remote.example".to_string()),
        username: Some("bob@remote.example".to_string()),
        notes: None,
        tags: vec!["synced".to_string()],
        metadata: Default::default(),
        is_favorite: true,
        is_active: true,
        data: password_data("remote-secret"),
    };
    let op = put_op(item_id, Uuid::new_v4(), 7, &snapshot, &group);
    Materializer::new(db.clone())
        .sync_repo
        .record_remote_op(&op)
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Written);

    let row = materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "远端邮箱");
    assert_eq!(row.username.as_deref(), Some("bob@remote.example"));
    assert_eq!(row.tags, vec!["synced".to_string()]);
    assert!(row.is_favorite);

    // item key 被本机主密钥重包，数据可正常解密。
    let hierarchy = KeyHierarchy::new(&master);
    let plaintext = hierarchy
        .decrypt_with_wrapped_key(row.wrapped_item_key.as_ref().unwrap(), &row.encrypted_data)
        .unwrap();
    let data = CredentialData::from_bytes(&plaintext).unwrap();
    assert_eq!(
        data.to_bytes().unwrap(),
        password_data("remote-secret").to_bytes().unwrap()
    );
}

#[tokio::test]
async fn tombstone_deletes_local_row() {
    let (db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let item_id = Uuid::new_v4();
    let snapshot = SyncItemSnapshot {
        identity_id,
        name: "待删".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data("x"),
    };
    let remote = Uuid::new_v4();
    Materializer::new(db.clone())
        .sync_repo
        .record_remote_op(&put_op(item_id, remote, 3, &snapshot, &group))
        .await
        .unwrap();
    Materializer::new(db.clone())
        .sync_repo
        .record_remote_op(&delete_op(item_id, remote, 4))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Tombstoned);
    assert!(materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn tombstone_with_audit_rows_detaches_references_instead_of_fk_error() {
    let (db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let item_id = Uuid::new_v4();
    let snapshot = SyncItemSnapshot {
        identity_id,
        name: "audited".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::High,
        url: None,
        username: Some("bob@remote.example".to_string()),
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data("x"),
    };
    let remote = Uuid::new_v4();
    materializer
        .sync_repo
        .record_remote_op(&put_op(item_id, remote, 3, &snapshot, &group))
        .await
        .unwrap();
    materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();

    // 审计行引用该凭据（audit_logs.credential_id FK 是 NO ACTION）
    sqlx::query(
        "INSERT INTO audit_logs (id, credential_id, action, resource_type, success, timestamp) \
         VALUES (?, ?, 'credential.viewed', 'credential', 1, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(item_id.to_string())
    .bind(Utc::now().to_rfc3339())
    .execute(db.pool())
    .await
    .unwrap();

    // 远端 tombstone：删行前必须先摘审计引用，否则 FK 787 拒删
    materializer
        .sync_repo
        .record_remote_op(&delete_op(item_id, remote, 4))
        .await
        .unwrap();
    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Tombstoned);
    assert!(materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
    // 审计行保留，引用已摘除
    let (detached,) =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_logs WHERE credential_id IS NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(detached, 1);
}

#[tokio::test]
async fn local_primary_is_skipped() {
    let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let local_device = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let snapshot = SyncItemSnapshot {
        identity_id,
        name: "本机写入".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data("local"),
    };
    // 主位是本机 op（device_id 相同）：主库是事实源，物化必须让路。
    materializer
        .sync_repo
        .record_remote_op(&put_op(item_id, local_device, 9, &snapshot, &group))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, local_device)
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::SkippedLocalPrimary);
    assert!(materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn pending_identity_defers_materialization() {
    let (db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let item_id = Uuid::new_v4();
    let snapshot = SyncItemSnapshot {
        identity_id: Uuid::new_v4(), // 未知身份：Identity 条目尚未同步
        name: "悬空凭据".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data("y"),
    };
    materializer
        .sync_repo
        .record_remote_op(&put_op(item_id, Uuid::new_v4(), 2, &snapshot, &group))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    match outcome {
        MaterializeOutcome::SkippedPendingIdentity { .. } => {}
        other => panic!("expected pending identity, got {other:?}"),
    }
    assert!(materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
    // op 留在 oplog，下轮可补齐
    assert_eq!(
        materializer
            .sync_repo
            .item_ops(item_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let _ = db; // keep db alive
}

#[tokio::test]
async fn true_conflict_materializes_winner_only() {
    let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let item_id = Uuid::new_v4();
    let mk = |name: &str| SyncItemSnapshot {
        identity_id,
        name: name.to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data(name),
    };
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    // 同 lamport 异设备 = 真冲突；主位 = device_id 大者（§7 降序）。
    let (winner_device, loser_device) = if device_a > device_b {
        (device_a, device_b)
    } else {
        (device_b, device_a)
    };
    let winner_name = if winner_device == device_a {
        "win-A"
    } else {
        "win-B"
    };
    materializer
        .sync_repo
        .record_remote_op(&put_op(item_id, device_a, 5, &mk("win-A"), &group))
        .await
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&put_op(item_id, device_b, 5, &mk("win-B"), &group))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Written);

    let row = materializer
        .credential_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, winner_name);
    // 败方留驻 oplog 冲突区，等阶段 3 裁决 UI。
    let view = item_view(materializer.sync_repo.item_ops(item_id).await.unwrap());
    assert_eq!(view.primary.unwrap().device_id, winner_device);
    assert_eq!(view.conflicts.len(), 1);
    assert_eq!(view.conflicts[0].device_id, loser_device);
    let _ = winner_device; // 已通过名称断言
}

#[tokio::test]
async fn materialize_all_reports_and_is_idempotent() {
    let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let local_device = Uuid::new_v4();

    let item_a = Uuid::new_v4();
    let item_b = Uuid::new_v4();
    let snap = |name: &str, iid: Uuid| SyncItemSnapshot {
        identity_id: iid,
        name: name.to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data(name),
    };
    materializer
        .sync_repo
        .record_remote_op(&put_op(
            item_a,
            Uuid::new_v4(),
            1,
            &snap("A", identity_id),
            &group,
        ))
        .await
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&delete_op(item_b, Uuid::new_v4(), 1))
        .await
        .unwrap();

    let report = materializer
        .materialize_all(&master, &group, local_device)
        .await
        .unwrap();
    assert_eq!(report.written, 1);
    assert_eq!(report.tombstoned, 1);
    assert!(report.pending_identity.is_empty());

    // 重跑幂等：同样的结果，不重复也不报错。
    let again = materializer
        .materialize_all(&master, &group, local_device)
        .await
        .unwrap();
    assert_eq!(again, report);
}

/// 协议防御面：oplog 无该 item（调用方枚举与查询竞态）与
/// 「Put 无 payload」的不变量违反都归 NoPrimary，且后者绝不写库。
#[tokio::test]
async fn no_primary_paths_never_touch_main_store() {
    let (_db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let other_device = Uuid::new_v4();

    // 1) oplog 里没有这个 item 的任何 op。
    let ghost = Uuid::new_v4();
    let outcome = materializer
        .materialize_item(&ghost, &master, &group, other_device)
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::NoPrimary);

    // 2) Put 不带 payload——fail-closed，不落半行。
    let item = Uuid::new_v4();
    let broken = SyncOp {
        op_id: Uuid::new_v4(),
        item_id: item,
        kind: ItemKind::Credential,
        op: OpType::Put,
        lamport: 1,
        device_id: other_device,
        timestamp: Some(Utc::now()),
        payload: None,
    };
    materializer
        .sync_repo
        .record_remote_op(&broken)
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::NoPrimary);
    assert!(materializer
        .credential_repo
        .find_by_id(&item)
        .await
        .unwrap()
        .is_none());
}

/// materialize_all 的报告面：pending 身份进报告留待下轮；单 item
/// 快照损坏（wrapped key 合法但密文坏）走 Err 臂只记 warn，不中断
/// 整批——两条 op 都留驻 oplog。
#[tokio::test]
async fn materialize_all_reports_pending_and_tolerates_corrupt_snapshot() {
    let (_db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    // pending：引用未知身份（Identity 尚未同步）
    let pending_item = Uuid::new_v4();
    let pending_identity = Uuid::new_v4();
    let pending_snapshot = SyncItemSnapshot {
        identity_id: pending_identity,
        name: "悬空凭据".to_string(),
        credential_type: CredentialType::Password,
        security_level: SecurityLevel::Medium,
        url: None,
        username: None,
        notes: None,
        tags: vec![],
        metadata: Default::default(),
        is_favorite: false,
        is_active: true,
        data: password_data("y"),
    };
    materializer
        .sync_repo
        .record_remote_op(&put_op(
            pending_item,
            Uuid::new_v4(),
            1,
            &pending_snapshot,
            &group,
        ))
        .await
        .unwrap();

    // 损坏：wrapped item key 合法（group 能拆），但密文解不出快照
    let corrupt_item = Uuid::new_v4();
    let broken = SyncOp {
        op_id: Uuid::new_v4(),
        item_id: corrupt_item,
        kind: ItemKind::Credential,
        op: OpType::Put,
        lamport: 1,
        device_id: Uuid::new_v4(),
        timestamp: Some(Utc::now()),
        payload: Some(SyncPayload {
            ciphertext: vec![7; 64],
            wrapped_item_key: wrap_item_key_with_group(&EncryptionService::generate_key(), &group),
        }),
    };
    materializer
        .sync_repo
        .record_remote_op(&broken)
        .await
        .unwrap();

    let report = materializer
        .materialize_all(&master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(report.written, 0);
    assert_eq!(
        report.pending_identity,
        vec![(pending_item, pending_identity)]
    );
    assert_eq!(
        materializer.sync_repo.item_ids().await.unwrap().len(),
        2,
        "两条 op 都留在 oplog，可重跑补齐"
    );
}
