//! oplog GC 域测试（谓词矩阵注释与 retention_days/pending_after_resolve
//! 域内 helper 随组）。

use super::*;

// ---- oplog GC（E2EE_SYNC_DESIGN §11 开放问题 3 的客户端半边）----
// 谓词矩阵：pending 保护 / acked 旧版本可清 / 真冲突副本保护 /
// 主位 put 永不清理 / tombstone 保留窗口（timestamp None 保守不清）。

fn retention_days(days: i64) -> chrono::Duration {
    chrono::Duration::try_days(days).unwrap()
}

#[tokio::test]
async fn gc_prunes_consumed_versions_and_keeps_protection_set() {
    let (db, identity, _master) = seeded_db().await;
    let group = GroupKey::generate().unwrap();
    let sync_repo = SyncRepository::new(db.clone());

    // 已收敛条目：v1 旧版本（acked）+ v2 主位（acked）→ 只清 v1
    let lived = Uuid::new_v4();
    let v1 = conflict_put_op(
        lived,
        Uuid::new_v4(),
        1,
        &snapshot("lived-v1", identity.id),
        &group,
    );
    let v2 = conflict_put_op(
        lived,
        Uuid::new_v4(),
        2,
        &snapshot("lived-v2", identity.id),
        &group,
    );
    sync_repo.record_remote_op(&v1).await.unwrap();
    sync_repo.record_remote_op(&v2).await.unwrap();

    // 真冲突条目：同 lamport 异设备 → 副本未裁决，双双保护
    let conflicted = Uuid::new_v4();
    let (p, c) = seeded_conflict(conflicted, &group, identity.id);
    sync_repo.record_remote_op(&p).await.unwrap();
    sync_repo.record_remote_op(&c).await.unwrap();

    // 未 ack 条目：本机主位 pending 保护；同 item 的 acked 旧版本可清
    let pending_item = Uuid::new_v4();
    let stale = conflict_put_op(
        pending_item,
        Uuid::new_v4(),
        1,
        &snapshot("pend-v1", identity.id),
        &group,
    );
    let fresh = conflict_put_op(
        pending_item,
        Uuid::new_v4(),
        2,
        &snapshot("pend-v2", identity.id),
        &group,
    );
    sync_repo.record_remote_op(&stale).await.unwrap();
    sync_repo.append_local_op(&fresh).await.unwrap();

    let primary_of = |ops: &[SyncOp]| item_view(ops.to_vec()).primary.unwrap().op_id;
    let before_lived = primary_of(&sync_repo.item_ops(lived).await.unwrap());
    let before_conflict = item_view(sync_repo.item_ops(conflicted).await.unwrap());
    let before_pending = primary_of(&sync_repo.item_ops(pending_item).await.unwrap());

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let report = session
        .gc_oplog(default_tombstone_retention())
        .await
        .unwrap();
    assert_eq!(report.removed_ops, 2);
    assert!(!sync_repo.has_op(v1.op_id).await.unwrap());
    assert!(!sync_repo.has_op(stale.op_id).await.unwrap());

    // 保护集全数存活
    for kept in [v2.op_id, p.op_id, c.op_id, fresh.op_id] {
        assert!(sync_repo.has_op(kept).await.unwrap());
    }

    // GC 前后主位/副本视图逐字节不变（被清的都是推导上不可见的版本）
    let after_lived = primary_of(&sync_repo.item_ops(lived).await.unwrap());
    assert_eq!(after_lived, before_lived);
    let after_conflict = item_view(sync_repo.item_ops(conflicted).await.unwrap());
    assert_eq!(
        after_conflict.primary.as_ref().map(|o| o.op_id),
        before_conflict.primary.as_ref().map(|o| o.op_id)
    );
    assert_eq!(after_conflict.conflicts.len(), 1);
    let after_pending = primary_of(&sync_repo.item_ops(pending_item).await.unwrap());
    assert_eq!(after_pending, before_pending);
}

#[tokio::test]
async fn gc_tombstone_window_and_missing_timestamp() {
    let (db, _identity, _master) = seeded_db().await;
    let group = GroupKey::generate().unwrap();
    let sync_repo = SyncRepository::new(db.clone());
    let now = TestUtc::now();

    // 过窗 acked 墓碑 → 清；窗内 / 无 timestamp（保守）→ 不清；
    // 过窗但仍在 push 队列 → pending 保护优先，不清
    let mut expired = conflict_delete_op(Uuid::new_v4(), Uuid::new_v4(), 5);
    expired.timestamp = Some(now - retention_days(31));
    let mut in_window = conflict_delete_op(Uuid::new_v4(), Uuid::new_v4(), 5);
    in_window.timestamp = Some(now);
    let mut no_timestamp = conflict_delete_op(Uuid::new_v4(), Uuid::new_v4(), 5);
    no_timestamp.timestamp = None;
    let mut expired_pending = conflict_delete_op(Uuid::new_v4(), Uuid::new_v4(), 5);
    expired_pending.timestamp = Some(now - retention_days(31));

    for op in [&expired, &in_window, &no_timestamp] {
        sync_repo.record_remote_op(op).await.unwrap();
    }
    sync_repo.append_local_op(&expired_pending).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let report = session.gc_oplog(retention_days(30)).await.unwrap();
    assert_eq!(report.removed_ops, 1);
    assert!(!sync_repo.has_op(expired.op_id).await.unwrap());
    for kept in [in_window.op_id, no_timestamp.op_id, expired_pending.op_id] {
        assert!(sync_repo.has_op(kept).await.unwrap());
    }
}

#[tokio::test]
async fn gc_after_resolve_prunes_losing_copies_once_acked() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, copy) = seeded_conflict(item, &group, identity.id);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let local_device = Uuid::new_v4();
    let (session, _) = session_for(&db, local_device, group.clone());
    session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap();

    // 裁决采纳即以更大 lamport 重新入账：败方在采纳那一刻就落出副本集
    // （可清），与采纳 op 是否已推出去无关；pending 保护的只有采纳
    // op 自身。清理后重放安全：败方重拉回来 lamport 落后，不影响视图。
    let report = session
        .gc_oplog(default_tombstone_retention())
        .await
        .unwrap();
    assert_eq!(report.removed_ops, 2);
    let rest = sync_repo.item_ops(item).await.unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].op_id, pending_after_resolve(&sync_repo, item).await);

    // ack 后再跑一轮：队列空，无可清
    let pending = sync_repo.pending_ops(100).await.unwrap();
    assert_eq!(pending.len(), 1);
    sync_repo.mark_acked(&[pending[0].op_id]).await.unwrap();
    let report = session
        .gc_oplog(default_tombstone_retention())
        .await
        .unwrap();
    assert_eq!(report.removed_ops, 0);

    // 视图收敛到被采纳副本，冲突区清空
    let view = item_view(sync_repo.item_ops(item).await.unwrap());
    let new_primary = view.primary.unwrap();
    assert_eq!(new_primary.op_id, pending[0].op_id);
    assert_eq!(new_primary.device_id, local_device);
    assert!(view.conflicts.is_empty());
}

/// 裁决采纳后 push 队列里那条采纳 op 的 op_id（断言辅助）。
async fn pending_after_resolve(sync_repo: &SyncRepository, item: Uuid) -> Uuid {
    let pending = sync_repo.pending_ops(100).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].item_id, item);
    pending[0].op_id
}
