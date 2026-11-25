//! oplog GC domain tests (the predicate matrix comment and the
//! retention_days/pending_after_resolve in-domain helpers live with this
//! group).

use super::*;

// ---- oplog GC (the client half of E2EE_SYNC_DESIGN section 11 open
// question 3) ----
// Predicate matrix: pending is protected / acked old versions are prunable /
// genuine-conflict copies are protected / master-position puts are never
// pruned / tombstone retention window (timestamp None is conservatively kept).

fn retention_days(days: i64) -> chrono::Duration {
    chrono::Duration::try_days(days).unwrap()
}

#[tokio::test]
async fn gc_prunes_consumed_versions_and_keeps_protection_set() {
    let (db, identity, _master) = seeded_db().await;
    let group = GroupKey::generate().unwrap();
    let sync_repo = SyncRepository::new(db.clone());

    // Converged entry: old v1 (acked) + v2 master position (acked) -> only
    // v1 is pruned
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

    // Genuine conflict entry: same lamport, different devices -> the copy is
    // unresolved, both are protected
    let conflicted = Uuid::new_v4();
    let (p, c) = seeded_conflict(conflicted, &group, identity.id);
    sync_repo.record_remote_op(&p).await.unwrap();
    sync_repo.record_remote_op(&c).await.unwrap();

    // Unacked entry: the local master position is pending and protected; the
    // acked old version of the same item is prunable
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

    // Every entry in the protection set survives
    for kept in [v2.op_id, p.op_id, c.op_id, fresh.op_id] {
        assert!(sync_repo.has_op(kept).await.unwrap());
    }

    // The primary/copy view is byte-identical before and after GC (what gets
    // pruned is by derivation not visible)
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

    // Out-of-window acked tombstone -> pruned; in-window / no timestamp
    // (conservative) -> kept; out-of-window but still in the push queue ->
    // pending protection wins, kept
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

    // Adoption re-logs with a larger lamport: the loser drops out of the copy
    // set (becomes prunable) the moment it is adopted, regardless of whether
    // the adopt op has been pushed yet; only the adopt op itself is pending
    // and protected. Replay after pruning is safe: if the loser is pulled
    // back its lamport lags behind and the view is unaffected.
    let report = session
        .gc_oplog(default_tombstone_retention())
        .await
        .unwrap();
    assert_eq!(report.removed_ops, 2);
    let rest = sync_repo.item_ops(item).await.unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].op_id, pending_after_resolve(&sync_repo, item).await);

    // Run another round after ack: the queue is empty, nothing to prune
    let pending = sync_repo.pending_ops(100).await.unwrap();
    assert_eq!(pending.len(), 1);
    sync_repo.mark_acked(&[pending[0].op_id]).await.unwrap();
    let report = session
        .gc_oplog(default_tombstone_retention())
        .await
        .unwrap();
    assert_eq!(report.removed_ops, 0);

    // The view converges on the adopted copy and the conflict area is empty
    let view = item_view(sync_repo.item_ops(item).await.unwrap());
    let new_primary = view.primary.unwrap();
    assert_eq!(new_primary.op_id, pending[0].op_id);
    assert_eq!(new_primary.device_id, local_device);
    assert!(view.conflicts.is_empty());
}

/// op_id of the adopt op in the push queue after a resolution
/// (an assertion helper).
async fn pending_after_resolve(sync_repo: &SyncRepository, item: Uuid) -> Uuid {
    let pending = sync_repo.pending_ops(100).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].item_id, item);
    pending[0].op_id
}
