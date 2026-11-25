//! Conflict list / resolution domain tests (assert_variant is the in-domain
//! helper).

use super::*;

fn assert_variant(err: anyhow::Error, ok: impl Fn(&PersonaError) -> bool) {
    assert!(
        err.downcast_ref::<PersonaError>().is_some_and(ok),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn list_conflicts_exposes_both_versions_and_count() {
    let (db, identity, _master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, copy) = seeded_conflict(item, &group, identity.id);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group.clone());
    let entries = session.list_conflicts().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].item_id, item);
    assert_eq!(
        entries[0].primary.snapshot.as_ref().unwrap().name,
        "primary-name"
    );
    assert!(!entries[0].primary.deleted);
    assert_eq!(entries[0].copies.len(), 1);
    assert_eq!(
        entries[0].copies[0].snapshot.as_ref().unwrap().name,
        "copy-name"
    );
    assert_eq!(session.conflict_item_count().await.unwrap(), 1);

    // A conflict-free entry (single version) does not enter the resolution
    // view
    sync_repo
        .record_remote_op(&conflict_put_op(
            Uuid::new_v4(),
            Uuid::new_v4(),
            1,
            &snapshot("lone", identity.id),
            &group,
        ))
        .await
        .unwrap();
    assert_eq!(session.list_conflicts().await.unwrap().len(), 1);
}

#[tokio::test]
async fn resolve_adopted_put_writes_row_and_wins_primary() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, copy) = seeded_conflict(item, &group, identity.id);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let local_device = Uuid::new_v4();
    let (session, _) = session_for(&db, local_device, group);
    session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap();

    // The master row = the adopted copy's content (including the
    // CredentialData, readable after rewrapping)
    let cred_repo = CredentialRepository::new(db.clone());
    let row = cred_repo.find_by_id(&item).await.unwrap().unwrap();
    assert_eq!(row.name, "copy-name");
    let plaintext = KeyHierarchy::new(&master)
        .decrypt_with_wrapped_key(row.wrapped_item_key.as_ref().unwrap(), &row.encrypted_data)
        .unwrap();
    match CredentialData::from_bytes(&plaintext).unwrap() {
        CredentialData::Password(p) => assert_eq!(p.password, "copy-name"),
        other => panic!("expected password data, got {other:?}"),
    }

    // oplog: the adopt op with a fresh local lamport wins the master
    // position; the conflict area is empty
    let view = item_view(sync_repo.item_ops(item).await.unwrap());
    let new_primary = view.primary.unwrap();
    assert_eq!(new_primary.device_id, local_device);
    assert!(new_primary.lamport > 5);
    assert!(view.conflicts.is_empty());

    // The adopt op is in the push queue and its payload bytes reuse the
    // copy's (device-independent)
    let pending = sync_repo.pending_ops(500).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].payload, copy.payload);

    // The resolution view is empty
    assert!(session.list_conflicts().await.unwrap().is_empty());
    assert_eq!(session.conflict_item_count().await.unwrap(), 0);
}

#[tokio::test]
async fn resolve_adopted_delete_removes_row_and_wins_primary() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let local_device = Uuid::new_v4();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let (winner, loser) = if a > b { (a, b) } else { (b, a) };
    let put = conflict_put_op(item, winner, 5, &snapshot("alive", identity.id), &group);
    let del = conflict_delete_op(item, loser, 5);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&put).await.unwrap();
    sync_repo.record_remote_op(&del).await.unwrap();

    let (session, _) = session_for(&db, local_device, group.clone());
    // Materialize the master-position put first (the row exists), then adopt
    // the delete copy
    Materializer::new(db.clone())
        .materialize_all(&master, &group, local_device)
        .await
        .unwrap();
    let cred_repo = CredentialRepository::new(db.clone());
    assert!(cred_repo.find_by_id(&item).await.unwrap().is_some());

    session
        .resolve_conflict(&master, item, del.op_id)
        .await
        .unwrap();
    assert!(cred_repo.find_by_id(&item).await.unwrap().is_none());
    let view = item_view(sync_repo.item_ops(item).await.unwrap());
    assert!(view.primary.unwrap().is_tombstone());
    assert!(view.conflicts.is_empty());
    assert_eq!(session.conflict_item_count().await.unwrap(), 0);
}

#[tokio::test]
async fn resolve_adopted_delete_detaches_audit_rows_instead_of_fk_error() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let local_device = Uuid::new_v4();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let (winner, loser) = if a > b { (a, b) } else { (b, a) };
    let put = conflict_put_op(item, winner, 5, &snapshot("alive", identity.id), &group);
    let del = conflict_delete_op(item, loser, 5);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&put).await.unwrap();
    sync_repo.record_remote_op(&del).await.unwrap();

    let (session, _) = session_for(&db, local_device, group.clone());
    // Materialize the master-position put first (the row exists), then create
    // an audit reference (audit_logs FK NO ACTION)
    Materializer::new(db.clone())
        .materialize_all(&master, &group, local_device)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO audit_logs (id, credential_id, action, resource_type, success, timestamp) \
             VALUES (?, ?, 'credential.viewed', 'credential', 1, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(item.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(db.pool())
    .await
    .unwrap();

    // Adopt the delete copy: the delete is not rejected because of the audit
    // reference (the earlier FK 787)
    session
        .resolve_conflict(&master, item, del.op_id)
        .await
        .unwrap();
    let cred_repo = CredentialRepository::new(db.clone());
    assert!(cred_repo.find_by_id(&item).await.unwrap().is_none());
    let (detached,) =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_logs WHERE credential_id IS NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(detached, 1, "audit row preserved with reference detached");
}

#[tokio::test]
async fn resolve_rejects_unknown_primary_and_stale_op_ids() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, copy) = seeded_conflict(item, &group, identity.id);
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);

    // Adopting the master position (not a copy) and an unknown op_id both
    // -> NotFound
    let err = session
        .resolve_conflict(&master, item, primary.op_id)
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));
    let err = session
        .resolve_conflict(&master, item, Uuid::new_v4())
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));

    // After one resolution: the remaining versions drop out of the view, and
    // resolving the same item again -> NotFound
    session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap();
    let err = session
        .resolve_conflict(&master, item, primary.op_id)
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::NotFound(_)));
}

/// The copy references an unsynced identity: the master cannot be written ->
/// a Validation error, with zero side effects on the oplog / clock /
/// resolution view (never log an op without writing the master = guard
/// against silent divergence).
#[tokio::test]
async fn resolve_with_pending_identity_errors_without_side_effects() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let (winner, loser) = if a > b { (a, b) } else { (b, a) };
    let primary = conflict_put_op(item, winner, 5, &snapshot("primary", identity.id), &group);
    // The copy references an unknown identity
    let copy = conflict_put_op(
        item,
        loser,
        5,
        &snapshot("dangling", Uuid::new_v4()),
        &group,
    );
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let lamport_before = sync_repo.get_state().await.unwrap().local_lamport;

    let err = session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::Validation(_)));

    assert!(sync_repo.pending_ops(500).await.unwrap().is_empty());
    assert_eq!(
        sync_repo.get_state().await.unwrap().local_lamport,
        lamport_before
    );
    assert_eq!(session.list_conflicts().await.unwrap().len(), 1);
}

// Shape defenses at the resolution entry: a copy whose kind is not a
// credential and a put copy missing its payload both fail with InvalidInput;
// the oplog / master database are untouched.
#[tokio::test]
async fn resolve_rejects_non_credential_conflict_copy() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, mut copy) = seeded_conflict(item, &group, identity.id);
    copy.kind = ItemKind::Unknown;
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let err = session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::InvalidInput(_)));
}

#[tokio::test]
async fn resolve_rejects_put_copy_without_payload() {
    let (db, identity, master) = seeded_db().await;
    let item = Uuid::new_v4();
    let group = GroupKey::generate().unwrap();
    let (primary, mut copy) = seeded_conflict(item, &group, identity.id);
    copy.payload = None;
    let sync_repo = SyncRepository::new(db.clone());
    sync_repo.record_remote_op(&primary).await.unwrap();
    sync_repo.record_remote_op(&copy).await.unwrap();

    let (session, _) = session_for(&db, Uuid::new_v4(), group);
    let err = session
        .resolve_conflict(&master, item, copy.op_id)
        .await
        .unwrap_err();
    assert_variant(err, |e| matches!(e, PersonaError::InvalidInput(_)));
}
