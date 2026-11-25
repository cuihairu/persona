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

    // The item key is rewrapped to the local primary key, so the data decrypts normally.
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

    // The audit row references the credential (audit_logs.credential_id FK is NO ACTION)
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

    // Remote tombstone: the audit reference must be detached before deleting the row, otherwise the FK rejects it with 787
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
    // The audit row survives with its reference detached
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
    // The primary is a local op (same device_id): the primary store is the source of truth, so materialization must yield.
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
        identity_id: Uuid::new_v4(), // Unknown identity: the Identity entry has not synced yet
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
    // The op stays in the oplog and can be caught up next round
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
    // Same lamport, different devices = a real conflict; the primary is the one with the larger device_id (§7, descending).
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
    // The loser stays resident in the oplog conflict area, awaiting phase 3's arbitration UI.
    let view = item_view(materializer.sync_repo.item_ops(item_id).await.unwrap());
    assert_eq!(view.primary.unwrap().device_id, winner_device);
    assert_eq!(view.conflicts.len(), 1);
    assert_eq!(view.conflicts[0].device_id, loser_device);
    let _ = winner_device; // Already asserted via the name
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

    // Re-running is idempotent: the same outcome, with no duplication and no error.
    let again = materializer
        .materialize_all(&master, &group, local_device)
        .await
        .unwrap();
    assert_eq!(again, report);
}

/// Protocol defense surface: an item with no op in the oplog (a caller enumeration racing the query) and
/// the "put without payload" invariant violation both map to NoPrimary, and the latter never writes to the store.
#[tokio::test]
async fn no_primary_paths_never_touch_main_store() {
    let (_db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());
    let other_device = Uuid::new_v4();

    // 1) No op for this item exists in the oplog.
    let ghost = Uuid::new_v4();
    let outcome = materializer
        .materialize_item(&ghost, &master, &group, other_device)
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::NoPrimary);

    // 2) A put carrying no payload — fail-closed, no half-written row.
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

/// The reporting surface of materialize_all: pending identities land in the report and wait for the next round; a
/// single item with a corrupt snapshot (a valid wrapped key but bad ciphertext) takes the Err arm and is only
/// warned about, without aborting the batch — both ops stay resident in the oplog.
#[tokio::test]
async fn materialize_all_reports_pending_and_tolerates_corrupt_snapshot() {
    let (_db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    // pending: references an unknown identity (Identity not synced yet)
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

    // Corrupt: the wrapped item key is valid (the group can unwrap it), but the ciphertext yields no snapshot
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
