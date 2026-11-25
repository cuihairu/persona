use super::*;

use crate::crypto::key_hierarchy::KeyHierarchy;
use crate::sync::materialize::MaterializeOutcome;

// ---- passkey materialization ----

#[tokio::test]
async fn remote_passkey_put_materializes_row_and_private_key_stays_decryptable() {
    let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    let item_id = Uuid::new_v4();
    let item_key = EncryptionService::generate_key();
    // Private-key envelope = the scalar bytes sealed with the item key (same shape as create_passkey_full)
    let scalar = b"p256-scalar-bytes-32-bytes-xxxxxxx";
    let sealed_key = EncryptionService::new(&item_key).encrypt(scalar).unwrap();
    let snapshot = passkey_snapshot(identity_id, "remote.example", &sealed_key);
    materializer
        .sync_repo
        .record_remote_op(&passkey_put_op(
            item_id,
            Uuid::new_v4(),
            3,
            &item_key,
            &snapshot,
            &group,
        ))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Written);

    let row = materializer
        .passkey_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .expect("passkey row materialized");
    assert_eq!(row.rp_id, "remote.example");
    assert_eq!(row.user_name.as_deref(), Some("bob@example.com"));
    assert!(!row.export_allowed);
    assert_eq!(row.alg, -7);

    // The item key is rewrapped to the local primary key with unchanged bytes -> the private-key envelope still decrypts
    let hierarchy = KeyHierarchy::new(&master);
    let scalar_out = hierarchy
        .decrypt_with_wrapped_key(&row.wrapped_item_key, &row.encrypted_private_key)
        .unwrap();
    assert_eq!(scalar_out, scalar);
    // Device-local usage state takes zero values (the remote snapshot carries none)
    assert_eq!(row.sign_count, 0);
    assert!(row.last_used_at.is_none());
}

#[tokio::test]
async fn remote_passkey_put_overwrites_semantics_but_keeps_local_usage() {
    let (db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    let item_id = Uuid::new_v4();
    let item_key = EncryptionService::generate_key();
    let sealed_key = EncryptionService::new(&item_key)
        .encrypt(b"scalar-v1")
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&passkey_put_op(
            item_id,
            Uuid::new_v4(),
            1,
            &item_key,
            &passkey_snapshot(identity_id, "first.example", &sealed_key),
            &group,
        ))
        .await
        .unwrap();
    materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();

    // Local usage state: written directly (repo.update's semantic field set excludes sign_count)
    sqlx::query("UPDATE passkeys SET sign_count = 5, last_used_at = ? WHERE id = ?")
        .bind(Utc::now().timestamp())
        .bind(item_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();

    // Second remote put (newer lamport): a different rp and a different private-key envelope
    let sealed_key2 = EncryptionService::new(&item_key)
        .encrypt(b"scalar-v2")
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&passkey_put_op(
            item_id,
            Uuid::new_v4(),
            2,
            &item_key,
            &passkey_snapshot(identity_id, "second.example", &sealed_key2),
            &group,
        ))
        .await
        .unwrap();
    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Written);

    let row = materializer
        .passkey_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.rp_id, "second.example");
    // Usage state keeps the local values
    assert_eq!(row.sign_count, 5);
    assert!(row.last_used_at.is_some());
}

#[tokio::test]
async fn remote_passkey_tombstone_deletes_local_row() {
    let (_db, materializer, _identity_repo, group, identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    let item_id = Uuid::new_v4();
    let item_key = EncryptionService::generate_key();
    let sealed_key = EncryptionService::new(&item_key)
        .encrypt(b"scalar")
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&passkey_put_op(
            item_id,
            Uuid::new_v4(),
            1,
            &item_key,
            &passkey_snapshot(identity_id, "gone.example", &sealed_key),
            &group,
        ))
        .await
        .unwrap();
    materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert!(materializer
        .passkey_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_some());

    materializer
        .sync_repo
        .record_remote_op(&SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Passkey,
            op: OpType::Delete,
            lamport: 2,
            device_id: Uuid::new_v4(),
            timestamp: Some(Utc::now()),
            payload: None,
        })
        .await
        .unwrap();
    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(outcome, MaterializeOutcome::Tombstoned);
    assert!(materializer
        .passkey_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn remote_passkey_put_with_unknown_identity_defers() {
    let (_db, materializer, _identity_repo, group, _identity_id) = setup().await;
    let master = EncryptionService::new(&EncryptionService::generate_key());

    let item_id = Uuid::new_v4();
    let item_key = EncryptionService::generate_key();
    let sealed_key = EncryptionService::new(&item_key)
        .encrypt(b"scalar")
        .unwrap();
    materializer
        .sync_repo
        .record_remote_op(&passkey_put_op(
            item_id,
            Uuid::new_v4(),
            1,
            &item_key,
            &passkey_snapshot(Uuid::new_v4(), "dangling.example", &sealed_key),
            &group,
        ))
        .await
        .unwrap();

    let outcome = materializer
        .materialize_item(&item_id, &master, &group, Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        MaterializeOutcome::SkippedPendingIdentity { .. }
    ));
    assert!(materializer
        .passkey_repo
        .find_by_id(&item_id)
        .await
        .unwrap()
        .is_none());
}
