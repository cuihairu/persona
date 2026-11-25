//! Group key rotation / rewrap domain tests.

use super::*;

// Rotation core (the rewrap half): rewrap_all re-logs every credential in
// the master database under the new group key -- the new ops' item key
// envelopes can only be unwrapped with the new group key, the opened
// snapshot content matches the original credential, and the lamport strictly
// increases (LWW makes them the new master position).
// drain_push_queue only exists under the remote-auth feature, so the test is
// gated the same way.
#[cfg(feature = "remote-auth")]
#[tokio::test]
async fn rewrap_all_reseals_every_credential_with_new_group_key() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());
    store_credential(&cred_repo, identity.id, "cred-one", &master, "one").await;
    store_credential(&cred_repo, identity.id, "cred-two", &master, "two").await;

    let old_group = GroupKey::generate().unwrap();
    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), old_group.clone());
    assert_eq!(session.backfill_existing(&master).await.unwrap(), 2);

    let new_group = GroupKey::generate().unwrap();
    let (rewrapped, skipped) = session.rewrap_all(&master, &new_group).await.unwrap();
    assert_eq!((rewrapped, skipped), (2, 0));

    // After draining, the remote receives 4 ops in total: 2 from backfill
    // (sealed with the old key) + 2 from the rewrap (sealed with the new key)
    let drained = session.drain_push_queue().await.unwrap();
    assert_eq!(drained, 4);
    let pushed = pushed_log.lock().unwrap();
    assert_eq!(pushed.len(), 4);
    assert_eq!(pushed.len(), 4);
    let (older, newer) = pushed.split_at(2);
    // The new batch's lamport is strictly greater than the old batch's
    // (monotonically increasing in total order)
    assert!(newer.iter().all(|op| op.lamport > older[0].lamport));

    for op in newer {
        let payload = op.payload.as_ref().unwrap();
        // Only the new group key can unwrap the item key envelope
        let item_key =
            crate::sync::keys::unwrap_item_key_with_group(&payload.wrapped_item_key, &new_group)
                .unwrap();
        let snapshot = SyncItemSnapshot::open(&payload.ciphertext, &item_key).unwrap();
        let expected = if snapshot.name == "cred-one" {
            "one"
        } else {
            "two"
        };
        let opened = match &snapshot.data {
            CredentialData::Password(p) => p.password.clone(),
            #[allow(unreachable_patterns)]
            _ => String::new(),
        };
        assert_eq!(opened, expected);
        // The old group key cannot unwrap the new batch (forward boundary: a
        // revoked device holding the old key reads nothing)
        assert!(crate::sync::keys::unwrap_item_key_with_group(
            &payload.wrapped_item_key,
            &old_group
        )
        .is_err());
    }
}

// An admin-side failure during rotation must have zero side effects: the
// clock does not advance and no pending op is added -- the failure happens
// before the envelopes are re-sealed, so the local oplog is untouched.
// rotate_group_key/SyncAdminApi only exist under the remote-auth feature, so
// this is gated the same way.
#[cfg(feature = "remote-auth")]
#[tokio::test]
async fn rotate_with_failing_admin_leaves_no_side_effects() {
    let (db, _identity, master) = seeded_db().await;
    let (session, pushed_log) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let admin = crate::sync::remote::SyncAdminApi::new("http://127.0.0.1:1", "t").unwrap();
    let lamport_before = session.sync_repo.get_state().await.unwrap().local_lamport;

    let err = session
        .rotate_group_key(&master, &admin)
        .await
        .expect_err("unreachable admin must fail");
    let _ = err;

    assert!(pushed_log.lock().unwrap().is_empty());
    let lamport_after = session.sync_repo.get_state().await.unwrap().local_lamport;
    assert_eq!(lamport_after, lamport_before);
}

// ---- Rewrap tolerance matrix: legacy / corrupt wrapped key / corrupt
// ciphertext / invalid plaintext -- each is skipped individually without
// blocking the whole batch; a healthy entry rewraps normally (control
// group). ----

#[tokio::test]
async fn rewrap_all_skips_unreadable_credentials_one_by_one() {
    let (db, identity, master) = seeded_db().await;
    let cred_repo = CredentialRepository::new(db.clone());

    // (1) legacy: no wrapped item key (no item key to recover) -> skip
    cred_repo
        .create(&Credential::new(
            identity.id,
            "legacy".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1u8; 32],
            None,
        ))
        .await
        .unwrap();

    // (2) wrapped key corrupt (unwrap_item_key fails) -> skip
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-wrapped".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![1u8; 32],
            Some(vec![7u8; 8]),
        ))
        .await
        .unwrap();

    // (3) wrapped key valid but ciphertext corrupt (decrypt fails) -> skip
    let item_key = EncryptionService::generate_key();
    let wrapped = master.encrypt(&item_key).unwrap();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-ciphertext".into(),
            CredentialType::Password,
            SecurityLevel::High,
            vec![9u8; 64],
            Some(wrapped.clone()),
        ))
        .await
        .unwrap();

    // (4) decryption succeeds but the plaintext is not valid CredentialData
    // (from_bytes fails) -> skip
    let junk = KeyHierarchy::new(&master)
        .encrypt_with_item_key(&item_key, b"not-credential-data")
        .unwrap();
    cred_repo
        .create(&Credential::new(
            identity.id,
            "bad-data".into(),
            CredentialType::Password,
            SecurityLevel::High,
            junk,
            Some(wrapped),
        ))
        .await
        .unwrap();

    // Control group: a healthy credential should rewrap normally
    store_credential(&cred_repo, identity.id, "healthy", &master, "ok").await;

    let new_group = GroupKey::generate().unwrap();
    let (session, _) = session_for(&db, Uuid::new_v4(), GroupKey::generate().unwrap());
    let (rewrapped, skipped) = session.rewrap_all(&master, &new_group).await.unwrap();
    assert_eq!(
        (rewrapped, skipped),
        (1, 4),
        "healthy rewrapped, 4 bad skipped"
    );
}
