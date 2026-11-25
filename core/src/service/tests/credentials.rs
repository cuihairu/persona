use super::*;

#[tokio::test]
async fn custom_fields_set_read_roundtrip_seals_values() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(
        &service,
        identity.id,
        "WithFields",
        CredentialType::Password,
    )
    .await;

    let fields = vec![
        crate::custom_fields::new_custom_field(
            "Server",
            "db.internal:5432",
            crate::models::credential::CustomFieldType::Text,
        ),
        crate::custom_fields::new_custom_field(
            "Recovery code",
            "abcd-efgh",
            crate::models::credential::CustomFieldType::Concealed,
        ),
    ];
    service
        .set_custom_fields(&cred.id, fields.clone())
        .await
        .unwrap();

    let read_back = service.custom_fields(&cred.id).await.unwrap();
    assert_eq!(read_back, fields);

    // The stored form is ciphertext: the metadata blob holds no plaintext label or value
    let stored = service.get_credential(&cred.id).await.unwrap().unwrap();
    let blob = stored
        .metadata
        .get(crate::custom_fields::CUSTOM_FIELDS_METADATA_KEY)
        .unwrap();
    assert!(!blob.contains("Recovery code"));
    assert!(!blob.contains("abcd-efgh"));
}

#[tokio::test]
async fn custom_fields_empty_list_removes_blob() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;

    let fields = vec![crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    )];
    service.set_custom_fields(&cred.id, fields).await.unwrap();
    service
        .set_custom_fields(&cred.id, Vec::new())
        .await
        .unwrap();

    assert!(service.custom_fields(&cred.id).await.unwrap().is_empty());
    let stored = service.get_credential(&cred.id).await.unwrap().unwrap();
    assert!(!stored
        .metadata
        .contains_key(crate::custom_fields::CUSTOM_FIELDS_METADATA_KEY));
}

#[tokio::test]
async fn custom_fields_locked_vault_fails_closed() {
    let (_db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;
    let fields = vec![crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    )];
    service.set_custom_fields(&cred.id, fields).await.unwrap();

    service.lock();
    assert!(service.custom_fields(&cred.id).await.is_err());
    assert!(service
        .set_custom_fields(&cred.id, Vec::new())
        .await
        .is_err());
}

#[tokio::test]
async fn custom_fields_duplicate_ids_rejected() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("CF Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "CF", CredentialType::Password).await;

    let mut a = crate::custom_fields::new_custom_field(
        "K",
        "V",
        crate::models::credential::CustomFieldType::Text,
    );
    let b = a.clone();
    a.label = "K2".to_string();
    assert!(service
        .set_custom_fields(&cred.id, vec![a, b])
        .await
        .is_err());
}

#[tokio::test]
async fn credential_history_records_created_updated_deleted() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("History Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let mut cred = seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;

    // Create -> created row v1 (new state present, no previous state)
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].change_type, ChangeType::Created);
    assert_eq!(history[0].version, 1);
    assert!(history[0].new_state.is_some());
    assert!(history[0].previous_state.is_none());

    // Metadata change -> updated row v2, with field-level diffs for username and url
    cred.username = Some("alice".to_string());
    cred.url = Some("https://mail.example.com".to_string());
    service.update_credential(&cred).await.unwrap();

    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].change_type, ChangeType::Updated);
    assert_eq!(history[0].version, 2);
    assert_eq!(history[0].changes_summary.len(), 2);
    let username_change = history[0].changes_summary.get("username").unwrap();
    assert_eq!(username_change.old_value, "");
    assert_eq!(username_change.new_value, "alice");

    // A repeat update with no real change -> no new history row
    service.update_credential(&cred).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2, "no-op update must not add history");

    // Ciphertext change (password rotation) -> only a placeholder diff; content never reaches history
    cred.encrypted_data = vec![9u8; 8];
    service.update_credential(&cred).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let enc_change = history[0].changes_summary.get("encrypted_data").unwrap();
    assert_eq!(enc_change.old_value, "<encrypted>");
    assert_eq!(enc_change.new_value, "<encrypted>");
    let states = serde_json::to_string(&history[0].new_state).unwrap();
    assert!(!states.contains("encrypted_data"));

    // Delete -> deleted row v4 (the credential row is gone, the history stays)
    service.delete_credential(&cred.id).await.unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].change_type, ChangeType::Deleted);
    assert_eq!(history[0].version, 4);
}

#[tokio::test]
async fn restore_credential_version_reverts_metadata_and_keeps_secrets() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Restore Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let mut cred = seed_credential(&service, identity.id, "Gmail", CredentialType::Password).await;
    let original_ciphertext = cred.encrypted_data.clone();

    // v2：username/url
    cred.username = Some("alice".to_string());
    cred.url = Some("https://mail.example.com".to_string());
    service.update_credential(&cred).await.unwrap();

    // v3：rename
    cred.name = "Gmail Work".to_string();
    service.update_credential(&cred).await.unwrap();

    // Restore to v1 (creation state): metadata rolls back, ciphertext stays as-is
    let restored = service
        .restore_credential_version(&cred.id, 1)
        .await
        .unwrap();
    assert_eq!(restored.name, "Gmail");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);
    assert_eq!(restored.tags, Vec::<String>::new());
    assert!(!restored.is_favorite);
    assert!(restored.is_active);
    assert_eq!(
        restored.encrypted_data, original_ciphertext,
        "metadata restore must never touch the secret payload"
    );

    // History gains a restored row, with the reason naming the target version
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].change_type, ChangeType::Restored);
    assert_eq!(history[0].version, 4);
    assert_eq!(history[0].reason.as_deref(), Some("restore to version 1"));
    let name_change = history[0].changes_summary.get("name").unwrap();
    assert_eq!(name_change.old_value, "Gmail Work");
    assert_eq!(name_change.new_value, "Gmail");
    let username_change = history[0].changes_summary.get("username").unwrap();
    assert_eq!(username_change.old_value, "alice");
    assert_eq!(username_change.new_value, "");

    // An intermediate version is also restorable: back to v2 (username=alice, name=Gmail)
    let restored = service
        .restore_credential_version(&cred.id, 2)
        .await
        .unwrap();
    assert_eq!(restored.name, "Gmail");
    assert_eq!(restored.username.as_deref(), Some("alice"));
    assert_eq!(restored.url.as_deref(), Some("https://mail.example.com"));

    // Restoring to the current state = no real change -> no noisy history row
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 5);
    service
        .restore_credential_version(&cred.id, 2)
        .await
        .unwrap();
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    assert_eq!(history.len(), 5, "no-op restore must not add history");
}

#[tokio::test]
async fn restore_credential_version_rejects_bad_targets() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Restore Errors".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Temp", CredentialType::Password).await;

    let err = service
        .restore_credential_version(&cred.id, 99)
        .await
        .expect_err("unknown version must fail");
    assert!(err.to_string().contains("no history version 99"));

    let missing = Uuid::new_v4();
    let err = service
        .restore_credential_version(&missing, 1)
        .await
        .expect_err("unknown credential must fail");
    assert!(err.to_string().contains("not found"));

    // A deleted item cannot be restored (the row is gone; history remains queryable but the secret envelope is not rebuilt)
    service.delete_credential(&cred.id).await.unwrap();
    let err = service
        .restore_credential_version(&cred.id, 1)
        .await
        .expect_err("deleted credential must not restore");
    assert!(err.to_string().contains("not found"));
}

/// Core invariant of editing a payload: wrapped_item_key bytes stay untouched, the new
/// payload is re-sealed with the same item key, attached attachments remain decryptable,
/// and item history records an Updated row.
#[tokio::test]
async fn update_credential_data_reuses_item_key_and_keeps_attachments() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Edit Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "edit target",
        CredentialType::Password,
    )
    .await;
    let wrapped_before = credential.wrapped_item_key.clone().unwrap();

    // Attach one encrypted attachment first (sealed with the current item key)
    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db.clone())
        .await
        .unwrap();
    let file_path = dir.path().join("edit-attach.bin");
    std::fs::write(&file_path, b"attachment-before-edit").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    // Edit the payload
    let edited = CredentialData::Password(PasswordCredentialData {
        password: "rotated-secret".to_string(),
        email: Some("edited@example.com".to_string()),
        security_questions: vec![],
    });
    let updated = service
        .update_credential_data(&credential.id, &edited)
        .await
        .unwrap();

    // wrapped key bytes unchanged (hard guarantee of the attachment invariant)
    assert_eq!(
        updated.wrapped_item_key.as_deref(),
        Some(&wrapped_before[..])
    );

    // The new payload reads back verbatim
    let data = service
        .get_credential_data(&credential.id)
        .await
        .unwrap()
        .unwrap();
    match data {
        CredentialData::Password(p) => {
            assert_eq!(p.password, "rotated-secret");
            assert_eq!(p.email.as_deref(), Some("edited@example.com"));
        }
        other => panic!("unexpected credential data: {other:?}"),
    }

    // The attachment is still decryptable (same item key)
    let plain = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap();
    assert_eq!(plain, b"attachment-before-edit".to_vec());

    // item history records an Updated row (created + updated, at least two rows)
    let history = service
        .get_entity_history(EntityType::Credential, &credential.id)
        .await
        .unwrap();
    assert!(history.iter().any(|e| e.change_type == ChangeType::Updated));
}

/// Editing a legacy row (wrapped_item_key NULL) upgrades it to a per-item key:
/// after the upgrade the new ciphertext decrypts via the item key and the row gains a wrapped key.
#[tokio::test]
async fn update_credential_data_upgrades_legacy_row_to_item_key() {
    let (db, service) = unlocked_service().await;

    let identity = service
        .create_identity("Legacy Edit Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // Build the legacy row by hand (same pattern as the attach upgrade test)
    let master = service.get_master_encryption_service().unwrap();
    let plaintext = CredentialData::Password(PasswordCredentialData {
        password: "legacy-pw".to_string(),
        email: None,
        security_questions: vec![],
    })
    .to_bytes()
    .unwrap();
    let sealed = master.encrypt(&plaintext).unwrap();
    let credential = Credential::new(
        identity.id,
        "legacy edit row".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        sealed,
        None,
    );
    let credentials = crate::storage::CredentialRepository::new(db.clone());
    credentials.create(&credential).await.unwrap();

    let edited = CredentialData::Password(PasswordCredentialData {
        password: "edited-pw".to_string(),
        email: None,
        security_questions: vec![],
    });
    let updated = service
        .update_credential_data(&credential.id, &edited)
        .await
        .unwrap();
    assert!(updated.wrapped_item_key.is_some());

    // The new ciphertext decrypts via the item key path (legacy branch no longer hit)
    let data = service
        .get_credential_data(&credential.id)
        .await
        .unwrap()
        .unwrap();
    match data {
        CredentialData::Password(p) => assert_eq!(p.password, "edited-pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

/// Editing a nonexistent credential returns InvalidInput (instead of silently succeeding).
#[tokio::test]
async fn update_credential_data_rejects_unknown_id() {
    let (_db, service) = unlocked_service().await;
    let err = service
        .update_credential_data(
            &Uuid::new_v4(),
            &CredentialData::Password(PasswordCredentialData {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

/// Deleting a credential cascades to attachments: blob metadata disappears with the row, leaving no undecryptable orphans.
#[tokio::test]
async fn delete_credential_cascades_attachments() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Cascade Attach".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "cascade attach",
        CredentialType::Password,
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("cascade.bin");
    std::fs::write(&file_path, b"cascade-bytes").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();
    assert_eq!(
        service.get_attachments(&credential.id).await.unwrap().len(),
        1
    );

    assert!(service.delete_credential(&credential.id).await.unwrap());

    assert!(service
        .get_attachments(&credential.id)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .retrieve_attachment(&attachment_id, true)
        .await
        .is_err());
}

/// Both branches of delete_credential: an existing credential returns true and writes a
/// CredentialDeleted audit; deleting again (now nonexistent) returns false without a duplicate audit.
#[tokio::test]
async fn delete_credential_true_then_false_with_audit() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Delete Audit".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Doomed", CredentialType::Password).await;

    assert!(service.delete_credential(&cred.id).await.unwrap());
    assert!(!service.delete_credential(&cred.id).await.unwrap());

    let logs = service
        .query_audit_logs(AuditLogQuery::default())
        .await
        .unwrap();
    let deleted = logs
        .iter()
        .filter(|l| l.action == AuditAction::CredentialDeleted)
        .collect::<Vec<_>>();
    assert_eq!(deleted.len(), 1, "audit written once, not for the miss");
    assert_eq!(
        deleted[0].resource_id.as_deref(),
        Some(cred.id.to_string()).as_deref()
    );
    assert!(deleted[0].success);
}

/// Sync capture seam: after attach(Some), credential writes hand a Put to the capture impl; after
/// attach(None) the write path silently skips. Capture failures or missing capture never block the
/// main operation — that is guaranteed by the type. What is verified here is the wiring between
/// attach and capture itself.
#[tokio::test]
async fn attach_sync_capture_feeds_credential_puts_only_while_attached() {
    use std::sync::Mutex;

    struct RecordingCapture(std::sync::Arc<Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl crate::sync::capture::SyncCapture for RecordingCapture {
        async fn capture(
            &self,
            _item_id: Uuid,
            kind: crate::sync::oplog::ItemKind,
            op: crate::sync::oplog::OpType,
            _ciphertext: Option<Vec<u8>>,
            _item_key: Option<zeroize::Zeroizing<[u8; 32]>>,
        ) {
            self.0.lock().unwrap().push(format!("{kind:?}:{op:?}"));
        }
    }

    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Capture Seam".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    service
        .attach_sync_capture(Some(Arc::new(RecordingCapture(log.clone()))))
        .await;

    seed_credential(&service, identity.id, "Synced", CredentialType::Password).await;
    assert_eq!(*log.lock().unwrap(), vec!["Credential:Put".to_string()]);

    service.attach_sync_capture(None).await;
    seed_credential(&service, identity.id, "Unsynced", CredentialType::Password).await;
    assert_eq!(
        *log.lock().unwrap(),
        vec!["Credential:Put".to_string()],
        "detached capture must not observe further writes"
    );
}

/// Whole-snapshot validation semantics of apply_meta_snapshot: a bad snapshot reports InvalidInput
/// field by field, and on failure no credential metadata field is applied (no half-updates).
#[test]
fn apply_meta_snapshot_validates_before_mutating() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Original".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        b"ciphertext".to_vec(),
        None,
    );

    fn apply(cred: &mut Credential, snapshot: &serde_json::Value) -> Result<()> {
        PersonaService::apply_meta_snapshot(cred, snapshot)
    }

    // not an object / missing name / missing tags / tags not an array of strings / missing boolean fields
    assert!(apply(&mut cred, &serde_json::json!("nope"))
        .unwrap_err()
        .to_string()
        .contains("not an object"));
    assert!(apply(&mut cred, &serde_json::json!({}))
        .unwrap_err()
        .to_string()
        .contains("missing field name"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High"
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field tags"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": [7]
        })
    )
    .unwrap_err()
    .to_string()
    .contains("tag is not a string"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": []
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field is_favorite"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "High",
            "tags": [], "is_favorite": true
        })
    )
    .unwrap_err()
    .to_string()
    .contains("missing field is_active"));
    assert!(apply(
        &mut cred,
        &serde_json::json!({
            "name": "Broken", "credential_type": "Password", "security_level": "extreme",
            "tags": [], "is_favorite": true, "is_active": true
        })
    )
    .unwrap_err()
    .to_string()
    .contains("Unknown security level"));

    // After all the failures the credential has not been half-applied
    assert_eq!(cred.name, "Original");

    // A valid snapshot: all metadata is applied, secret envelope fields left as-is
    apply(
        &mut cred,
        &serde_json::json!({
            "name": "Restored", "credential_type": "ApiKey", "security_level": "Medium",
            "username": "u", "url": "https://x", "notes": "n", "tags": ["a", "b"],
            "is_favorite": true, "is_active": false
        }),
    )
    .unwrap();
    assert_eq!(cred.name, "Restored");
    assert_eq!(cred.credential_type.to_string(), "ApiKey");
    assert_eq!(cred.security_level.to_string(), "Medium");
    assert_eq!(cred.username.as_deref(), Some("u"));
    assert_eq!(cred.tags, vec!["a".to_string(), "b".to_string()]);
    assert!(cred.is_favorite);
    assert!(!cred.is_active);
    assert_eq!(cred.encrypted_data, b"ciphertext".to_vec());
}

/// restore hitting a Deleted history row with "version exists but no new_state" -> reports
/// no restorable state and leaves the credential itself untouched.
#[tokio::test]
async fn restore_credential_version_rejects_tombstone_history() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Tombstone Restore".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = seed_credential(&service, identity.id, "Target", CredentialType::Password).await;

    // Record a Deleted history row (new_state=None); the credential body is still in the database
    service
        .record_credential_history(ChangeType::Deleted, Some(&cred), None, None)
        .await;
    let history = service
        .get_entity_history(EntityType::Credential, &cred.id)
        .await
        .unwrap();
    let deleted_version = history
        .iter()
        .find(|h| h.change_type.to_string() == "deleted")
        .expect("Deleted history row was recorded")
        .version;

    let err = service
        .restore_credential_version(&cred.id, deleted_version)
        .await
        .expect_err("tombstone history has nothing to restore");
    assert!(err.to_string().contains("no restorable state"));

    let after = service
        .credential_repo
        .find_by_id(&cred.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.name, "Target", "failed restore must not mutate");
}

/// Best-effort semantics of history recording: (None, None) returns immediately; when the
/// underlying table is unavailable only a warning is emitted and the main write is not blocked
/// (the business fact is already committed, history is derived data).
#[tokio::test]
async fn credential_history_is_best_effort() {
    let (db, service) = unlocked_service().await;
    let identity = service
        .create_identity("Hist".into(), IdentityType::Personal)
        .await
        .unwrap();

    // (None, None) pass-through: no entity to record
    service
        .record_credential_history(ChangeType::Created, None, None, None)
        .await;

    // Table unavailable -> recording failure only warns, credential creation still succeeds
    sqlx::query("DROP TABLE change_history")
        .execute(db.pool())
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "after drop",
        CredentialType::Password,
    )
    .await;
    assert!(service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .is_some());
}
