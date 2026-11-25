use super::*;

#[tokio::test]
async fn test_attachment_lifecycle() {
    let (db, mut service) = unlocked_service().await;

    // Before initialization every attachment op reports the missing store.
    let err = service
        .get_attachment_stats()
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Attachment storage not initialized"));

    let identity = service
        .create_identity("Attach Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "with file", CredentialType::Password).await;

    let err = service
        .attach_file(credential.id, "/tmp/nope", false)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Attachment storage not initialized"));

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("secret.txt");
    std::fs::write(&file_path, b"attachment-bytes").unwrap();

    let attachment_id = service
        .attach_file(credential.id, &file_path, false)
        .await
        .unwrap();

    let listed = service.get_attachments(&credential.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, attachment_id);

    let content = service
        .retrieve_attachment(&attachment_id, false)
        .await
        .unwrap();
    assert_eq!(content, b"attachment-bytes");

    let out_path = dir.path().join("restored.txt");
    service
        .save_attachment(&attachment_id, &out_path, false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&out_path).unwrap(), b"attachment-bytes");

    let stats = service.get_attachment_stats().await.unwrap();
    assert_eq!(stats.total_attachments, 1);

    service.delete_attachment(&attachment_id).await.unwrap();
    assert!(service
        .get_attachments(&credential.id)
        .await
        .unwrap()
        .is_empty());

    // Retrieving a deleted attachment surfaces the missing-file error.
    assert!(service
        .retrieve_attachment(&attachment_id, false)
        .await
        .is_err());
}

#[tokio::test]
async fn test_attachment_encrypted_store_marks_and_scrambles_content() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Encrypted Attach".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "enc attach",
        CredentialType::Password,
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("secret.bin");
    std::fs::write(&file_path, b"top-secret-bytes").unwrap();

    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    let listed = service.get_attachments(&credential.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, attachment_id);
    assert!(listed[0].is_encrypted);

    // Without the decrypt flag the raw ciphertext comes back untouched.
    let raw = service
        .retrieve_attachment(&attachment_id, false)
        .await
        .unwrap();
    assert_ne!(raw, b"top-secret-bytes".to_vec());

    // The attachment is sealed under the credential's per-item key, so
    // decrypting through the service yields the original bytes.
    let plain = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap();
    assert_eq!(plain, b"top-secret-bytes".to_vec());

    // Saving with decrypt=false still writes the stored bytes to disk.
    let out_path = dir.path().join("raw-copy.bin");
    service
        .save_attachment(&attachment_id, &out_path, false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&out_path).unwrap(), raw);
}

/// Core guarantee of encrypted attachments reusing the credential item key: attachments remain
/// decryptable after a master password change (rewrap).
/// Rotation only re-wraps wrapped_item_key; the item key itself is unchanged, so the blob does not
/// need rewriting.
#[tokio::test]
async fn encrypted_attachment_survives_master_password_rotation() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Rotation Attach".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity.id,
        "rot attach",
        CredentialType::Password,
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("doc.txt");
    std::fs::write(&file_path, b"survive-rotation-payload").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    service
        .change_master_password("master-pin", "master-pin-2")
        .await
        .unwrap();

    let plain = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap();
    assert_eq!(plain, b"survive-rotation-payload".to_vec());

    // The credential body is still decryptable too (an existing promise of the change transaction); a regression guard
    let data = service.get_credential_data(&credential.id).await.unwrap();
    assert!(data.is_some());
}

/// A legacy credential (wrapped_item_key NULL) is upgraded to a per-item key when it first gets an
/// encrypted attachment: after the upgrade the credential payload is still readable, the row gains
/// a wrapped key, and the attachment round-trips decryptable.
#[tokio::test]
async fn attach_upgrades_legacy_credential_to_item_key() {
    let (db, mut service) = unlocked_service().await;

    let identity = service
        .create_identity("Legacy Attach".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // Build the legacy row by hand: encrypted_data sealed directly with the master key, no wrapped key
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
        "legacy row".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        sealed,
        None,
    );
    let credentials = crate::storage::CredentialRepository::new(db.clone());
    credentials.create(&credential).await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db)
        .await
        .unwrap();

    let file_path = dir.path().join("legacy-attach.bin");
    std::fs::write(&file_path, b"legacy-attachment-bytes").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    // After the upgrade: the row has a wrapped key, the credential data decrypts back to the original value, and the attachment round-trips
    let upgraded = service
        .get_credential(&credential.id)
        .await
        .unwrap()
        .unwrap();
    assert!(upgraded.wrapped_item_key.is_some());

    let data = service
        .get_credential_data(&credential.id)
        .await
        .unwrap()
        .unwrap();
    match data {
        CredentialData::Password(p) => assert_eq!(p.password, "legacy-pw"),
        other => panic!("unexpected credential data: {other:?}"),
    }

    let plain = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap();
    assert_eq!(plain, b"legacy-attachment-bytes".to_vec());
}

/// Three defenses on the retrieve_attachment decryption path: metadata pointing at a deleted
/// credential, a legacy row missing its per-item key, and a corrupted wrapped key — all fail-closed.
#[tokio::test]
async fn retrieve_attachment_decrypt_defensive_arms() {
    let (db, mut service) = unlocked_service().await;
    let identity = service
        .create_identity("Attach Arms".into(), IdentityType::Personal)
        .await
        .unwrap();
    let credential =
        seed_credential(&service, identity.id, "with file", CredentialType::Password).await;

    let dir = tempfile::tempdir().unwrap();
    service
        .init_attachment_storage(dir.path(), db.clone())
        .await
        .unwrap();

    let file_path = dir.path().join("secret.bin");
    std::fs::write(&file_path, b"attachment-bytes").unwrap();
    let attachment_id = service
        .attach_file(credential.id, &file_path, true)
        .await
        .unwrap();

    // ① metadata's credential_id points at a deleted credential. At runtime an orphan row comes
    // from the "blob cleanup failure on credential deletion only warns" path; an FK would not let
    // it be constructed directly, so the test briefly bypasses it with a connection-level PRAGMA
    // (restored right after, returned to the pool).
    let orphan = Uuid::new_v4().to_string();
    {
        let mut conn = db.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("UPDATE attachments SET credential_id = ? WHERE id = ?")
            .bind(&orphan)
            .bind(attachment_id.to_string())
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let err = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not found for attachment"),
        "{err}"
    );

    // ② A legacy row (no per-item key) cannot decrypt a sealed attachment
    sqlx::query("UPDATE attachments SET credential_id = ? WHERE id = ?")
        .bind(credential.id.to_string())
        .bind(attachment_id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET wrapped_item_key = NULL WHERE id = ?")
        .bind(credential.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("predates item-key sealing"),
        "{err}"
    );

    // ③ Corrupted wrapped key -> unwrap fails
    sqlx::query("UPDATE credentials SET wrapped_item_key = ? WHERE id = ?")
        .bind(vec![0u8, 1, 2, 3, 4, 5, 6, 7])
        .bind(credential.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let err = service
        .retrieve_attachment(&attachment_id, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Failed to unwrap item key"),
        "{err}"
    );
}
