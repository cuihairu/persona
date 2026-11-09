use super::*;

#[tokio::test]
async fn test_persona_service_basic_operations() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db).await.unwrap();
    let salt = service.generate_salt();

    // Test unlock/lock
    assert!(!service.is_unlocked());
    service.unlock("test_password", &salt).unwrap();
    assert!(service.is_unlocked());

    // Create identity
    let identity = service
        .create_identity("Test Identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // Create credential
    let password_data = CredentialData::Password(PasswordCredentialData {
        password: "secret123".to_string(),
        email: Some("test@example.com".to_string()),
        security_questions: vec![],
    });

    let credential = service
        .create_credential(
            identity.id,
            "Test Account".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &password_data,
        )
        .await
        .unwrap();

    // Retrieve and decrypt credential
    let retrieved_data = service.get_credential_data(&credential.id).await.unwrap();
    assert!(retrieved_data.is_some());

    if let Some(CredentialData::Password(pwd_data)) = retrieved_data {
        assert_eq!(pwd_data.password, "secret123");
        assert_eq!(pwd_data.email, Some("test@example.com".to_string()));
    } else {
        panic!("Expected password credential data");
    }
}

#[tokio::test]
async fn test_export_identity_and_statistics() {
    let (_db, service) = unlocked_service().await;

    let identity = service
        .create_identity("Export Target".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let first = seed_credential(&service, identity.id, "GitHub", CredentialType::Password).await;
    seed_credential(&service, identity.id, "API", CredentialType::ApiKey).await;

    let mut favorite = first.clone();
    favorite.is_favorite = true;
    service.update_credential(&favorite).await.unwrap();

    let export = service.export_identity(&identity.id).await.unwrap();
    assert_eq!(export.identity.id, identity.id);
    assert_eq!(export.credentials.len(), 2);

    // Unknown identity -> IdentityNotFound.
    let err = service
        .export_identity(&Uuid::new_v4())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not found"), "unexpected error: {}", err);

    let stats = service.get_statistics().await.unwrap();
    assert_eq!(stats.total_identities, 1);
    assert_eq!(stats.total_credentials, 2);
    assert_eq!(stats.active_credentials, 2);
    assert_eq!(stats.favorite_credentials, 1);
    assert_eq!(stats.credential_types.values().sum::<u32>(), 2);
    assert_eq!(stats.security_levels.values().sum::<u32>(), 2);
}

#[tokio::test]
async fn test_identity_and_credential_crud() {
    let (_db, service) = unlocked_service().await;

    // create_identity_full stores the pre-populated identity.
    let mut identity = Identity::new("Full Identity".to_string(), IdentityType::Work);
    identity.email = Some("work@example.com".to_string());
    let created = service.create_identity_full(identity).await.unwrap();
    assert_eq!(created.email.as_deref(), Some("work@example.com"));

    // Rename and persist.
    let mut renamed = created.clone();
    renamed.name = "Renamed Identity".to_string();
    let updated = service.update_identity(&renamed).await.unwrap();
    assert_eq!(updated.name, "Renamed Identity");

    let fetched = service.get_identity(&created.id).await.unwrap().unwrap();
    assert_eq!(fetched.name, "Renamed Identity");

    // Credential lifecycle: not-found delete reports false, then a real delete.
    assert!(!service.delete_credential(&Uuid::new_v4()).await.unwrap());

    let identity2 = service
        .create_identity("Cred Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credential = seed_credential(
        &service,
        identity2.id,
        "to delete",
        CredentialType::Password,
    )
    .await;

    let mut edited = credential.clone();
    edited.name = "renamed cred".to_string();
    service.update_credential(&edited).await.unwrap();
    assert_eq!(
        service
            .get_credential(&credential.id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "renamed cred"
    );

    assert!(service.delete_credential(&credential.id).await.unwrap());
    assert!(!service.delete_credential(&credential.id).await.unwrap());

    // Deleting an identity with no leftover credentials succeeds.
    assert!(service.delete_identity(&identity2.id).await.unwrap());
    assert!(!service.delete_identity(&identity2.id).await.unwrap());
}

#[tokio::test]
async fn test_get_credential_data_legacy_and_error_paths() {
    let (db, service) = unlocked_service().await;

    // Unknown id → Ok(None), never an error.
    assert!(service
        .get_credential_data(&Uuid::new_v4())
        .await
        .unwrap()
        .is_none());

    let identity = service
        .create_identity("Legacy Owner".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let credentials = crate::storage::CredentialRepository::new(db.clone());

    let plaintext = CredentialData::Password(PasswordCredentialData {
        password: "legacy-secret".to_string(),
        email: None,
        security_questions: vec![],
    })
    .to_bytes()
    .unwrap();

    // Legacy format: sealed directly with the master key, no wrapped item key.
    let ciphertext = service
        .get_master_encryption_service()
        .unwrap()
        .encrypt(&plaintext)
        .unwrap();
    let legacy = Credential::new(
        identity.id,
        "Legacy".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        ciphertext,
        None,
    );
    credentials.create(&legacy).await.unwrap();

    let data = service
        .get_credential_data(&legacy.id)
        .await
        .unwrap()
        .expect("legacy credential must decrypt");
    match data {
        CredentialData::Password(pwd) => assert_eq!(pwd.password, "legacy-secret"),
        other => panic!("expected password credential data, got {:?}", other),
    }

    // The lookup stamps last_accessed via the repository update.
    let stored = credentials.find_by_id(&legacy.id).await.unwrap().unwrap();
    assert!(stored.last_accessed.is_some());

    // Legacy ciphertext that does not decrypt surfaces the legacy error.
    let broken = Credential::new(
        identity.id,
        "Broken Legacy".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        vec![7u8; 64],
        None,
    );
    credentials.create(&broken).await.unwrap();
    let err = service
        .get_credential_data(&broken.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Failed to decrypt legacy credential"),
        "unexpected error: {}",
        err
    );

    // A validly sealed envelope whose plaintext is not CredentialData
    // surfaces the deserialization error. Four zero bytes decode to the
    // Password variant and then run out of input for the payload.
    let hierarchy =
        crate::crypto::KeyHierarchy::new(service.get_master_encryption_service().unwrap());
    let envelope = hierarchy.encrypt_with_new_item_key(&[0u8; 4]).unwrap();
    let garbage = Credential::new(
        identity.id,
        "Garbage".to_string(),
        CredentialType::Password,
        SecurityLevel::Medium,
        envelope.ciphertext,
        Some(envelope.wrapped_key),
    );
    credentials.create(&garbage).await.unwrap();
    let err = service
        .get_credential_data(&garbage.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Failed to deserialize credential data"),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_get_identity_by_name_and_id_record_audit() {
    let (db, service) = unlocked_service().await;
    let created = service
        .create_identity("audited-identity".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    let by_name = service
        .get_identity_by_name("audited-identity")
        .await
        .unwrap()
        .expect("identity found by name");
    assert_eq!(by_name.id, created.id);

    let by_id = service
        .get_identity(&created.id)
        .await
        .unwrap()
        .expect("identity found by id");
    assert_eq!(by_id.id, created.id);

    let missing = service
        .get_identity_by_name("no-such-identity")
        .await
        .unwrap();
    assert!(missing.is_none());

    // Two IdentityViewed audit entries were recorded for the found reads.
    let repo = crate::storage::AuditLogRepository::new(db.clone());
    let logs = repo
        .find_by_action(&AuditAction::IdentityViewed)
        .await
        .unwrap();
    assert_eq!(logs.len(), 2);
}

#[tokio::test]
async fn test_get_credentials_for_identity_lists_seed() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("cred-listing".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    seed_credential(&service, identity.id, "listed", CredentialType::Password).await;

    let creds = service
        .get_credentials_for_identity(&identity.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name, "listed");
}

#[tokio::test]
async fn test_get_identities_surface_and_unknown_identity_returns_none() {
    let (_db, service) = unlocked_service().await;
    let created = service
        .create_identity("listed-surface".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    // get_identities lists everything, including the fresh identity.
    let all = service.get_identities().await.unwrap();
    assert!(all.iter().any(|i| i.id == created.id));

    // A lookup by an unknown id yields None without an audit entry.
    assert!(service
        .get_identity(&Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_create_passkey_full_preserves_supplied_user_handle() {
    let (_db, service) = unlocked_service().await;
    let identity = service
        .create_identity("handle-full".to_string(), IdentityType::Personal)
        .await
        .unwrap();

    let client_data =
        br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#;
    let handle = vec![1u8, 2, 3, 4];
    let creation = service
        .create_passkey_full(
            identity.id,
            "example.com".to_string(),
            "https://example.com",
            client_data,
            Some(handle.clone()),
            Some("alice@example.com".to_string()),
            None,
            false,
        )
        .await
        .unwrap();

    // The caller-supplied handle is stored verbatim instead of a random one.
    assert_eq!(creation.item.user_handle, handle);
    assert_eq!(
        creation.item.user_name.as_deref(),
        Some("alice@example.com")
    );
    assert!(!creation.item.uv_initialized);
    assert!(!creation.attestation_object.is_empty());
}
