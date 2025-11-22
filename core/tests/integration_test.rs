use persona_core::*;
use tempfile::tempdir;
/// End-to-end integration test for the core Persona functionality
#[tokio::test]
async fn test_complete_identity_workflow() -> Result<()> {
    // Create a temporary directory for the test database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_persona.db");

    // Step 1: Initialize database and service
    let db = Database::from_file(&db_path).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;

    // Step 2: Initialize first-time user
    let master_password = "test_master_password_123";
    let user_id = service.initialize_user(master_password).await?;

    assert!(service.is_unlocked());
    println!("✓ User initialized with ID: {}", user_id);

    // Step 3: Create an identity
    let identity = service
        .create_identity("Test Identity".to_string(), IdentityType::Personal)
        .await?;

    assert_eq!(identity.name, "Test Identity");
    assert_eq!(identity.identity_type, IdentityType::Personal);
    assert!(identity.is_active);
    println!("✓ Identity created: {}", identity.name);

    // Step 4: Create a password credential
    let password_data = CredentialData::Password(PasswordCredentialData {
        password: "test_password_123".to_string(),
        email: Some("test@example.com".to_string()),
        security_questions: vec![],
    });

    let credential = service
        .create_credential(
            identity.id,
            "Test Website".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &password_data,
        )
        .await?;

    assert_eq!(credential.name, "Test Website");
    assert_eq!(credential.credential_type, CredentialType::Password);
    assert_eq!(credential.security_level, SecurityLevel::High);
    println!("✓ Credential created: {}", credential.name);

    // Step 5: Retrieve and decrypt the credential
    let retrieved_data = service.get_credential_data(&credential.id).await?;
    assert!(retrieved_data.is_some());

    if let Some(CredentialData::Password(pwd_data)) = retrieved_data {
        assert_eq!(pwd_data.password, "test_password_123");
        assert_eq!(pwd_data.email, Some("test@example.com".to_string()));
        println!("✓ Credential decrypted successfully");
    } else {
        panic!("Failed to decrypt credential or wrong type");
    }

    // Step 6: Search credentials
    let search_results = service.search_credentials("Test").await?;
    assert_eq!(search_results.len(), 1);
    assert_eq!(search_results[0].id, credential.id);
    println!("✓ Search functionality works");

    // Step 7: Get statistics
    let stats = service.get_statistics().await?;
    assert_eq!(stats.total_identities, 1);
    assert_eq!(stats.total_credentials, 1);
    assert_eq!(stats.active_credentials, 1);
    println!(
        "✓ Statistics: {} identities, {} credentials",
        stats.total_identities, stats.total_credentials
    );

    // Step 8: Test locking and unlocking
    service.lock();
    assert!(!service.is_unlocked());
    println!("✓ Service locked successfully");

    // For unlock test, we would need the stored salt - this is a limitation of current implementation
    // In a complete implementation, the salt would be retrieved from the database
    println!("✓ All tests passed!");

    Ok(())
}

/// Test credential data encryption/decryption
#[tokio::test]
async fn test_credential_encryption() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_encryption.db");

    let db = Database::from_file(&db_path).await?;
    db.migrate().await?;

    let mut service = PersonaService::new(db).await?;
    let _user_id = service.initialize_user("encryption_test_password").await?;

    // Create identity
    let identity = service
        .create_identity("Encryption Test".to_string(), IdentityType::Work)
        .await?;

    // Test different credential types
    let test_cases = vec![
        (
            "Password Test",
            CredentialData::Password(PasswordCredentialData {
                password: "super_secret_password".to_string(),
                email: Some("work@company.com".to_string()),
                security_questions: vec![],
            }),
            CredentialType::Password,
        ),
        (
            "API Key Test",
            CredentialData::ApiKey(ApiKeyData {
                api_key: "sk-1234567890abcdef".to_string(),
                api_secret: Some("secret_key_here".to_string()),
                token: None,
                permissions: vec!["read".to_string(), "write".to_string()],
                expires_at: None,
            }),
            CredentialType::ApiKey,
        ),
    ];

    for (name, data, cred_type) in test_cases {
        // Create credential
        let credential = service
            .create_credential(
                identity.id,
                name.to_string(),
                cred_type,
                SecurityLevel::Critical,
                &data,
            )
            .await?;

        // Retrieve and verify
        let retrieved = service
            .get_credential_data(&credential.id)
            .await?
            .expect("Failed to retrieve credential data");

        match (&data, &retrieved) {
            (CredentialData::Password(original), CredentialData::Password(decrypted)) => {
                assert_eq!(original.password, decrypted.password);
                assert_eq!(original.email, decrypted.email);
            }
            (CredentialData::ApiKey(original), CredentialData::ApiKey(decrypted)) => {
                assert_eq!(original.api_key, decrypted.api_key);
                assert_eq!(original.api_secret, decrypted.api_secret);
            }
            _ => panic!("Credential type mismatch after encryption/decryption"),
        }

        println!("✓ Encryption/decryption test passed for: {}", name);
    }

    Ok(())
}

/// Test error handling and edge cases
#[tokio::test]
async fn test_error_handling() -> Result<()> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_errors.db");

    let db = Database::from_file(&db_path).await?;
    db.migrate().await?;

    let service = PersonaService::new(db).await?;

    // Test operations on locked service
    let result = service.get_identities().await;
    assert!(result.is_err());
    println!("✓ Locked service properly rejects operations");

    // Test credential operations without identity
    // This would require unlocking the service first, so we'll skip for now

    println!("✓ Error handling tests passed");
    Ok(())
}
