use persona_core::*;
use std::collections::HashMap;

/// Integration tests for the Persona core library
#[tokio::test]
async fn test_full_persona_workflow() {
    // Initialize database and service
    let db = Database::in_memory().await.expect("Failed to create database");
    db.migrate().await.expect("Failed to run migrations");

    let mut service = PersonaService::new(db).await.expect("Failed to create service");

    // Test service is initially locked
    assert!(!service.is_unlocked());

    // Generate salt and unlock service
    let salt = service.generate_salt();
    service.unlock("super_secret_password", &salt).expect("Failed to unlock service");
    assert!(service.is_unlocked());

    // Create personal identity
    let personal_identity = service.create_identity(
        "John Doe".to_string(),
        IdentityType::Personal,
    ).await.expect("Failed to create personal identity");

    // Create work identity
    let work_identity = service.create_identity(
        "John Doe (Work)".to_string(),
        IdentityType::Work,
    ).await.expect("Failed to create work identity");

    // Verify identities were created
    let identities = service.get_identities().await.expect("Failed to get identities");
    assert_eq!(identities.len(), 2);

    // Create password credential
    let password_data = CredentialData::Password(PasswordCredentialData {
        password: "secure_password_123".to_string(),
        email: Some("john.doe@example.com".to_string()),
        security_questions: vec![
            SecurityQuestion {
                question: "What was your first pet's name?".to_string(),
                answer: "Fluffy".to_string(),
            }
        ],
    });

    let password_credential = service.create_credential(
        personal_identity.id,
        "Email Account".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        &password_data,
    ).await.expect("Failed to create password credential");

    // Create crypto wallet credential
    let wallet_data = CredentialData::CryptoWallet(CryptoWalletData {
        wallet_type: "Bitcoin".to_string(),
        mnemonic_phrase: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        private_key: Some("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ".to_string()),
        public_key: "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd".to_string(),
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        network: "mainnet".to_string(),
    });

    let wallet_credential = service.create_credential(
        personal_identity.id,
        "Bitcoin Wallet".to_string(),
        CredentialType::CryptoWallet,
        SecurityLevel::Critical,
        &wallet_data,
    ).await.expect("Failed to create wallet credential");

    // Create SSH key credential
    let ssh_data = CredentialData::SshKey(SshKeyData {
        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA...".to_string(),
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbPhGn... user@example.com".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: Some("key_passphrase".to_string()),
    });

    let ssh_credential = service.create_credential(
        work_identity.id,
        "Work Server".to_string(),
        CredentialType::SshKey,
        SecurityLevel::High,
        &ssh_data,
    ).await.expect("Failed to create SSH credential");

    // Test credential retrieval and decryption
    let retrieved_password = service.get_credential_data(&password_credential.id)
        .await.expect("Failed to get password credential");

    match retrieved_password {
        Some(CredentialData::Password(pwd_data)) => {
            assert_eq!(pwd_data.password, "secure_password_123");
            assert_eq!(pwd_data.email, Some("john.doe@example.com".to_string()));
            assert_eq!(pwd_data.security_questions.len(), 1);
        }
        _ => panic!("Expected password credential data"),
    }

    // Test wallet credential
    let retrieved_wallet = service.get_credential_data(&wallet_credential.id)
        .await.expect("Failed to get wallet credential");

    match retrieved_wallet {
        Some(CredentialData::CryptoWallet(wallet_data)) => {
            assert_eq!(wallet_data.wallet_type, "Bitcoin");
            assert_eq!(wallet_data.address, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        }
        _ => panic!("Expected wallet credential data"),
    }

    // Test credentials for identity
    let personal_credentials = service.get_credentials_for_identity(&personal_identity.id)
        .await.expect("Failed to get personal credentials");
    assert_eq!(personal_credentials.len(), 2);

    let work_credentials = service.get_credentials_for_identity(&work_identity.id)
        .await.expect("Failed to get work credentials");
    assert_eq!(work_credentials.len(), 1);

    // Test search functionality
    let email_results = service.search_credentials("Email")
        .await.expect("Failed to search credentials");
    assert_eq!(email_results.len(), 1);
    assert_eq!(email_results[0].name, "Email Account");

    // Test credentials by type
    let password_credentials = service.get_credentials_by_type(&CredentialType::Password)
        .await.expect("Failed to get password credentials");
    assert_eq!(password_credentials.len(), 1);

    let crypto_credentials = service.get_credentials_by_type(&CredentialType::CryptoWallet)
        .await.expect("Failed to get crypto credentials");
    assert_eq!(crypto_credentials.len(), 1);

    // Test identity export
    let export = service.export_identity(&personal_identity.id)
        .await.expect("Failed to export identity");
    assert_eq!(export.identity.id, personal_identity.id);
    assert_eq!(export.credentials.len(), 2);

    // Test statistics
    let stats = service.get_statistics()
        .await.expect("Failed to get statistics");
    assert_eq!(stats.total_identities, 2);
    assert_eq!(stats.total_credentials, 3);
    assert_eq!(stats.active_credentials, 3);

    // Test lock/unlock cycle
    service.lock();
    assert!(!service.is_unlocked());

    // Should fail when locked
    let locked_result = service.get_identities().await;
    assert!(locked_result.is_err());

    // Unlock again
    service.unlock("super_secret_password", &salt).expect("Failed to unlock service again");
    assert!(service.is_unlocked());

    // Should work again
    let identities_after_unlock = service.get_identities()
        .await.expect("Failed to get identities after unlock");
    assert_eq!(identities_after_unlock.len(), 2);
}

#[tokio::test]
async fn test_identity_management() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();

    // Test identity creation with different types
    let personal = service.create_identity("Personal".to_string(), IdentityType::Personal).await.unwrap();
    let work = service.create_identity("Work".to_string(), IdentityType::Work).await.unwrap();
    let gaming = service.create_identity("Gaming".to_string(), IdentityType::Gaming).await.unwrap();

    // Test get by type
    let personal_identities = service.get_identities_by_type(&IdentityType::Personal).await.unwrap();
    assert_eq!(personal_identities.len(), 1);
    assert_eq!(personal_identities[0].name, "Personal");

    let work_identities = service.get_identities_by_type(&IdentityType::Work).await.unwrap();
    assert_eq!(work_identities.len(), 1);

    // Test identity update
    let mut updated_personal = personal.clone();
    updated_personal.add_tag("primary".to_string());
    updated_personal.set_attribute("theme".to_string(), "dark".to_string());

    let result = service.update_identity(&updated_personal).await.unwrap();
    assert!(result.tags.contains(&"primary".to_string()));
    assert_eq!(result.get_attribute("theme"), Some(&"dark".to_string()));

    // Test identity deletion
    let deleted = service.delete_identity(&gaming.id).await.unwrap();
    assert!(deleted);

    let remaining = service.get_identities().await.unwrap();
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn test_credential_security_levels() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();

    let mut service = PersonaService::new(db).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();

    let identity = service.create_identity("Test".to_string(), IdentityType::Personal).await.unwrap();

    // Create credentials with different security levels
    let low_security = service.create_credential(
        identity.id,
        "Social Media".to_string(),
        CredentialType::Password,
        SecurityLevel::Low,
        &CredentialData::Raw(b"low_security_data".to_vec()),
    ).await.unwrap();

    let high_security = service.create_credential(
        identity.id,
        "Bank Account".to_string(),
        CredentialType::BankCard,
        SecurityLevel::Critical,
        &CredentialData::Raw(b"critical_data".to_vec()),
    ).await.unwrap();

    // Verify security levels are stored correctly
    let low_cred = service.get_credential(&low_security.id).await.unwrap().unwrap();
    assert_eq!(low_cred.security_level, SecurityLevel::Low);

    let high_cred = service.get_credential(&high_security.id).await.unwrap().unwrap();
    assert_eq!(high_cred.security_level, SecurityLevel::Critical);

    // Test statistics include security level breakdown
    let stats = service.get_statistics().await.unwrap();
    assert_eq!(*stats.security_levels.get("Low").unwrap(), 1);
    assert_eq!(*stats.security_levels.get("Critical").unwrap(), 1);
}

#[test]
fn test_crypto_operations() {
    // Test encryption service
    let key = EncryptionService::generate_key();
    let service = EncryptionService::new(&key);

    let plaintext = b"sensitive data";
    let encrypted = service.encrypt(plaintext).unwrap();
    let decrypted = service.decrypt(&encrypted).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());

    // Test secure string
    let secure = SecureString::from_string("secret".to_string());
    assert_eq!(secure.len(), 6);
    assert!(!secure.is_empty());

    // Test password hashing
    let hasher = PasswordHasher::new();
    let password = "test_password";
    let hash = hasher.hash_password(password).unwrap();
    assert!(hasher.verify_password(password, &hash).unwrap());
    assert!(!hasher.verify_password("wrong_password", &hash).unwrap());

    // Test key derivation
    let salt = KeyDerivation::generate_salt();
    let key1 = KeyDerivation::derive_key_pbkdf2(password, &salt, 10000);
    let key2 = KeyDerivation::derive_key_pbkdf2(password, &salt, 10000);
    assert_eq!(key1, key2);
}

#[test]
fn test_signing_operations() {
    // Test signing key pair
    let keypair = SigningKeyPair::generate();
    let message = b"important message";

    let signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature).is_ok());

    let wrong_message = b"wrong message";
    assert!(keypair.verify(wrong_message, &signature).is_err());

    // Test public key verification
    let public_key_bytes = keypair.public_key_bytes();
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
    assert!(verifying_key.verify(message, &signature).is_ok());
}

#[test]
fn test_password_generation() {
    let db = Database::in_memory().await.unwrap();
    let mut service = PersonaService::new(db).await.unwrap();

    // Test password generation
    let password1 = service.generate_password(12, false);
    let password2 = service.generate_password(12, false);
    let password_with_symbols = service.generate_password(16, true);

    assert_eq!(password1.len(), 12);
    assert_eq!(password2.len(), 12);
    assert_eq!(password_with_symbols.len(), 16);
    assert_ne!(password1, password2); // Should be different

    // Test character sets
    assert!(!password1.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
    // password_with_symbols may contain symbols (though not guaranteed in a short string)
}