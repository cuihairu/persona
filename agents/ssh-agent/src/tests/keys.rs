use super::*;

#[test]
fn load_test_key_from_env_covers_all_paths() {
    let _guard = env_lock();
    clear_test_key_env();
    let mut agent = Agent::default();

    // No env var -> no key, no error.
    assert!(!agent.load_test_key_from_env().unwrap());
    assert!(agent.keys.is_empty());

    // Malformed base64 -> error.
    std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", "!!!not base64!!!");
    assert!(agent.load_test_key_from_env().is_err());

    // Wrong size payload -> error.
    std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(b"short"));
    assert!(agent.load_test_key_from_env().is_err());

    // Valid 32-byte seed -> key loaded with optional comment override.
    let seed = [7u8; 32];
    std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));
    assert!(agent.load_test_key_from_env().unwrap());
    assert_eq!(agent.keys.len(), 1);
    assert_eq!(agent.keys[0].comment, "Test Key");
    assert_eq!(key_seed(&agent.keys[0]), seed);

    std::env::set_var("PERSONA_AGENT_TEST_KEY_COMMENT", "custom comment");
    assert!(agent.load_test_key_from_env().unwrap());
    assert_eq!(agent.keys.len(), 2);
    assert_eq!(agent.keys[1].comment, "custom comment");

    clear_test_key_env();
}

#[tokio::test]
async fn load_keys_from_persona_test_env_override_short_circuits() {
    let _guard = env_lock();
    clear_test_key_env();
    let seed = [11u8; 32];
    std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));

    let mut agent = Agent::default();
    let bogus_path = PathBuf::from("/nonexistent/dir/identities.db");
    agent.load_keys_from_persona(&bogus_path).await.unwrap();
    assert_eq!(agent.keys.len(), 1);
    assert_eq!(key_seed(&agent.keys[0]), seed);

    clear_test_key_env();
}

#[tokio::test]
async fn load_keys_from_persona_missing_db_parent_errors() {
    let _guard = env_lock();
    clear_test_key_env();

    let dir = tempfile::tempdir().unwrap();
    // Parent directory does not exist -> Database::from_file cannot create it.
    let db_path = dir.path().join("no-such-dir").join("identities.db");
    let mut agent = Agent::default();
    assert!(agent.load_keys_from_persona(&db_path).await.is_err());
}

#[tokio::test]
async fn load_keys_from_persona_loads_valid_ssh_credential() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let identity = service
        .create_identity(
            "agent-test".to_string(),
            persona_core::models::IdentityType::Personal,
        )
        .await
        .unwrap();

    let seed = [21u8; 32];
    let (pub_line, pub_blob) = openssh_pub_line(seed);
    let cred = service
        .create_credential(
            identity.id,
            "my ssh key".to_string(),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &ssh_credential_data(seed, &pub_line),
        )
        .await
        .unwrap();

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert_eq!(agent.keys.len(), 1);
    let loaded = &agent.keys[0];
    assert_eq!(loaded.comment, "my ssh key");
    assert_eq!(key_seed(loaded), seed);
    assert_eq!(loaded.public_blob, pub_blob);
    assert_eq!(loaded.identity_id, identity.id);
    assert_eq!(loaded.credential_id, cred.id);
}

#[tokio::test]
async fn load_keys_from_persona_identity_filter_loads_only_matching_identity() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let a = seed_identity_ssh_key(&mut service, "agent-a", [51u8; 32]).await;
    let b = seed_identity_ssh_key(&mut service, "agent-b", [52u8; 32]).await;

    std::env::set_var("PERSONA_AGENT_IDENTITY", "agent-b");
    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_AGENT_IDENTITY");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert_eq!(
        agent.keys.len(),
        1,
        "only the filtered identity's key loads"
    );
    assert_eq!(agent.keys[0].identity_id, b);
    assert_ne!(agent.keys[0].identity_id, a);
    assert_eq!(key_seed(&agent.keys[0]), [52u8; 32]);
}

#[tokio::test]
async fn load_keys_from_persona_identity_filter_unknown_name_loads_nothing() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    seed_identity_ssh_key(&mut service, "agent-a", [53u8; 32]).await;

    // 过滤器失配 = 不加载任何密钥（fail-closed），绝不回落全量。
    std::env::set_var("PERSONA_AGENT_IDENTITY", "ghost");
    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_AGENT_IDENTITY");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert!(agent.keys.is_empty());
}

#[tokio::test]
async fn load_keys_from_persona_skips_invalid_seed_and_pubkey() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let identity = service
        .create_identity(
            "agent-test".to_string(),
            persona_core::models::IdentityType::Personal,
        )
        .await
        .unwrap();

    // Bad seed size (not 32 bytes) — neither seed nor PEM → skipped.
    let bad_seed = persona_core::models::CredentialData::SshKey(persona_core::models::SshKeyData {
        private_key: BASE64.encode(b"too short"),
        public_key: "ssh-ed25519 AAAA".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    });
    service
        .create_credential(
            identity.id,
            "bad seed".to_string(),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &bad_seed,
        )
        .await
        .unwrap();

    // Malformed public key text with a valid private key: the agent
    // rebuilds the public blob from the private key so the key stays usable.
    let bad_pub = persona_core::models::CredentialData::SshKey(persona_core::models::SshKeyData {
        private_key: BASE64.encode([32u8; 32]),
        public_key: "not-a-valid-key-line".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    });
    service
        .create_credential(
            identity.id,
            "bad pubkey".to_string(),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &bad_pub,
        )
        .await
        .unwrap();

    // A valid one to prove loading still works after skips.
    let seed = [41u8; 32];
    let (pub_line, _) = openssh_pub_line(seed);
    service
        .create_credential(
            identity.id,
            "good".to_string(),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &ssh_credential_data(seed, &pub_line),
        )
        .await
        .unwrap();

    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert_eq!(agent.keys.len(), 2, "bad seed skipped; bad pubkey rebuilt");
    // 加载顺序不承诺与入库顺序一致，按条目名定位
    let rebuilt = agent
        .keys
        .iter()
        .find(|k| k.comment == "bad pubkey")
        .expect("bad pubkey credential rebuilt from its private key");
    assert_eq!(
        public_key_algorithm(&rebuilt.public_blob).as_deref(),
        Some("ssh-ed25519"),
        "rebuilt blob carries the right algorithm"
    );
    let good = agent
        .keys
        .iter()
        .find(|k| k.comment == "good")
        .expect("valid credential loads");
    assert_eq!(key_seed(good), seed);
}

#[tokio::test]
async fn load_keys_from_persona_locked_vault_loads_nothing() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();

    // Vault has users but no PERSONA_MASTER_PASSWORD: fail closed, no keys.
    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert!(agent.keys.is_empty());

    // Wrong password also loads nothing.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert!(agent.keys.is_empty());
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

// ------------------------------------------------------------------
// sign_response policy branches
// ------------------------------------------------------------------

#[tokio::test]
async fn load_keys_from_persona_locked_vault_and_mismatched_type() {
    let _guard = env_lock();
    clear_test_key_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("identities.db");
    let db = persona_core::Database::from_file(&db_path).await.unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let identity = service
        .create_identity(
            "locked-vault".to_string(),
            persona_core::models::IdentityType::Personal,
        )
        .await
        .unwrap();

    // A vault with users but no PERSONA_MASTER_PASSWORD loads nothing.
    let mut agent = Agent::default();
    agent.load_keys_from_persona(&db_path).await.unwrap();
    assert!(agent.keys.is_empty());

    // An unlocked vault with a credential typed SshKey whose payload is
    // not SSH key material is skipped as well.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    let mismatched = persona_core::models::CredentialData::Password(
        persona_core::models::PasswordCredentialData {
            password: "not-an-ssh-key".to_string(),
            email: None,
            security_questions: vec![],
        },
    );
    service
        .create_credential(
            identity.id,
            "mismatched".to_string(),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &mismatched,
        )
        .await
        .unwrap();

    agent.load_keys_from_persona(&db_path).await.unwrap();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    assert!(agent.keys.is_empty());
}

// ------------------------------------------------------------------
// OpenSSH PEM entries (imported keys): load + sign per algorithm
