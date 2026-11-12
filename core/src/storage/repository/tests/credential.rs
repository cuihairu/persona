use super::*;

#[tokio::test]
async fn credential_repository_crud_and_queries() {
    let db = test_db().await;
    // credentials.identity_id has an FK to identities; seed the parent first.
    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("cred owner"))
        .await
        .unwrap();
    let repo = CredentialRepository::new(db);

    let identity_id = identities.find_all().await.unwrap()[0].id;
    let mut cred = sample_credential(identity_id, "Repo credential");
    cred.username = Some("user".to_string());
    cred.url = Some("https://example.com".to_string());
    cred.notes = Some("note".to_string());
    cred.tags = vec!["work".to_string()];
    cred.metadata.insert("env".to_string(), "test".to_string());

    repo.create(&cred).await.unwrap();
    assert!(repo.create(&cred).await.is_err()); // PK conflict

    let fetched = repo.find_by_id(&cred.id).await.unwrap().unwrap();
    assert_eq!(fetched.name, "Repo credential");
    assert_eq!(fetched.username.as_deref(), Some("user"));
    assert_eq!(fetched.tags, vec!["work".to_string()]);
    assert_eq!(
        fetched.metadata.get("env").map(String::as_str),
        Some("test")
    );

    // Every enum variant round-trips through the stored string form.
    for (name, variant) in [
        ("BankCard", CredentialType::BankCard),
        ("GameAccount", CredentialType::GameAccount),
        ("ServerConfig", CredentialType::ServerConfig),
        ("Certificate", CredentialType::Certificate),
        ("TwoFactor", CredentialType::TwoFactor),
        ("SecureNote", CredentialType::SecureNote),
        ("Identity", CredentialType::Identity),
        ("SoftwareLicense", CredentialType::SoftwareLicense),
        (
            "SomethingCustom",
            CredentialType::Custom("SomethingCustom".to_string()),
        ),
    ] {
        let mut special = sample_credential(identity_id, &format!("{} cred", name));
        special.credential_type = variant;
        repo.create(&special).await.unwrap();
        let round_trip = repo.find_by_id(&special.id).await.unwrap().unwrap();
        assert_eq!(round_trip.credential_type.to_string(), name);
    }

    // SecurityLevel Medium and Low round-trip through their string form
    // (High is the default used by the sample above).
    for (level_name, level) in [
        ("Medium", SecurityLevel::Medium),
        ("Low", SecurityLevel::Low),
    ] {
        let mut lvl_cred = sample_credential(identity_id, &format!("{} level", level_name));
        lvl_cred.security_level = level;
        repo.create(&lvl_cred).await.unwrap();
        let round_trip = repo.find_by_id(&lvl_cred.id).await.unwrap().unwrap();
        assert_eq!(round_trip.security_level.to_string(), level_name);
    }

    let mut renamed = fetched.clone();
    renamed.name = "Renamed credential".to_string();
    renamed.username = Some("alice-search".to_string());
    renamed.url = Some("https://search-hit.example.com".to_string());
    renamed.is_favorite = true;
    repo.update(&renamed).await.unwrap();

    // 8 from the earlier section plus the 2 security-level variants
    // plus the 2 new type variants (Identity / SoftwareLicense).
    assert_eq!(repo.find_all().await.unwrap().len(), 12);
    assert_eq!(repo.find_by_identity(&identity_id).await.unwrap().len(), 12);
    // The security-level variants reuse the Password sample shape, so
    // Password count is 3 (original + Medium + Low).
    assert_eq!(
        repo.find_by_type(&CredentialType::Password)
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(repo.find_favorites().await.unwrap().len(), 1);

    let hits = repo.search_by_fields("Renamed").await.unwrap();
    assert_eq!(hits.len(), 1);
    // username / url 子串同样命中（NULL 列不参与匹配）
    assert_eq!(
        repo.search_by_fields("alice-search").await.unwrap().len(),
        1
    );
    assert_eq!(
        repo.search_by_fields("search-hit.example.com")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(repo
        .search_by_fields("no-match-xyz")
        .await
        .unwrap()
        .is_empty());

    assert!(repo.delete(&renamed.id).await.unwrap());
    assert!(!repo.delete(&renamed.id).await.unwrap());
}

#[tokio::test]
async fn row_to_credential_falls_back_to_medium_for_unknown_level() {
    let db = test_db().await;
    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("weird level"))
        .await
        .unwrap();
    let identity_id = identities.find_all().await.unwrap()[0].id;

    // The schema does not constrain security_level, so a legacy or corrupt
    // row can carry an unrecognized value; it must map back to Medium.
    let cred_id = Uuid::new_v4();
    sqlx::query(
            r#"INSERT INTO credentials (id, identity_id, name, credential_type, security_level,
               encrypted_data, tags, metadata, created_at, updated_at, is_active, is_favorite)
               VALUES (?, ?, 'corrupt', 'Password', 'ULTRA-SECRET', x'00', '[]', '{}', ?, ?, 1, 0)"#,
        )
        .bind(cred_id.to_string())
        .bind(identity_id.to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(db.pool())
        .await
        .unwrap();

    let repo = CredentialRepository::new(db);
    let fetched = repo.find_by_id(&cred_id).await.unwrap().unwrap();
    assert_eq!(fetched.security_level, SecurityLevel::Medium);
}

#[tokio::test]
async fn credential_create_persists_last_accessed() {
    let db = test_db().await;
    let identities = IdentityRepository::new(db.clone());
    identities
        .create(&sample_identity("accessed"))
        .await
        .unwrap();
    let identity_id = identities.find_all().await.unwrap()[0].id;
    let repo = CredentialRepository::new(db);

    let mut cred = sample_credential(identity_id, "accessed once");
    cred.last_accessed = Some(chrono::Utc::now());
    repo.create(&cred).await.unwrap();

    let fetched = repo.find_by_id(&cred.id).await.unwrap().unwrap();
    assert!(fetched.last_accessed.is_some());
}
