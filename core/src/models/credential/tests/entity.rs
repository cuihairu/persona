use super::*;

#[test]
fn credential_new_sets_required_fields() {
    let identity_id = Uuid::new_v4();
    let cred = Credential::new(
        identity_id,
        "GitHub".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1, 2, 3],
        None,
    );

    assert_eq!(cred.identity_id, identity_id);
    assert_eq!(cred.name, "GitHub");
    assert_eq!(cred.credential_type, CredentialType::Password);
    assert_eq!(cred.security_level, SecurityLevel::High);
    assert_eq!(cred.encrypted_data, vec![1, 2, 3]);
    assert!(cred.is_active);
    assert!(!cred.is_favorite);
    assert!(cred.tags.is_empty());
    assert!(cred.metadata.is_empty());
}

#[test]
fn credential_tag_operations_are_idempotent() {
    let identity_id = Uuid::new_v4();
    let mut cred = Credential::new(
        identity_id,
        "GitHub".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1],
        None,
    );
    cred.tags.clear();

    cred.add_tag("work".to_string());
    cred.add_tag("work".to_string());
    assert_eq!(cred.tags, vec!["work".to_string()]);

    cred.remove_tag("work");
    assert!(cred.tags.is_empty());
}

#[test]
fn credential_metadata_roundtrip() {
    let identity_id = Uuid::new_v4();
    let mut cred = Credential::new(
        identity_id,
        "GitHub".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1],
        None,
    );
    cred.metadata.clear();

    cred.set_metadata("env".to_string(), "prod".to_string());
    assert_eq!(cred.get_metadata("env").map(|s| s.as_str()), Some("prod"));

    cred.remove_metadata("env");
    assert!(cred.get_metadata("env").is_none());
}

#[test]
fn credential_mark_accessed_sets_timestamp() {
    let identity_id = Uuid::new_v4();
    let mut cred = Credential::new(
        identity_id,
        "GitHub".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1],
        None,
    );

    assert!(cred.last_accessed.is_none());
    cred.mark_accessed();
    assert!(cred.last_accessed.is_some());
}

#[test]
fn credential_serde_roundtrip() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Example".to_string(),
        CredentialType::ApiKey,
        SecurityLevel::Critical,
        vec![1, 2, 3],
        Some(vec![9, 9]),
    );
    cred.url = Some("https://example.com".to_string());
    cred.username = Some("alice".to_string());
    cred.notes = Some("rotates quarterly".to_string());
    cred.tags = vec!["work".to_string()];
    cred.mark_accessed();

    let json = serde_json::to_string(&cred).unwrap();
    let decoded: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.id, cred.id);
    assert_eq!(decoded.wrapped_item_key, Some(vec![9, 9]));
    assert_eq!(decoded.last_accessed, cred.last_accessed);
    assert_eq!(decoded.credential_type, CredentialType::ApiKey);
}

#[test]
fn credential_remove_missing_tag_and_metadata_are_noop() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Example".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1],
        None,
    );
    cred.tags.clear();
    cred.metadata.clear();

    let before = cred.updated_at;
    cred.remove_tag("missing");
    cred.remove_metadata("missing");
    assert!(cred.tags.is_empty());
    assert!(cred.get_metadata("missing").is_none());
    assert_eq!(cred.updated_at, before);
}

#[test]
fn credential_touch_refreshes_updated_at() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Example".to_string(),
        CredentialType::Password,
        SecurityLevel::High,
        vec![1],
        None,
    );

    let before = cred.updated_at;
    cred.touch();
    assert!(cred.updated_at >= before);
}

// FromStr 与 Display/存储层字符串对齐：已知串逐一归位，未知串归入
// Custom（与 row_to_credential 同一策略）。

#[test]
fn credential_serde_roundtrip_preserves_every_field() {
    let mut cred = Credential::new(
        Uuid::new_v4(),
        "Full field row".to_string(),
        CredentialType::SoftwareLicense,
        SecurityLevel::Low,
        vec![7, 8, 9],
        Some(vec![1, 1]),
    );
    cred.url = Some("https://example.com".to_string());
    cred.username = Some("alice".to_string());
    cred.notes = Some("perpetual license".to_string());
    cred.tags = vec!["office".to_string(), "license".to_string()];
    cred.set_metadata("vendor".to_string(), "acme".to_string());
    cred.mark_accessed();
    cred.is_active = false;
    cred.is_favorite = true;

    let json = serde_json::to_string(&cred).unwrap();
    let decoded: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.id, cred.id);
    assert_eq!(decoded.identity_id, cred.identity_id);
    assert_eq!(decoded.name, cred.name);
    assert_eq!(decoded.credential_type, CredentialType::SoftwareLicense);
    assert_eq!(decoded.security_level, SecurityLevel::Low);
    assert_eq!(decoded.url, cred.url);
    assert_eq!(decoded.username, cred.username);
    assert_eq!(decoded.encrypted_data, cred.encrypted_data);
    assert_eq!(decoded.wrapped_item_key, Some(vec![1, 1]));
    assert_eq!(decoded.notes, cred.notes);
    assert_eq!(decoded.tags, cred.tags);
    assert_eq!(decoded.metadata, cred.metadata);
    assert_eq!(decoded.created_at, cred.created_at);
    assert_eq!(decoded.updated_at, cred.updated_at);
    assert_eq!(decoded.last_accessed, cred.last_accessed);
    assert!(!decoded.is_active);
    assert!(decoded.is_favorite);
}
