use super::*;

#[tokio::test]
async fn save_identity_without_id_resolves_by_name_and_coerces_values() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;

    let mut identity = sample_identity();
    identity.id = None; // force the by-name lookup branch
    identity.identity_type = "totally-custom".to_string(); // → IdentityType::Custom
    identity.description = String::new(); // empty description is stored as None
    identity.attributes.insert(
        "count".to_string(),
        Value::Number(serde_json::Number::from(42)),
    );
    identity
        .attributes
        .insert("on".to_string(), Value::Bool(true));
    identity
        .attributes
        .insert("nested".to_string(), serde_json::json!({"k": "v"}));
    identity
        .attributes
        .insert("plain".to_string(), Value::String("text".to_string()));

    save_identity(&identity, &config, &crate::utils::prompt::TerminalUi)
        .await
        .expect("save without id must succeed");

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let saved = IdentityRepository::new(db)
        .find_by_name("alice")
        .await
        .unwrap()
        .expect("identity still exists");
    assert!(matches!(
        saved.identity_type,
        IdentityType::Custom(ref s) if s == "totally-custom"
    ));
    assert_eq!(saved.description, None);
    assert_eq!(
        saved.attributes.get("count").map(String::as_str),
        Some("42")
    );
    assert_eq!(saved.attributes.get("on").map(String::as_str), Some("true"));
    assert_eq!(
        saved.attributes.get("nested").map(String::as_str),
        Some(r#"{"k":"v"}"#)
    );
    assert_eq!(
        saved.attributes.get("plain").map(String::as_str),
        Some("text")
    );
}

#[tokio::test]
async fn save_identity_reports_missing_identity() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;

    let mut identity = sample_identity();
    identity.name = "ghost".to_string(); // no such identity
    let err = save_identity(&identity, &config, &crate::utils::prompt::TerminalUi)
        .await
        .expect_err("saving an unknown identity must fail");
    assert!(err.to_string().contains("Identity not found"));
}

#[test]
fn validate_identity_checks_name_email_and_phone() {
    let mut identity = sample_identity();
    validate_identity(&identity).expect("valid identity");

    identity.name = String::new();
    let err = validate_identity(&identity).unwrap_err();
    assert!(err.to_string().contains("name cannot be empty"));
    identity.name = "alice".to_string();

    identity.email = Some("not-an-email".to_string());
    let err = validate_identity(&identity).unwrap_err();
    assert!(err.to_string().contains("Invalid email format"));
    identity.email = Some("a@b.c".to_string());

    identity.phone = Some("123".to_string());
    let err = validate_identity(&identity).unwrap_err();
    assert!(err.to_string().contains("Phone number too short"));
}
