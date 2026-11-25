use super::*;

// ---- Field vocabulary (walking every branch of the pure functions) ----

#[test]
fn extract_and_field_tables_cover_every_variant() {
    let samples = sample_of_each_variant();
    assert_eq!(samples.len(), 9, "every typed variant must be sampled");
    for (kind, data) in &samples {
        let fields = data_fields_of(data);
        assert!(!fields.is_empty(), "{kind} must list its vocabulary");
        for field in fields {
            // A hit with an all-Some sample → a value must be produced; walks every type's value branches
            let value = extract_data_field(data, field)
                .unwrap_or_else(|e| panic!("{kind}/{field} listed but errored: {e}"));
            assert!(value.is_some(), "{kind}/{field} unset in sample");
        }
        // A field outside the vocabulary → each type's own `_` branch → Ok(None)
        assert_eq!(
            extract_data_field(data, "no_such_field").unwrap(),
            None,
            "{kind} unknown field must read as absent"
        );
        // The primary secret alias must be inside the type's vocabulary; BankCard has no
        // primary secret alias (resolve takes the "no primary secret field" branch), so
        // only the vocabulary is checked
        if let Some(primary) = primary_secret_field(data) {
            assert!(
                fields.contains(&primary),
                "{kind} primary secret {primary:?} missing from vocabulary"
            );
        }
    }
    // Types without a primary secret alias (resolve reports no primary secret field)
    let bank_card = samples
        .iter()
        .find(|(k, _)| *k == "bank_card")
        .map(|(_, d)| d)
        .unwrap();
    assert!(
        primary_secret_field(bank_card).is_none(),
        "bank_card must have no primary secret alias"
    );

    // Types with no vocabulary / no primary secret (Raw hits both catch-alls and the unknown-field branch)
    assert_eq!(data_fields_of(&CredentialData::Raw(vec![])), &[] as &[&str]);
    assert_eq!(primary_secret_field(&CredentialData::Raw(vec![])), None);
    assert_eq!(
        extract_data_field(&CredentialData::Raw(vec![]), "x").unwrap(),
        None
    );
}

#[test]
fn extract_data_field_unset_optional_fields_are_errors_not_empty_strings() {
    let api = CredentialData::ApiKey(ApiKeyData {
        api_key: "k".into(),
        api_secret: None,
        token: None,
        permissions: vec![],
        expires_at: None,
    });
    for field in ["api_secret", "token"] {
        let err = extract_data_field(&api, field).unwrap_err();
        assert!(format!("{err:#}").contains("is not set"), "{err}");
    }
    // Non-string fields (a port number → the to_string branch) also go through the unified exit
    let mut server = ServerConfigData {
        hostname: "h".into(),
        ip_address: None,
        port: 22,
        protocol: "ssh".into(),
        username: "u".into(),
        password: None,
        ssh_key_id: None,
        additional_config: Default::default(),
    };
    let port = extract_data_field(&CredentialData::ServerConfig(server.clone()), "port").unwrap();
    assert_eq!(port, Some("22".to_string()));
    server.port = 0;
    let port = extract_data_field(&CredentialData::ServerConfig(server), "port").unwrap();
    assert_eq!(port, Some("0".to_string()));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn resolve_metadata_unset_url_and_notes_bail() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();

    // deploy (ApiKey) with url / notes unset: missing metadata likewise rejects an empty string
    for field in ["url", "notes"] {
        let err = resolve_ref(
            &service,
            &SecretRef::parse(&format!("work/deploy/{field}")).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("is not set"), "{err}");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn secret_alias_without_primary_lists_valid_fields() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.authenticate_user("master-pin").await.unwrap();
    let identity = service.get_identity_by_name("work").await.unwrap().unwrap();
    service
        .create_credential(
            identity.id,
            "bank".to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            &CredentialData::BankCard(BankCardData {
                card_number: "4111".into(),
                cardholder_name: "Alice".into(),
                expiry_date: "12/30".into(),
                cvv: "123".into(),
                bank_name: "Bank".into(),
                card_type: "visa".into(),
            }),
        )
        .await
        .unwrap();

    // BankCard has no primary secret alias: the error must list the valid fields
    let err = execute_with(
        resolve_args(&["work/bank/secret"]),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("no primary secret field"), "{msg}");
    assert!(msg.contains("card_number"), "{msg}");
}
