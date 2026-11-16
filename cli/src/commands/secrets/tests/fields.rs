use super::*;

// ---- 字段词汇表（纯函数全分支走查） ----

#[test]
fn extract_and_field_tables_cover_every_variant() {
    let samples = sample_of_each_variant();
    assert_eq!(samples.len(), 9, "every typed variant must be sampled");
    for (kind, data) in &samples {
        let fields = data_fields_of(data);
        assert!(!fields.is_empty(), "{kind} must list its vocabulary");
        for field in fields {
            // 命中字段且样本全 Some → 必取到值；各类型的值分支全走一遍
            let value = extract_data_field(data, field)
                .unwrap_or_else(|e| panic!("{kind}/{field} listed but errored: {e}"));
            assert!(value.is_some(), "{kind}/{field} unset in sample");
        }
        // 词汇表之外的字段 → 各类型自己的 _ 分支 → Ok(None)
        assert_eq!(
            extract_data_field(data, "no_such_field").unwrap(),
            None,
            "{kind} unknown field must read as absent"
        );
        // 主秘密别名必须落在该类型词汇表内；BankCard 无主秘密别名
        // （resolve 走"无主秘密字段"分支），只查词汇表
        if let Some(primary) = primary_secret_field(data) {
            assert!(
                fields.contains(&primary),
                "{kind} primary secret {primary:?} missing from vocabulary"
            );
        }
    }
    // 无主秘密别名的类型（resolve 会报 no primary secret field）
    let bank_card = samples
        .iter()
        .find(|(k, _)| *k == "bank_card")
        .map(|(_, d)| d)
        .unwrap();
    assert!(
        primary_secret_field(bank_card).is_none(),
        "bank_card must have no primary secret alias"
    );

    // 无词汇/无主秘密的类型（Raw 命中两个 catch-all 与未知字段分支）
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
    // 非字符串化字段（port 数字 → to_string 分支）也走统一出口
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

    // deploy（ApiKey）未设置 url / notes：缺省元数据同样拒绝空串
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

    // BankCard 没有主秘密别名：报错要列出合法字段
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
