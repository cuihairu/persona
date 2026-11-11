use super::*;

#[test]
fn custom_field_spec_parses_and_rejects_malformed() {
    // 基本形态 + 空 section
    let f = parse_field_spec("text::Notes=hello").unwrap();
    assert_eq!(f.label, "Notes");
    assert_eq!(f.value, "hello");
    assert_eq!(f.field_type, CustomFieldType::Text);
    assert!(f.section.is_none());

    // label/section trim；值里可再带 =（首个 = 分隔）
    let f = parse_field_spec("concealed: Bank : PIN =1=2").unwrap();
    assert_eq!(f.label, "PIN");
    assert_eq!(f.value, "1=2");
    assert_eq!(f.field_type, CustomFieldType::Concealed);
    assert_eq!(f.section.as_deref(), Some("Bank"));

    // date 类型；空值合法
    let f = parse_field_spec("date:Renewal:Expires=2030-01-31").unwrap();
    assert_eq!(f.field_type, CustomFieldType::Date);
    let f = parse_field_spec("text::Empty=").unwrap();
    assert_eq!(f.value, "");

    // 新字段 id 唯一
    let a = parse_field_spec("text::A=1").unwrap();
    let b = parse_field_spec("text::A=1").unwrap();
    assert_ne!(a.id, b.id);

    // 无 = / 缺 section 段 / 未知类型 / 空 label
    for bad in ["no-equals-sign", "text:Label=1", "weird::L=1", "text::  =1"] {
        assert!(parse_field_spec(bad).is_err(), "`{bad}` must be rejected");
    }
}

#[tokio::test]
async fn custom_fields_arg_guards() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let id = Uuid::new_v4();

    // --field 与 --clear 互斥
    let err = execute_with(
        CredentialArgs {
            command: CredentialCommand::SetFields {
                id,
                fields: vec!["text::A=1".to_string()],
                clear: true,
            },
        },
        &config,
        &TerminalUi,
    )
    .await
    .expect_err("field+clear must be rejected");
    assert!(err.to_string().contains("--clear"));

    // 二者皆无：无事可做
    let err = execute_with(
        CredentialArgs {
            command: CredentialCommand::SetFields {
                id,
                fields: vec![],
                clear: false,
            },
        },
        &config,
        &TerminalUi,
    )
    .await
    .expect_err("empty set must be rejected");
    assert!(err.to_string().contains("nothing to set"));
}

#[tokio::test]
async fn custom_fields_set_list_clear_roundtrip() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    seed(&config, "fields-user").await;

    execute(
        add_args("fields-user", "with-fields", Some("pw"), false),
        &config,
    )
    .await
    .expect("add works");
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let who = service
        .get_identity_by_name("fields-user")
        .await
        .unwrap()
        .unwrap();
    let creds = service.get_credentials_for_identity(&who.id).await.unwrap();
    assert_eq!(creds.len(), 1);
    let cred_id = creds[0].id;
    drop(service);

    // 整表写入：text 无 section / concealed 带 section / date
    execute(
        CredentialArgs {
            command: CredentialCommand::SetFields {
                id: cred_id,
                fields: vec![
                    "text::Recovery=abc123".to_string(),
                    "concealed:Bank:PIN=999999".to_string(),
                    "date:Renewal:Expires=2030-01-31".to_string(),
                ],
                clear: false,
            },
        },
        &config,
    )
    .await
    .expect("set fields works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let fields = service.custom_fields(&cred_id).await.unwrap();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].label, "Recovery");
    assert_eq!(fields[0].value, "abc123");
    assert!(fields[0].section.is_none());
    assert_eq!(fields[1].field_type, CustomFieldType::Concealed);
    assert_eq!(fields[1].section.as_deref(), Some("Bank"));
    assert_eq!(fields[2].value, "2030-01-31");
    assert!(fields.iter().all(|f| !f.id.is_empty()));
    drop(service);

    // 列表（打码）与揭示（确认 yes）两条路都跑通
    execute(
        CredentialArgs {
            command: CredentialCommand::Fields {
                id: cred_id,
                reveal: false,
            },
        },
        &config,
    )
    .await
    .expect("list masked works");
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Fields {
                id: cred_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("list reveal works");
    assert!(ui.exhausted());

    // --clear 清空
    execute(
        CredentialArgs {
            command: CredentialCommand::SetFields {
                id: cred_id,
                fields: vec![],
                clear: true,
            },
        },
        &config,
    )
    .await
    .expect("clear works");
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    assert!(service.custom_fields(&cred_id).await.unwrap().is_empty());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
