use super::*;

#[tokio::test]
async fn credential_add_list_show_remove_round_trip() {
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
    seed(&config, "alice").await;

    // Add with an explicit secret (no prompt path).
    execute(
        add_args("alice", "site-login", Some("s3cret"), true),
        &config,
    )
    .await
    .expect("add with explicit secret works");

    // List all + per identity + favorite filter, in each format.
    for fmt in ["table", "json", "yaml"] {
        execute(
            CredentialArgs {
                command: CredentialCommand::List {
                    identity: None,
                    credential_type: None,
                    favorite: false,
                    format: fmt.to_string(),
                },
            },
            &config,
        )
        .await
        .unwrap_or_else(|e| panic!("list {} must work: {}", fmt, e));
    }
    execute(
        CredentialArgs {
            command: CredentialCommand::List {
                identity: Some("alice".to_string()),
                credential_type: Some("password".to_string()),
                favorite: true,
                format: "json".to_string(),
            },
        },
        &config,
    )
    .await
    .expect("filtered list works");

    // Unknown format fails.
    let err = execute(
        CredentialArgs {
            command: CredentialCommand::List {
                identity: None,
                credential_type: None,
                favorite: false,
                format: "xml".to_string(),
            },
        },
        &config,
    )
    .await
    .expect_err("bad format must fail");
    assert!(err.to_string().contains("Unsupported format: xml"));

    // Unknown identity fails during add.
    let err = execute(add_args("ghost", "x", Some("pw"), false), &config)
        .await
        .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));

    // Grab the credential id, then show + remove it.
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let alice = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);
    let cred_id = creds[0].id;
    assert!(creds[0].is_favorite);
    drop(service);

    execute(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: cred_id,
                reveal: false,
            },
        },
        &config,
    )
    .await
    .expect("show works");

    // Missing credential fails fast.
    let err = execute(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: uuid::Uuid::new_v4(),
                reveal: false,
            },
        },
        &config,
    )
    .await
    .expect_err("missing credential must fail");
    assert!(err.to_string().contains("not found"));

    execute(
        CredentialArgs {
            command: CredentialCommand::Remove {
                id: cred_id,
                yes: true,
            },
        },
        &config,
    )
    .await
    .expect("remove works");

    // Remove is reported for missing credentials too.
    execute(
        CredentialArgs {
            command: CredentialCommand::Remove {
                id: cred_id,
                yes: true,
            },
        },
        &config,
    )
    .await
    .expect("second remove reports not found");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn credential_secret_env_var_serves_prompt() {
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
    seed(&config, "bob").await;

    // prompt_secret=true reads PERSONA_CREDENTIAL_SECRET instead of the TTY.
    std::env::set_var("PERSONA_CREDENTIAL_SECRET", "env-secret");
    let mut args = add_args("bob", "from-env", None, false);
    if let CredentialCommand::Add(add) = &mut args.command {
        add.prompt_secret = true;
    }
    execute(args, &config)
        .await
        .expect("add via env secret works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let bob = service.get_identity_by_name("bob").await.unwrap().unwrap();
    let creds = service.get_credentials_for_identity(&bob.id).await.unwrap();
    assert_eq!(creds.len(), 1);
    let data = service.get_credential_data(&creds[0].id).await.unwrap();
    match data {
        Some(CredentialData::Password(pw)) => assert_eq!(pw.password, "env-secret"),
        other => panic!("unexpected data: {:?}", other),
    }

    std::env::remove_var("PERSONA_CREDENTIAL_SECRET");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// `--credential-type api-key` 必须落 **ApiKey data 变体**（回归）：
/// 曾经落进 `_` 兜底被建成 Password 变体——type=ApiKey + data=Password，
/// `secrets resolve IDENTITY/ITEM/api_key` 报 "unknown field"（valid 只有
/// password/email），按 data 变体消费的下游（cockpit 等）全部失效。
/// 元数据 type 列一直显示 ApiKey，错在 data，只有解密路径能发现。
#[tokio::test]
async fn add_api_key_stores_api_key_data_variant_not_password() {
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
    seed(&config, "bob").await;

    std::env::set_var("PERSONA_CREDENTIAL_SECRET", "sk-env-key-1");
    let mut args = add_args("bob", "k-api", None, false);
    if let CredentialCommand::Add(add) = &mut args.command {
        add.credential_type = CredentialTypeOption::ApiKey;
        add.prompt_secret = true;
    }
    execute(args, &config)
        .await
        .expect("add api-key via env secret works");
    std::env::remove_var("PERSONA_CREDENTIAL_SECRET");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let bob = service.get_identity_by_name("bob").await.unwrap().unwrap();
    let creds = service.get_credentials_for_identity(&bob.id).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(
        creds[0].credential_type,
        CredentialType::ApiKey,
        "元数据 type 应为 ApiKey"
    );
    let data = service.get_credential_data(&creds[0].id).await.unwrap();
    match data {
        Some(CredentialData::ApiKey(api)) => assert_eq!(api.api_key, "sk-env-key-1"),
        other => panic!(
            "api-key 必须落 ApiKey data 变体（而非 Password），实得: {:?}",
            other
        ),
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn credential_add_prompts_for_secret_and_maps_every_type() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_CREDENTIAL_SECRET");
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
    seed(&config, "dora").await;

    // No --secret and no env var: the interactive input prompt is used.
    // Username/URL are left unset so the plain-show branch also renders.
    let mut prompted = add_args("dora", "typed", None, false);
    if let CredentialCommand::Add(add) = &mut prompted.command {
        add.username = None;
        add.url = None;
    }
    let ui = ScriptedUi::new().input("typed-secret");
    execute_with(prompted, &config, &ui)
        .await
        .expect("prompted secret path works");
    assert!(ui.exhausted());

    // Every credential type / security level mapping round-trips.
    let types = [
        (CredentialTypeOption::ApiKey, SecurityLevelOption::Critical),
        (CredentialTypeOption::SshKey, SecurityLevelOption::Medium),
        (CredentialTypeOption::CryptoWallet, SecurityLevelOption::Low),
        (CredentialTypeOption::BankCard, SecurityLevelOption::High),
        (
            CredentialTypeOption::GameAccount,
            SecurityLevelOption::Medium,
        ),
        (
            CredentialTypeOption::ServerConfig,
            SecurityLevelOption::High,
        ),
        (
            CredentialTypeOption::Certificate,
            SecurityLevelOption::Critical,
        ),
        (CredentialTypeOption::TwoFactor, SecurityLevelOption::High),
        (CredentialTypeOption::Custom, SecurityLevelOption::Low),
    ];
    for (i, (ctype, level)) in types.iter().enumerate() {
        let args = CredentialArgs {
            command: CredentialCommand::Add(Box::new(AddArgs {
                identity: "dora".to_string(),
                name: format!("cred{i}"),
                credential_type: ctype.clone(),
                security_level: level.clone(),
                username: Some("u".to_string()),
                url: None,
                prompt_secret: false,
                secret: Some("pw".to_string()),
                note: None,
                first_name: None,
                last_name: None,
                email: None,
                phone: None,
                birthday: None,
                address: None,
                id_number: None,
                passport_number: None,
                driver_license: None,
                tax_id: None,
                organization: None,
                job_title: None,
                license_key: None,
                version: None,
                publisher: None,
                purchase_date: None,
                order_number: None,
                support_email: None,
                download_url: None,
                seats: None,
                valid_until: None,
                favorite: false,
            })),
        };
        execute(args, &config)
            .await
            .unwrap_or_else(|e| panic!("add type {ctype:?} must work: {e}"));
    }

    // Type filter keeps only matching rows; favorite filter can empty the
    // list entirely ("No credentials found" path).
    execute(
        CredentialArgs {
            command: CredentialCommand::List {
                identity: Some("dora".to_string()),
                credential_type: Some("ApiKey".to_string()),
                favorite: false,
                format: "table".to_string(),
            },
        },
        &config,
    )
    .await
    .expect("type-filtered list works");
    execute(
        CredentialArgs {
            command: CredentialCommand::List {
                identity: Some("dora".to_string()),
                credential_type: None,
                favorite: true,
                format: "table".to_string(),
            },
        },
        &config,
    )
    .await
    .expect("favorite-only empty list works");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn credential_add_note_stores_encrypted_secure_note() {
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
    seed(&config, "alice").await;

    let note_args = |name: &str, secret: Option<&str>, note: Option<&str>| CredentialArgs {
        command: CredentialCommand::Add(Box::new(AddArgs {
            identity: "alice".to_string(),
            name: name.to_string(),
            credential_type: CredentialTypeOption::Note,
            security_level: SecurityLevelOption::High,
            username: None,
            url: None,
            prompt_secret: false,
            secret: secret.map(String::from),
            note: note.map(String::from),
            first_name: None,
            last_name: None,
            email: None,
            phone: None,
            birthday: None,
            address: None,
            id_number: None,
            passport_number: None,
            driver_license: None,
            tax_id: None,
            organization: None,
            job_title: None,
            license_key: None,
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until: None,
            favorite: false,
        })),
    };

    // note 类型不适用密码路径。
    let err = execute_with(note_args("bad", Some("pw"), None), &config, &TerminalUi)
        .await
        .expect_err("note with --secret must fail");
    assert!(err.to_string().contains("--note"));

    // --note 显式提供正文。
    execute_with(
        note_args("Recovery codes", None, Some("1111-2222\n3333-4444")),
        &config,
        &TerminalUi,
    )
    .await
    .expect("explicit note works");

    // --note 缺省：走可见 input 提示（ScriptedUi 预置答案）。
    let scripted = ScriptedUi::new().input("interactive note body");
    execute_with(note_args("Scratch", None, None), &config, &scripted)
        .await
        .expect("interactive note works");
    assert!(scripted.exhausted());

    // 读回：类型与数据变体正确，正文逐字保留（per-item key 加密往返）。
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let alice = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 2);
    assert!(creds
        .iter()
        .all(|c| matches!(c.credential_type, CredentialType::SecureNote)));

    let recovery = creds.iter().find(|c| c.name == "Recovery codes").unwrap();
    let data = service
        .get_credential_data(&recovery.id)
        .await
        .unwrap()
        .expect("note data present");
    match data {
        CredentialData::SecureNote(note) => {
            assert_eq!(note.note, "1111-2222\n3333-4444");
        }
        other => panic!("unexpected data: {:?}", other),
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// Identity / Software License：flag 驱动建条目，字段逐字往返
/// （per-item key 加密）；license key 缺省走交互提示。
#[tokio::test]
async fn credential_add_identity_and_license_round_trip() {
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
    seed(&config, "iris").await;

    // Identity：姓名 + 证件号走 flag，未提供字段保持 None。
    let identity_args = CredentialArgs {
        command: CredentialCommand::Add(Box::new(AddArgs {
            identity: "iris".to_string(),
            name: "Passport (main)".to_string(),
            credential_type: CredentialTypeOption::Identity,
            security_level: SecurityLevelOption::High,
            username: Some("iris".to_string()),
            url: None,
            prompt_secret: false,
            secret: None,
            note: None,
            first_name: Some("Alice".to_string()),
            last_name: Some("Zhang".to_string()),
            email: Some("alice@example.com".to_string()),
            phone: None,
            birthday: Some("1990-01-31".to_string()),
            address: Some("1 Main St\nBeijing".to_string()),
            id_number: Some("110101199001310011".to_string()),
            passport_number: Some("E12345678".to_string()),
            driver_license: None,
            tax_id: None,
            organization: None,
            job_title: None,
            license_key: None,
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until: None,
            favorite: false,
        })),
    };
    execute(identity_args.clone(), &config)
        .await
        .expect("identity add works");

    // SoftwareLicense：license key 缺省 → ScriptedUi 提示输入。
    let mut license_args = identity_args;
    if let CredentialCommand::Add(add) = &mut license_args.command {
        debug_assert!(add.license_key.is_none());
        add.name = "JetBrains All Products".to_string();
        add.credential_type = CredentialTypeOption::SoftwareLicense;
        add.username = None;
        add.first_name = None;
        add.last_name = None;
        add.email = None;
        add.birthday = None;
        add.address = None;
        add.id_number = None;
        add.passport_number = None;
    }
    let scripted = ScriptedUi::new().input("AAAA-BBBB-CCCC-DDDD");
    execute_with(license_args, &config, &scripted)
        .await
        .expect("license add with prompted key works");
    assert!(scripted.exhausted());

    // 互斥防线：--secret 不适用于这两种类型。
    let mut bad = CredentialArgs {
        command: CredentialCommand::Add(Box::new(AddArgs {
            identity: "iris".to_string(),
            name: "bad".to_string(),
            credential_type: CredentialTypeOption::SoftwareLicense,
            security_level: SecurityLevelOption::High,
            username: None,
            url: None,
            prompt_secret: false,
            secret: Some("pw".to_string()),
            note: None,
            first_name: None,
            last_name: None,
            email: None,
            phone: None,
            birthday: None,
            address: None,
            id_number: None,
            passport_number: None,
            driver_license: None,
            tax_id: None,
            organization: None,
            job_title: None,
            license_key: None,
            version: None,
            publisher: None,
            purchase_date: None,
            order_number: None,
            support_email: None,
            download_url: None,
            seats: None,
            valid_until: None,
            favorite: false,
        })),
    };
    let err = execute_with(bad.clone(), &config, &TerminalUi)
        .await
        .expect_err("license with --secret must fail");
    assert!(err.to_string().contains("--license-key"));
    if let CredentialCommand::Add(add) = &mut bad.command {
        add.credential_type = CredentialTypeOption::Identity;
        add.name = "bad-identity".to_string();
    }
    let err = execute_with(bad, &config, &TerminalUi)
        .await
        .expect_err("identity with --secret must fail");
    assert!(err.to_string().contains("--secret"));

    // 读回：类型变体与字段逐字保留。
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let iris = service.get_identity_by_name("iris").await.unwrap().unwrap();
    let creds = service
        .get_credentials_for_identity(&iris.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 2);

    let identity_cred = creds.iter().find(|c| c.name == "Passport (main)").unwrap();
    assert!(matches!(
        identity_cred.credential_type,
        CredentialType::Identity
    ));
    match service
        .get_credential_data(&identity_cred.id)
        .await
        .unwrap()
        .unwrap()
    {
        CredentialData::Identity(id) => {
            assert_eq!(id.first_name, "Alice");
            assert_eq!(id.last_name, "Zhang");
            assert_eq!(id.email.as_deref(), Some("alice@example.com"));
            assert_eq!(id.id_number.as_deref(), Some("110101199001310011"));
            assert_eq!(id.passport_number.as_deref(), Some("E12345678"));
            assert_eq!(id.address.as_deref(), Some("1 Main St\nBeijing"));
            assert_eq!(id.phone, None);
            assert_eq!(id.driver_license, None);
        }
        other => panic!("unexpected data: {:?}", other),
    }

    let license_cred = creds
        .iter()
        .find(|c| c.name == "JetBrains All Products")
        .unwrap();
    assert!(matches!(
        license_cred.credential_type,
        CredentialType::SoftwareLicense
    ));
    match service
        .get_credential_data(&license_cred.id)
        .await
        .unwrap()
        .unwrap()
    {
        CredentialData::SoftwareLicense(lic) => {
            assert_eq!(lic.license_key, "AAAA-BBBB-CCCC-DDDD");
            assert_eq!(lic.version, None);
        }
        other => panic!("unexpected data: {:?}", other),
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
