use super::super::codes::generate_codes;
use super::super::setup::setup_totp;
use super::*;

#[tokio::test]
async fn setup_then_generate_code_round_trip() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(dir.path().join("identities.db"))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        IdentityRepository::new(db)
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    // Unknown identity is reported before any credential work.
    let err = setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "ghost".to_string(),
        None,
        None,
        None,
        Some(BASE32_NOPAD.encode(b"secret")),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .await
    .expect_err("unknown identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));

    // Successful setup through the raw --secret path.
    setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        None,
        None,
        Some("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".to_string()),
        None,
        None,
        None,
        Some("github.com".to_string()),
        None,
        None,
        None,
        false,
        None,
    )
    .await
    .expect("setup must succeed");

    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let creds = service
        .get_credentials_for_identity(
            &IdentityRepository::new(service_db(&config).await)
                .find_by_name("alice")
                .await
                .unwrap()
                .unwrap()
                .id,
        )
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 1, "credential stored");
    assert!(creds[0].url.as_deref() == Some("https://github.com"));
    let totp_id = creds[0].id;
    drop(service);

    // A missing credential id and a non-TOTP credential both fail.
    let err = generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        uuid::Uuid::new_v4(),
        false,
        None,
    )
    .await
    .expect_err("missing credential must fail");
    assert!(err.to_string().contains("not found"));

    let db = service_db(&config).await;
    let pw_cred = persona_core::models::Credential::new(
        IdentityRepository::new(db.clone())
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap()
            .id,
        "plain-password".to_string(),
        persona_core::models::CredentialType::Password,
        persona_core::models::SecurityLevel::High,
        b"pw".to_vec(),
        None,
    );
    persona_core::storage::CredentialRepository::new(db)
        .create(&pw_cred)
        .await
        .unwrap();

    let pw_id = {
        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let id = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap()
            .id;
        let all = service
            .get_credentials_for_identity(&id)
            .await
            .into_anyhow()
            .unwrap();
        all.iter()
            .find(|c| c.credential_type == persona_core::models::CredentialType::Password)
            .unwrap()
            .id
    };
    let err = generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        pw_id,
        false,
        None,
    )
    .await
    .expect_err("non-TOTP credential must fail");
    assert!(err.to_string().contains("is not a TOTP entry"));

    // The real TOTP credential generates a 6-digit code.
    generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        totp_id,
        false,
        None,
    )
    .await
    .expect("code generated");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// HOTP（RFC 4226）全链路：otpauth://hotp/ 录入 → 入库标记 hotp +
/// initial_counter → 显式计数器出码；watch 与 --counter 的互斥边界。
#[tokio::test]
async fn setup_then_generate_hotp_code_uses_explicit_counter() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    setup_totp(
            &config,
            &crate::utils::prompt::TerminalUi,
            "alice".to_string(),
            Some("Hotp Example".to_string()),
            None,
            Some(
                "otpauth://hotp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3&algorithm=SHA1&digits=6"
                    .to_string(),
            ),
            None,
            None,
            Some("alice@example.com".to_string()),
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .await
        .expect("HOTP setup must succeed");

    let id = {
        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let identity_id = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap()
            .id;
        let all = service
            .get_credentials_for_identity(&identity_id)
            .await
            .into_anyhow()
            .unwrap();
        let cred = all
            .into_iter()
            .find(|c| c.credential_type == CredentialType::TwoFactor)
            .expect("HOTP credential stored");
        // 入库形状：hotp=Some(true) + URI 的 counter 作为初始计数器
        match service
            .get_credential_data(&cred.id)
            .await
            .into_anyhow()
            .unwrap()
            .expect("data readable")
        {
            CredentialData::TwoFactor(tf) => {
                assert_eq!(tf.hotp, Some(true));
                assert_eq!(tf.initial_counter, Some(3));
                assert_eq!(tf.digits, 6);
            }
            other => panic!("unexpected credential data: {:?}", other),
        }
        cred.id
    };

    // 显式计数器出码（RFC 4226 附录 D 向量由 core 层锁定）
    generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        id,
        false,
        Some(1),
    )
    .await
    .expect("counter 1 code generated");
    // 缺省计数器 = 入库的 initial_counter
    generate_codes(&config, &crate::utils::prompt::TerminalUi, id, false, None)
        .await
        .expect("initial counter code generated");
    // watch 与 HOTP 互斥
    let err = generate_codes(&config, &crate::utils::prompt::TerminalUi, id, true, None)
        .await
        .expect_err("watch must be rejected for HOTP");
    assert!(
        err.to_string().contains("--counter"),
        "unexpected error: {}",
        err
    );

    // --counter 对时间型 TOTP 条目报错，而不是被静默忽略
    setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        Some("Totp Example".to_string()),
        None,
        None,
        Some(BASE32_NOPAD.encode(b"seed-secret")),
        Some("Example".to_string()),
        Some("alice@totp".to_string()),
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .await
    .expect("TOTP setup must succeed");
    let totp_id = {
        let service = init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
        let identity_id = IdentityRepository::new(service_db(&config).await)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap()
            .id;
        let all = service
            .get_credentials_for_identity(&identity_id)
            .await
            .into_anyhow()
            .unwrap();
        all.iter()
            .find(|c| c.id != id)
            .expect("TOTP credential stored")
            .id
    };
    let err = generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        totp_id,
        false,
        Some(1),
    )
    .await
    .expect_err("--counter must be rejected for time-based TOTP");
    assert!(
        err.to_string()
            .contains("--counter applies to HOTP entries only"),
        "unexpected error: {}",
        err
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn setup_totp_applies_overrides_and_display_name_precedence() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    // Raw secret with no issuer anywhere: the display name wins over the
    // account fallback, and every override lands in the stored credential.
    setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        Some("my authenticator".to_string()),
        None,
        None,
        Some("jbswy3dpehpk3pxp".to_string()), // lowercase → must normalize internally
        None,
        None,
        Some("  https://example.org/login  ".to_string()),
        Some(8),
        Some(60),
        Some("sha512".to_string()),
        false,
        None,
    )
    .await
    .expect("setup with overrides must succeed");

    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let alice = IdentityRepository::new(service_db(&config).await)
        .find_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name, "my authenticator");
    assert_eq!(creds[0].url.as_deref(), Some("https://example.org"));
    assert_eq!(creds[0].username.as_deref(), Some("TOTP")); // default account
    assert_eq!(
        creds[0].metadata.get("algorithm").map(String::as_str),
        Some("SHA512")
    );
    assert_eq!(
        creds[0].metadata.get("digits").map(String::as_str),
        Some("8")
    );

    let data = service
        .get_credential_data(&creds[0].id)
        .await
        .into_anyhow()
        .unwrap()
        .expect("two-factor data present");
    match data {
        CredentialData::TwoFactor(totp) => {
            assert_eq!(totp.algorithm, "SHA512");
            assert_eq!(totp.digits, 8);
            assert_eq!(totp.period, 60);
        }
        other => panic!("unexpected data: {:?}", other),
    }
    drop(service);

    // Second credential: no display name and no issuer → the account
    // label becomes the credential name.
    setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        None,
        None,
        Some("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP".to_string()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .await
    .expect("issuer-less setup must succeed");

    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 2);
    let names: Vec<_> = creds.iter().map(|c| c.name.as_str()).collect();
    assert!(
        names.contains(&"alice@example.com"),
        "account fallback used as name: {:?}",
        names
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// Steam Guard 录入端到端：坏密钥快速失败；正常录入后数据/元数据/
/// URL 绑定齐全，且 Code 子命令可对 GameToken 凭据出码。
#[tokio::test]
async fn setup_steam_token_stores_game_token_and_code_subcommand_reads_it() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    // Invalid shared_secret fails fast, before any DB write.
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::SetupSteam {
                identity: "alice".to_string(),
                name: None,
                secret: "!!!not base64!!!".to_string(),
                account: "alice_steam".to_string(),
                url: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("invalid shared_secret must fail");
    assert!(err.to_string().contains("Invalid Steam shared_secret"));

    // Happy path through the public dispatch wrapper.
    let secret = data_encoding::BASE64.encode(b"0123456789abcdefghij");
    execute_with(
        TotpArgs {
            command: TotpCommand::SetupSteam {
                identity: "alice".to_string(),
                name: None,
                secret,
                account: "alice_steam".to_string(),
                url: Some("store.steampowered.com".to_string()),
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("steam setup succeeds");

    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let alice = IdentityRepository::new(service_db(&config).await)
        .find_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name, "Steam (alice_steam)");
    assert_eq!(creds[0].username.as_deref(), Some("alice_steam"));
    assert_eq!(
        creds[0].url.as_deref(),
        Some("https://store.steampowered.com")
    );
    assert_eq!(
        creds[0].metadata.get("provider").map(String::as_str),
        Some("steam_guard")
    );

    let data = service
        .get_credential_data(&creds[0].id)
        .await
        .into_anyhow()
        .unwrap()
        .expect("game token data present");
    match data {
        CredentialData::GameToken(gt) => {
            assert_eq!(gt.provider, "steam_guard");
            assert_eq!(gt.issuer, "Steam");
            assert_eq!(gt.account_name, "alice_steam");
        }
        other => panic!("unexpected data: {:?}", other),
    }
    let steam_id = creds[0].id;
    drop(service);

    // The Code subcommand reads GameToken credentials through the core
    // dispatcher exactly like RFC TOTP ones.
    execute_with(
        TotpArgs {
            command: TotpCommand::Code {
                id: steam_id,
                watch: false,
                counter: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("steam token code generated");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn setup_game_token_records_vendor_bound_entry() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        IdentityRepository::new(db.clone())
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    // Provider slug validation.
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::SetupGameToken {
                identity: "alice".to_string(),
                provider: "Tencent-Security".to_string(),
                name: None,
                secret: None,
                account: "qq_123456".to_string(),
                issuer: None,
                url: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("non-slug provider must fail");
    assert!(err.to_string().contains("non-empty slug"));

    // Offline-computable providers are redirected to their dedicated command.
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::SetupGameToken {
                identity: "alice".to_string(),
                provider: "steam_guard".to_string(),
                name: None,
                secret: None,
                account: "alice_steam".to_string(),
                issuer: None,
                url: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("supported provider must be redirected");
    assert!(err.to_string().contains("setup-steam"));

    // Happy path: vendor-bound record without a secret, through the
    // public dispatch wrapper.
    execute_with(
        TotpArgs {
            command: TotpCommand::SetupGameToken {
                identity: "alice".to_string(),
                provider: "Tencent_Security".to_string(),
                name: None,
                secret: None,
                account: "qq_123456".to_string(),
                issuer: None,
                url: Some("gamesafe.qq.com".to_string()),
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("vendor-bound record succeeds");

    // A second entry keeps an exported secret (trimmed) for future
    // offline support.
    execute_with(
        TotpArgs {
            command: TotpCommand::SetupGameToken {
                identity: "alice".to_string(),
                provider: "netease_dashen".to_string(),
                name: Some("NetEase Da Shen (custom)".to_string()),
                secret: Some("  aGVsbG8=  ".to_string()),
                account: "wy_987654".to_string(),
                issuer: None,
                url: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("record with secret succeeds");

    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let alice = IdentityRepository::new(service_db(&config).await)
        .find_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    let mut creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    creds.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(creds.len(), 2);

    // Record without secret: provider slug normalized to lowercase,
    // issuer defaults to the slug, secret_key stays empty.
    let tencent = creds
        .iter()
        .find(|c| c.name == "tencent_security (qq_123456)")
        .expect("tencent record present");
    assert_eq!(tencent.username.as_deref(), Some("qq_123456"));
    assert_eq!(tencent.url.as_deref(), Some("https://gamesafe.qq.com"));
    assert_eq!(
        tencent.metadata.get("provider").map(String::as_str),
        Some("tencent_security")
    );
    let data = service
        .get_credential_data(&tencent.id)
        .await
        .into_anyhow()
        .unwrap()
        .expect("game token data present");
    match data {
        CredentialData::GameToken(gt) => {
            assert_eq!(gt.provider, "tencent_security");
            assert_eq!(gt.issuer, "tencent_security");
            assert_eq!(gt.account_name, "qq_123456");
            assert_eq!(gt.secret_key, "");
            assert_eq!(gt.url.as_deref(), Some("https://gamesafe.qq.com"));
        }
        other => panic!("unexpected data: {:?}", other),
    }

    // Record with secret: display name override wins, secret is trimmed.
    let netease = creds
        .iter()
        .find(|c| c.name == "NetEase Da Shen (custom)")
        .expect("netease record present");
    let data = service
        .get_credential_data(&netease.id)
        .await
        .into_anyhow()
        .unwrap()
        .expect("game token data present");
    match data {
        CredentialData::GameToken(gt) => {
            assert_eq!(gt.provider, "netease_dashen");
            assert_eq!(gt.secret_key, "aGVsbG8=");
        }
        other => panic!("unexpected data: {:?}", other),
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
