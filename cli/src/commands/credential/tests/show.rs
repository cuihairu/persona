use super::*;

#[tokio::test]
async fn credential_show_reveal_and_remove_decline_paths() {
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
    seed(&config, "cara").await;

    execute(add_args("cara", "vault", Some("topsecret"), false), &config)
        .await
        .expect("seed credential added");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let cara = service.get_identity_by_name("cara").await.unwrap().unwrap();
    let creds = service
        .get_credentials_for_identity(&cara.id)
        .await
        .unwrap();
    let cred_id = creds[0].id;
    drop(service);

    // Declining the reveal prompt hides the secret.
    let ui = ScriptedUi::new().confirm(false);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: cred_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("declined reveal succeeds");
    assert!(ui.exhausted());

    // Accepting it prints the decrypted password.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: cred_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("accepted reveal succeeds");
    assert!(ui.exhausted());

    // Removing with a declined confirmation aborts and keeps the row.
    let ui = ScriptedUi::new().confirm(false);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Remove {
                id: cred_id,
                yes: false,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("declined removal returns success");
    assert!(ui.exhausted());

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let creds = service
        .get_credentials_for_identity(&cara.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1, "declined removal must keep the credential");
    drop(service);

    // Accepting the confirmation deletes it.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Remove {
                id: cred_id,
                yes: false,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("confirmed removal deletes");
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn credential_show_reveal_renders_api_key_and_ssh_key_payloads() {
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
    seed(&config, "erin").await;

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let erin = service.get_identity_by_name("erin").await.unwrap().unwrap();

    // Seed a non-password credential of each decryptable kind directly so
    // the reveal match arms for ApiKey and SshKey render.
    let api_id = service
        .create_credential(
            erin.id,
            "api-token".to_string(),
            CredentialType::ApiKey,
            SecurityLevel::High,
            &CredentialData::ApiKey(ApiKeyData {
                api_key: "sk-live-123".to_string(),
                api_secret: None,
                token: None,
                permissions: Vec::new(),
                expires_at: None,
            }),
        )
        .await
        .unwrap()
        .id;
    let ssh_id = service
        .create_credential(
            erin.id,
            "server-key".to_string(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(SshKeyData {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAA".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            }),
        )
        .await
        .unwrap()
        .id;
    drop(service);

    // Accepting the reveal prints the API key.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: api_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("api key reveal works");
    assert!(ui.exhausted());

    // Same for the SSH private key arm.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: ssh_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("ssh key reveal works");
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// Kinds without a dedicated reveal line fall through to the generic
/// debug formatter instead of being skipped.
#[tokio::test]
async fn credential_show_reveal_renders_generic_payload_kinds() {
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
    seed(&config, "faye").await;

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let faye = service.get_identity_by_name("faye").await.unwrap().unwrap();

    let totp_id = service
        .create_credential(
            faye.id,
            "login-otp".to_string(),
            CredentialType::TwoFactor,
            SecurityLevel::Medium,
            &CredentialData::TwoFactor(persona_core::TwoFactorData {
                secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                issuer: "Example".to_string(),
                account_name: "faye".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                hotp: None,
                initial_counter: None,
                period: 30,
            }),
        )
        .await
        .unwrap()
        .id;
    drop(service);

    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: totp_id,
                reveal: true,
            },
        },
        &config,
        &ui,
    )
    .await
    .expect("two-factor reveal renders via the generic arm");
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// Reveal 的 SecureNote / Identity / SoftwareLicense 三个专用渲染分支
/// （Identity 与 SoftwareLicense 用全 Some 字段，连内层 `if let Some`
/// 打印行一起覆盖）。
#[tokio::test]
async fn credential_show_reveal_renders_note_identity_license_payloads() {
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
    seed(&config, "nova").await;

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let nova = service.get_identity_by_name("nova").await.unwrap().unwrap();

    let note_id = service
        .create_credential(
            nova.id,
            "recovery-notes".to_string(),
            CredentialType::SecureNote,
            SecurityLevel::Medium,
            &CredentialData::SecureNote(SecureNoteData {
                note: "one-time recovery codes".to_string(),
            }),
        )
        .await
        .unwrap()
        .id;
    let identity_id = service
        .create_credential(
            nova.id,
            "government-id".to_string(),
            CredentialType::Identity,
            SecurityLevel::High,
            &CredentialData::Identity(IdentityData {
                first_name: "Nova".to_string(),
                last_name: "Sato".to_string(),
                username: Some("nova.sato".to_string()),
                email: Some("nova@example.com".to_string()),
                phone: Some("+81-90-0000-0000".to_string()),
                birthday: None,
                address: Some("2-1 Marunouchi\nChiyoda-ku".to_string()),
                id_number: Some("1234-5678".to_string()),
                passport_number: Some("TK9876543".to_string()),
                driver_license: Some("DL-12345".to_string()),
                tax_id: Some("T-0001".to_string()),
                organization: None,
                job_title: None,
            }),
        )
        .await
        .unwrap()
        .id;
    let license_id = service
        .create_credential(
            nova.id,
            "ide-license".to_string(),
            CredentialType::SoftwareLicense,
            SecurityLevel::High,
            &CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: "IDE-PRO-0001-FFFF".to_string(),
                version: Some("2026.1".to_string()),
                publisher: Some("Example Corp".to_string()),
                purchase_date: Some("2026-01-15".to_string()),
                order_number: Some("ORD-42".to_string()),
                support_email: Some("support@example.com".to_string()),
                download_url: Some("https://example.com/dl".to_string()),
                seats: Some(5),
                valid_until: Some("2027-01-15".to_string()),
            }),
        )
        .await
        .unwrap()
        .id;
    drop(service);

    for (id, label) in [
        (note_id, "secure note"),
        (identity_id, "identity"),
        (license_id, "software license"),
    ] {
        let ui = ScriptedUi::new().confirm(true);
        execute_with(
            CredentialArgs {
                command: CredentialCommand::Show { id, reveal: true },
            },
            &config,
            &ui,
        )
        .await
        .unwrap_or_else(|e| panic!("{label} reveal must work: {e}"));
        assert!(ui.exhausted(), "{label} reveal consumed its confirm");
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
