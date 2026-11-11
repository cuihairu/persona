use super::super::codes::generate_codes;
use super::super::setup::setup_totp;
use super::*;

#[tokio::test]
async fn execute_dispatches_setup_and_code_subcommands() {
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

    // Setup through the public dispatch wrapper.
    execute_with(
        TotpArgs {
            command: TotpCommand::Setup {
                identity: "alice".to_string(),
                name: None,
                qr: None,
                otpauth: None,
                secret: Some(BASE32_NOPAD.encode(b"dispatch")),
                issuer: Some("Dispatch".to_string()),
                account: Some("alice@dispatch".to_string()),
                url: None,
                digits: None,
                period: None,
                algorithm: None,
                hotp: false,
                counter: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("dispatched setup succeeds");

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
    let totp_id = creds[0].id;
    drop(service);

    // Code generation through the same wrapper.
    execute_with(
        TotpArgs {
            command: TotpCommand::Code {
                id: totp_id,
                watch: false,
                counter: None,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("dispatched code generation succeeds");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn public_execute_wrapper_dispatches_to_terminal_ui() {
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

    // The production wrapper shares the TerminalUi-backed path; run the
    // Setup subcommand through `execute` end to end.
    execute(
        TotpArgs {
            command: TotpCommand::Setup {
                identity: "alice".to_string(),
                name: None,
                qr: None,
                otpauth: None,
                secret: Some(BASE32_NOPAD.encode(b"wrapper")),
                issuer: None,
                account: None,
                url: None,
                digits: None,
                period: None,
                algorithm: None,
                hotp: false,
                counter: None,
            },
        },
        &config,
    )
    .await
    .expect("public execute wrapper performs the setup");

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
    assert_eq!(creds.len(), 1, "credential stored through the wrapper");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// `generate_codes` refuses credentials whose decrypted payload is not
/// TOTP data even when the row exists.
#[tokio::test]
async fn generate_codes_rejects_non_totp_credential_data() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let pw_cred_id: uuid::Uuid;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let identity = IdentityRepository::new(db.clone())
            .create(&Identity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        // A password credential: type says TwoFactor is required below.
        let mut cred = service
            .create_credential(
                identity.id,
                "pw entry".to_string(),
                persona_core::CredentialType::Password,
                persona_core::SecurityLevel::Medium,
                &persona_core::CredentialData::Password(persona_core::PasswordCredentialData {
                    password: "hunter2".to_string(),
                    email: None,
                    security_questions: vec![],
                }),
            )
            .await
            .unwrap();
        // Mislabel the row as TwoFactor so the type gate passes and the
        // decrypted payload mismatch is what surfaces.
        use persona_core::Repository;
        cred.credential_type = persona_core::CredentialType::TwoFactor;
        persona_core::storage::CredentialRepository::new(service_db(&config).await)
            .update(&cred)
            .await
            .unwrap();
        pw_cred_id = cred.id;
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let err = generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        pw_cred_id,
        false,
        None,
    )
    .await
    .expect_err("password payload must not be shown as TOTP");
    assert!(
        err.to_string().contains("does not contain TOTP data"),
        "got: {err}"
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn setup_requires_unlocked_workspace() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    // No users: init_service bails before any TOTP work.
    let err = setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        None,
        None,
        None,
        Some("JBSWY3DPEHPK3PXP".to_string()),
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
    .expect_err("uninitialized workspace must fail");
    assert!(err.to_string().contains("Workspace not initialized"));

    // Wrong password is reported instead of prompting.
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let err = setup_totp(
        &config,
        &crate::utils::prompt::TerminalUi,
        "alice".to_string(),
        None,
        None,
        None,
        Some("JBSWY3DPEHPK3PXP".to_string()),
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
    .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
