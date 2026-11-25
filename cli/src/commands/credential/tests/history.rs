use super::*;

/// Item history: add lands a created row, a metadata touch-up lands an updated row,
/// the `history` subcommand lists the timeline; history stays queryable after deletion.
#[tokio::test]
async fn credential_history_lists_changes_and_survives_delete() {
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
    seed(&config, "gina").await;

    // add = create + metadata fill-in (username/url/favorite) → two rows, created + updated
    execute(add_args("gina", "hist-login", Some("pw"), true), &config)
        .await
        .expect("seed add works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let gina = service.get_identity_by_name("gina").await.unwrap().unwrap();
    let creds = service
        .get_credentials_for_identity(&gina.id)
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);
    let cred_id = creds[0].id;
    drop(service);

    execute(
        CredentialArgs {
            command: CredentialCommand::History { id: cred_id },
        },
        &config,
    )
    .await
    .expect("history lists rows");

    // After deletion: the credential query 404s, the history command still lists (including the deleted row)
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

    let err = execute(
        CredentialArgs {
            command: CredentialCommand::Show {
                id: cred_id,
                reveal: false,
            },
        },
        &config,
    )
    .await
    .expect_err("show after delete must fail");
    assert!(err.to_string().contains("not found"));

    execute(
        CredentialArgs {
            command: CredentialCommand::History { id: cred_id },
        },
        &config,
    )
    .await
    .expect("history survives delete");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// restore: the metadata rolls back to the target version; secrets do not (history only holds metadata snapshots).
#[tokio::test]
async fn credential_restore_reverts_metadata_to_target_version() {
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
    seed(&config, "gina").await;

    execute(add_args("gina", "restore-me", Some("pw"), false), &config)
        .await
        .expect("seed add works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let gina = service.get_identity_by_name("gina").await.unwrap().unwrap();
    let creds = service
        .get_credentials_for_identity(&gina.id)
        .await
        .unwrap();
    let cred_id = creds[0].id;

    let mut cred = service.get_credential(&cred_id).await.unwrap().unwrap();
    cred.name = "renamed".to_string();
    service.update_credential(&cred).await.unwrap();
    drop(service);

    execute(
        CredentialArgs {
            command: CredentialCommand::Restore {
                id: cred_id,
                version: 1,
            },
        },
        &config,
    )
    .await
    .expect("restore works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let restored = service.get_credential(&cred_id).await.unwrap().unwrap();
    assert_eq!(restored.name, "restore-me");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);

    let history = service
        .get_entity_history(EntityType::Credential, &cred_id)
        .await
        .unwrap();
    assert_eq!(history[0].change_type.to_string(), "restored");
    assert_eq!(history[0].version, 4);

    let err = execute(
        CredentialArgs {
            command: CredentialCommand::Restore {
                id: cred_id,
                version: 99,
            },
        },
        &config,
    )
    .await
    .expect_err("unknown version must fail");
    assert!(format!("{err:?}").contains("99"));

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
