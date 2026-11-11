use super::*;

/// Item history：add 落 created 行，元数据补写落 updated 行，
/// `history` 子命令列出时间线；删除后历史仍可查询。
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

    // add = create + 元数据补写（username/url/favorite）→ created + updated 两行
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

    // 删除后：凭据查询 404，历史命令仍列出（含 deleted 行）
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

/// restore：元数据回滚到目标版本；秘密不回滚（历史只有元数据快照）。
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
