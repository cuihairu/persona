use super::*;

#[test]
fn attachment_size_formats_bytes_kb_and_mb() {
    assert_eq!(format_attachment_size(512), "512 B");
    assert_eq!(format_attachment_size(1023), "1023 B");
    assert_eq!(format_attachment_size(1024), "1.0 KB");
    assert_eq!(format_attachment_size(2048), "2.0 KB");
    assert_eq!(
        format_attachment_size(1024 * 1024),
        format!("{:.1} MB", 1.0)
    );
    assert_eq!(
        format_attachment_size(3 * 1024 * 1024),
        format!("{:.1} MB", 3.0)
    );
}

/// Attachments: attach (encrypted store) → attachments list → save-attachment decrypt
/// and read back → remove-attachment; deleting a credential cascades to remove its attachments.
#[tokio::test]
async fn credential_attachment_commands_round_trip() {
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
    seed(&config, "hana").await;
    execute(add_args("hana", "attach-login", Some("pw"), false), &config)
        .await
        .expect("seed add works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let hana = service.get_identity_by_name("hana").await.unwrap().unwrap();
    let cred_id = service
        .get_credentials_for_identity(&hana.id)
        .await
        .unwrap()[0]
        .id;
    drop(service);

    // The source file goes in a dedicated tempdir (the workspace tempdir is reused by the attachments/ directory)
    let src_dir = TempDir::new().unwrap();
    let src = src_dir.path().join("recovery.txt");
    std::fs::write(&src, b"cli-attachment-payload").unwrap();

    execute(
        CredentialArgs {
            command: CredentialCommand::Attach {
                id: cred_id,
                file: src.clone(),
                no_encrypt: false,
            },
        },
        &config,
    )
    .await
    .expect("attach works");

    // The list command runs; the metadata assertions go through the service layer (is_encrypted / file name)
    execute(
        CredentialArgs {
            command: CredentialCommand::Attachments { id: cred_id },
        },
        &config,
    )
    .await
    .expect("attachments list works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let attachments = service.get_attachments(&cred_id).await.unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].filename, "recovery.txt");
    assert!(attachments[0].is_encrypted);
    let attachment_id = attachments[0].id;
    drop(service);

    // Decrypt and store: the bytes read back match the source exactly (the core guarantee of per-item key sealing)
    let out = src_dir.path().join("restored.txt");
    execute(
        CredentialArgs {
            command: CredentialCommand::SaveAttachment {
                attachment_id,
                output: out.clone(),
            },
        },
        &config,
    )
    .await
    .expect("save-attachment works");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"cli-attachment-payload".to_vec()
    );

    // Remove the attachment → the list comes back empty
    execute(
        CredentialArgs {
            command: CredentialCommand::RemoveAttachment {
                attachment_id,
                yes: true,
            },
        },
        &config,
    )
    .await
    .expect("remove-attachment works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    assert!(service.get_attachments(&cred_id).await.unwrap().is_empty());

    // Credential deletion cascades (attach another one, then delete the credential)
    drop(service);
    execute(
        CredentialArgs {
            command: CredentialCommand::Attach {
                id: cred_id,
                file: src.clone(),
                no_encrypt: false,
            },
        },
        &config,
    )
    .await
    .expect("re-attach works");
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
    .expect("credential remove works");

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    assert!(
        service.get_attachments(&cred_id).await.unwrap().is_empty(),
        "credential deletion must cascade attachments"
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
