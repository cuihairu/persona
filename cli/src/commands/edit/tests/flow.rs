use super::*;

#[tokio::test]
async fn edit_rejects_missing_identity_before_prompts() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let args = EditArgs {
        name: "ghost".to_string(),
        identity_type: None,
        description: None,
        email: None,
        phone: None,
        interactive: false,
        field: None,
        value: None,
    };
    let err = execute(args, &config)
        .await
        .expect_err("missing identity must fail");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
}

/// On a master-password workspace: a wrong password aborts the load, a
/// correct one loads and saves through the authenticated service, and
/// `save_identity` with no id resolves the row by name.
#[tokio::test]
async fn edit_auth_paths_cover_password_arms_and_name_lookup() {
    let _guard = lock_process_env();

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("edit-master").await.unwrap();
    }

    let args = |description: Option<&str>| EditArgs {
        name: "alice".to_string(),
        identity_type: None,
        description: description.map(str::to_string),
        email: None,
        phone: None,
        interactive: false,
        field: None,
        value: None,
    };

    // Wrong password aborts while loading the identity.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-edit-pin");
    let err = execute_with(
        args(Some("nope")),
        &config,
        &ScriptedUi::new().confirm(true),
    )
    .await
    .expect_err("wrong password must abort the edit");
    assert!(
        err.to_string().contains("Authentication failed"),
        "got: {err}"
    );

    // A direct save with the wrong password fails the same way.
    let mut ghost = sample_identity();
    ghost.name = "alice".to_string();
    ghost.id = None;
    let err = save_identity(&ghost, &config, &crate::utils::prompt::TerminalUi)
        .await
        .expect_err("wrong password must abort the save");
    assert!(
        err.to_string().contains("Authentication failed"),
        "got: {err}"
    );

    // The correct password unlocks, edits, and saves by name (no id).
    std::env::set_var("PERSONA_MASTER_PASSWORD", "edit-master");
    execute_with(
        args(Some("via auth")),
        &config,
        &ScriptedUi::new().confirm(true),
    )
    .await
    .expect("authenticated edit saves");

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let saved = IdentityRepository::new(db)
        .find_by_name("alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.description.as_deref(), Some("via auth"));

    // A no-id identity saves through the by-name lookup arm.
    let mut no_id = sample_identity();
    no_id.id = None;
    no_id.name = "alice".to_string();
    no_id.description = "by name".to_string();
    save_identity(&no_id, &config, &crate::utils::prompt::TerminalUi)
        .await
        .expect("save by name through the authenticated service");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// The existence check and the load each authenticate separately. With
/// the password supplied per-prompt (no env), the check can pass while
/// the load fails — reaching the bail `identity_exists` normally shadows.
#[tokio::test]
async fn edit_load_identity_rejects_wrong_password_after_check_passes() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("edit-master").await.unwrap();
    }

    let args = EditArgs {
        name: "alice".to_string(),
        identity_type: None,
        description: Some("nope".to_string()),
        email: None,
        phone: None,
        interactive: false,
        field: None,
        value: None,
    };

    let ui = ScriptedUi::new()
        .password("edit-master") // identity_exists
        .password("wrong-pin"); // load_identity
    let err = execute_with(args, &config, &ui)
        .await
        .expect_err("wrong password must abort the load");
    assert!(
        err.to_string().contains("Authentication failed"),
        "got: {err}"
    );
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn edit_end_to_end_without_users_covers_field_and_args_modes() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seeded_db(&dir, &["alice"]).await;

    let base = |field: Option<String>, value: Option<String>| EditArgs {
        name: "alice".to_string(),
        identity_type: None,
        description: None,
        email: None,
        phone: None,
        interactive: false,
        field,
        value,
    };

    // --field/--value path with an explicit confirmation.
    let ui = ScriptedUi::new().confirm(true);
    execute_with(
        base(
            Some("description".to_string()),
            Some("via field".to_string()),
        ),
        &config,
        &ui,
    )
    .await
    .expect("field edit saves");
    assert!(ui.exhausted());

    // Flag-based edit (--description/--email/--phone) with confirmation.
    let mut flag_args = base(None, None);
    flag_args.description = Some("via flags".to_string());
    flag_args.email = Some("flag@example.com".to_string());
    flag_args.phone = Some("+49123456789".to_string());
    let ui = ScriptedUi::new().confirm(true);
    execute_with(flag_args, &config, &ui)
        .await
        .expect("flag edit saves");
    assert!(ui.exhausted());

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let saved = IdentityRepository::new(db)
        .find_by_name("alice")
        .await
        .unwrap()
        .expect("alice still exists");
    assert_eq!(saved.email.as_deref(), Some("flag@example.com"));
    assert_eq!(saved.phone.as_deref(), Some("+49123456789"));

    // Declining the confirmation keeps the stored values.
    let ui = ScriptedUi::new().confirm(false);
    execute_with(
        base(
            Some("description".to_string()),
            Some("discarded".to_string()),
        ),
        &config,
        &ui,
    )
    .await
    .expect("declined edit returns success");
    assert!(ui.exhausted());

    // --field without a --value falls back to the interactive prompt.
    let ui = ScriptedUi::new().confirm(true).input("prompted desc");
    execute_with(base(Some("description".to_string()), None), &config, &ui)
        .await
        .expect("prompted field edit saves");
    assert!(ui.exhausted());

    // Unknown field names are rejected.
    let err = execute_with(
        base(Some("bogus".to_string()), Some("x".to_string())),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown field must fail");
    assert!(err.to_string().contains("Unknown field: bogus"));
}

#[tokio::test]
async fn edit_authentication_is_propagated() {
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

    // Wrong password is reported instead of being treated as "not found".
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let args = EditArgs {
        name: "alice".to_string(),
        identity_type: None,
        description: None,
        email: None,
        phone: None,
        interactive: false,
        field: None,
        value: None,
    };
    let err = execute(args, &config)
        .await
        .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn edit_interactive_flow_saves_and_discards_through_execute() {
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
        service
            .create_identity_full(CoreIdentity::new(
                "alice".to_string(),
                IdentityType::Personal,
            ))
            .await
            .unwrap();
    }
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

    let args = |interactive: bool| EditArgs {
        name: "alice".to_string(),
        identity_type: None,
        description: None,
        email: None,
        phone: None,
        interactive,
        field: None,
        value: None,
    };

    // Interactive mode: change the description, then confirm the save.
    let ui = ScriptedUi::new()
        .select(1) // edit description
        .input("saved via scripted ui")
        .select(6) // done
        .confirm(true); // save changes
    execute_with(args(true), &config, &ui)
        .await
        .expect("interactive edit saves");
    assert!(ui.exhausted());

    // The new description survives a round-trip through the database.
    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let alice = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .expect("alice exists");
    assert_eq!(alice.description.as_deref(), Some("saved via scripted ui"));
    drop(service);

    // Declining the save confirmation discards the changes.
    let ui = ScriptedUi::new()
        .select(1)
        .input("discarded edit")
        .select(6)
        .confirm(false); // discard
    execute_with(args(true), &config, &ui)
        .await
        .expect("discarding returns success");
    assert!(ui.exhausted());

    let service =
        crate::commands::service::init_service(&config, &crate::utils::prompt::TerminalUi)
            .await
            .unwrap();
    let alice = service
        .get_identity_by_name("alice")
        .await
        .unwrap()
        .expect("alice exists");
    assert_eq!(
        alice.description.as_deref(),
        Some("saved via scripted ui"),
        "discarded edit must not persist"
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
