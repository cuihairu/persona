use super::*;

#[tokio::test]
async fn ensure_service_unlocks_with_scripted_password() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = ssh_test_config(&dir).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    // Wrong scripted password fails authentication.
    let ui = ScriptedUi::new().password("wrong-pin");
    let Err(err) = ensure_service(&config, &ui).await else {
        panic!("wrong password must fail");
    };
    assert!(err.to_string().contains("Authentication failed"));
    assert!(ui.exhausted());

    // The correct scripted password unlocks the service.
    let ui = ScriptedUi::new().password("master-pin");
    let service = ensure_service(&config, &ui)
        .await
        .expect("correct password must unlock");
    assert!(service.has_users().await.unwrap());
    assert!(ui.exhausted());
}

#[tokio::test]
async fn remove_key_confirm_gate_cancels_or_deletes() {
    let _env = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = ssh_test_config(&dir).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }
    let id = uuid::Uuid::new_v4();

    // Declining the confirmation keeps everything untouched. The unlock
    // password is consumed before the confirm gate.
    let ui = ScriptedUi::new().password("master-pin").confirm(false);
    remove_key(id, false, &config, &ui)
        .await
        .expect("declined removal returns success");
    assert!(ui.exhausted());

    // Accepting proceeds (the id does not exist; delete is a no-op).
    let ui = ScriptedUi::new().password("master-pin").confirm(true);
    remove_key(id, false, &config, &ui)
        .await
        .expect("confirmed removal returns success");
    assert!(ui.exhausted());

    // --yes skips the confirm prompt entirely.
    let ui = ScriptedUi::new().password("master-pin");
    remove_key(id, true, &config, &ui)
        .await
        .expect("forced removal returns success");
    assert!(ui.exhausted(), "--yes must not touch the confirm queue");

    // The CLI dispatch arm reaches the same flow.
    let ui = ScriptedUi::new().password("master-pin").confirm(false);
    execute_with(
        ssh_args(SshSubcommand::Remove { id, yes: false }),
        &config,
        &ui,
    )
    .await
    .expect("dispatched removal cancel works");
    assert!(ui.exhausted());
}

#[tokio::test]
async fn ensure_service_without_users_needs_no_prompt() {
    let dir = TempDir::new().unwrap();
    let config = ssh_test_config(&dir).await;
    let ui = ScriptedUi::new();
    let service = ensure_service(&config, &ui)
        .await
        .expect("userless workspace opens without prompting");
    assert!(!service.has_users().await.unwrap());
    assert!(ui.exhausted(), "no prompt consumed");

    // Keep TerminalUi referenced so the import stays honest.
    let _ = TerminalUi;
}

// ------------------------------------------------------------------
// ensure_service: non-interactive env resolution.
// ------------------------------------------------------------------

#[tokio::test]
async fn ensure_service_non_interactive_uses_env_password() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = unlocked_workspace(&dir, "master-pin").await;
    config.ui.interactive = false;

    // Without the env var there is no prompt to fall back to.
    let ui = ScriptedUi::new();
    let Err(err) = ensure_service(&config, &ui).await else {
        panic!("missing env password must fail");
    };
    assert!(err.to_string().contains("PERSONA_MASTER_PASSWORD"));
    assert!(ui.exhausted(), "non-interactive mode never prompts");

    // With the env var set the service unlocks without any prompt.
    let _pw = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let ui = ScriptedUi::new();
    let service = ensure_service(&config, &ui)
        .await
        .expect("env password unlocks the service");
    assert!(service.has_users().await.unwrap());
    assert!(ui.exhausted());
}
