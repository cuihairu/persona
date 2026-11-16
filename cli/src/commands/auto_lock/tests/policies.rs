use super::*;

#[tokio::test]
async fn policy_crud_lifecycle_via_cli_handler() {
    let dir = TempDir::new().unwrap();

    // Empty list reports no policies.
    handler(
        AutoLockCommand::List {
            active: false,
            security_level: None,
            search: None,
        },
        &dir,
    )
    .await
    .expect("empty list works");

    // Create from a use-case preset.
    handler(
        AutoLockCommand::Create {
            name: "preset".to_string(),
            description: Some("from preset".to_string()),
            security_level: AutoLockSecurityLevel::Medium,
            inactivity_timeout: None,
            absolute_timeout: None,
            sensitive_timeout: None,
            max_sessions: None,
            warnings: false,
            warning_time: None,
            force_sensitive: false,
            use_case: Some("personal".to_string()),
        },
        &dir,
    )
    .await
    .expect("preset create works");

    // Create with explicit configuration.
    handler(
        AutoLockCommand::Create {
            name: "custom".to_string(),
            description: None,
            security_level: AutoLockSecurityLevel::High,
            inactivity_timeout: Some(600),
            absolute_timeout: Some(2400),
            sensitive_timeout: Some(120),
            max_sessions: Some(3),
            warnings: true,
            warning_time: Some(30),
            force_sensitive: true,
            use_case: None,
        },
        &dir,
    )
    .await
    .expect("custom create works");

    // List with each filter.
    handler(
        AutoLockCommand::List {
            active: false,
            security_level: None,
            search: None,
        },
        &dir,
    )
    .await
    .expect("full list works");
    handler(
        AutoLockCommand::List {
            active: true,
            security_level: None,
            search: None,
        },
        &dir,
    )
    .await
    .expect("active list works");
    handler(
        AutoLockCommand::List {
            active: false,
            security_level: None,
            search: Some("cust".to_string()),
        },
        &dir,
    )
    .await
    .expect("search list works");
    handler(
        AutoLockCommand::List {
            active: false,
            security_level: Some(AutoLockSecurityLevel::High),
            search: None,
        },
        &dir,
    )
    .await
    .expect("level filter works");

    // Resolve the custom policy id through the repository.
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    let all = repo.find_all().await.unwrap();
    // The repository seeds built-in system policies; ours are on top.
    assert!(all.len() >= 2, "seeded policies present");
    let custom = all.iter().find(|p| p.name == "custom").unwrap().clone();
    drop(repo);

    // Show by UUID and by name, and a missing one.
    handler(
        AutoLockCommand::Show {
            policy_identifier: custom.id.to_string(),
        },
        &dir,
    )
    .await
    .expect("show by uuid works");
    handler(
        AutoLockCommand::Show {
            policy_identifier: "custom".to_string(),
        },
        &dir,
    )
    .await
    .expect("show by name works");
    let err = handler(
        AutoLockCommand::Show {
            policy_identifier: "ghost".to_string(),
        },
        &dir,
    )
    .await
    .expect_err("missing policy must fail");
    assert!(err.to_string().contains("Policy 'ghost' not found"));

    // Update fields.
    handler(
        AutoLockCommand::Update {
            policy_id: custom.id,
            name: Some("renamed".to_string()),
            description: Some("new desc".to_string()),
            security_level: Some(AutoLockSecurityLevel::Maximum),
            inactivity_timeout: Some(300),
            absolute_timeout: Some(1200),
            sensitive_timeout: Some(60),
            max_sessions: Some(2),
            warnings: Some(false),
            warning_time: Some(15),
            force_sensitive: Some(false),
        },
        &dir,
    )
    .await
    .expect("update works");

    // Deleting a system policy needs --force. Flag the renamed policy as
    // a system policy so the guarded branch actually runs.
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    let mut renamed = repo.find_by_id(&custom.id).await.unwrap().unwrap();
    renamed.metadata.is_system_policy = true;
    repo.update(&renamed).await.unwrap();
    drop(repo);
    if renamed.metadata.is_system_policy {
        let err = handler(
            AutoLockCommand::Delete {
                policy_id: renamed.id,
                force: false,
            },
            &dir,
        )
        .await
        .expect_err("system policy delete without force must fail");
        assert!(err.to_string().contains("Cannot delete system policy"));
    }
    handler(
        AutoLockCommand::Delete {
            policy_id: renamed.id,
            force: true,
        },
        &dir,
    )
    .await
    .expect("forced delete works");

    // Unknown update id fails.
    let err = handler(
        AutoLockCommand::Update {
            policy_id: uuid::Uuid::new_v4(),
            name: None,
            description: None,
            security_level: None,
            inactivity_timeout: None,
            absolute_timeout: None,
            sensitive_timeout: None,
            max_sessions: None,
            warnings: None,
            warning_time: None,
            force_sensitive: None,
        },
        &dir,
    )
    .await
    .expect_err("unknown update must fail");
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn empty_search_result_reports_no_policies() {
    let dir = TempDir::new().unwrap();

    handler(
        AutoLockCommand::List {
            active: false,
            security_level: None,
            search: Some("definitely-missing-policy".to_string()),
        },
        &dir,
    )
    .await
    .expect("a non-matching search reports the empty state");
}

#[tokio::test]
async fn delete_guards_system_policy_and_warns_without_force() {
    let dir = TempDir::new().unwrap();

    handler(
        AutoLockCommand::Create {
            name: "temp".to_string(),
            description: None,
            security_level: AutoLockSecurityLevel::Low,
            inactivity_timeout: None,
            absolute_timeout: None,
            sensitive_timeout: None,
            max_sessions: None,
            warnings: false,
            warning_time: None,
            force_sensitive: false,
            use_case: None,
        },
        &dir,
    )
    .await
    .expect("create works");

    let repo = init_repository(&config_for(&dir)).await.unwrap();
    let all = repo.find_all().await.unwrap();
    let system = all
        .iter()
        .find(|p| p.metadata.is_system_policy)
        .expect("repository seeds a system policy")
        .clone();
    let user_policy = all.iter().find(|p| p.name == "temp").unwrap().clone();
    drop(repo);

    // A system policy refuses a plain delete.
    let err = handler(
        AutoLockCommand::Delete {
            policy_id: system.id,
            force: false,
        },
        &dir,
    )
    .await
    .expect_err("system policy must refuse a plain delete");
    assert!(err.to_string().contains("Cannot delete system policy"));

    // Non-interactive mode never prompts: warn and keep the row.
    let non_interactive_config = {
        let mut config = config_for(&dir);
        config.ui.interactive = false;
        config
    };
    let ui = ScriptedUi::new();
    handle_auto_lock_with(
        AutoLockArgs {
            command: AutoLockCommand::Delete {
                policy_id: user_policy.id,
                force: false,
            },
        },
        &non_interactive_config,
        &ui,
    )
    .await
    .expect("non-interactive delete refuses without prompting");
    assert!(
        ui.exhausted(),
        "no prompt may be consumed in non-interactive mode"
    );
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    assert!(
        repo.find_by_id(&user_policy.id).await.unwrap().is_some(),
        "non-interactive refusal must keep the policy"
    );
    drop(repo);

    // Interactive mode asks for confirmation: a decline keeps the row.
    let ui = ScriptedUi::new().confirm(false);
    handle_auto_lock_with(
        AutoLockArgs {
            command: AutoLockCommand::Delete {
                policy_id: user_policy.id,
                force: false,
            },
        },
        &config_for(&dir),
        &ui,
    )
    .await
    .expect("cancelled delete returns success");
    assert!(ui.exhausted(), "confirmation must have been asked");
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    assert!(
        repo.find_by_id(&user_policy.id).await.unwrap().is_some(),
        "policy must survive a declined confirmation"
    );
    drop(repo);

    // A confirmed delete removes the row.
    let ui = ScriptedUi::new().confirm(true);
    handle_auto_lock_with(
        AutoLockArgs {
            command: AutoLockCommand::Delete {
                policy_id: user_policy.id,
                force: false,
            },
        },
        &config_for(&dir),
        &ui,
    )
    .await
    .expect("confirmed delete works");
    assert!(ui.exhausted());
    let repo = init_repository(&config_for(&dir)).await.unwrap();
    assert!(
        repo.find_by_id(&user_policy.id).await.unwrap().is_none(),
        "confirmed delete must remove the policy"
    );
    drop(repo);
}
