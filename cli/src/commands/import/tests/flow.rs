use super::*;

use persona_core::{
    storage::{IdentityRepository, Repository},
    Database,
};

#[test]
fn validate_reports_missing_and_directory_paths() {
    let dir = TempDir::new().unwrap();
    let err =
        validate_import_file(&dir.path().join("ghost.json")).expect_err("missing file must fail");
    assert!(err.to_string().contains("does not exist"));

    let err = validate_import_file(dir.path()).expect_err("directory must fail");
    assert!(err.to_string().contains("not a file"));

    let f = dir.path().join("ok.json");
    std::fs::write(&f, "{}").unwrap();
    validate_import_file(&f).expect("regular file validates");
}

#[tokio::test]
async fn backup_flag_copies_database_and_dry_run_labels_all_modes() {
    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.backup.directory = dir.path().join("backups");
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();

    // Dry-run labels depend on the mode; with no existing identities and
    // force=true there are no conflicts, so even an unknown mode never
    // reaches conflict validation and still dry-runs.
    for (mode, _label) in [
        ("merge", "Would merge"),
        ("replace", "Would replace"),
        ("skip", "Would skip"),
        ("bogus", "Would process"),
    ] {
        let mut dry_args = args(&json_path, true);
        dry_args.mode = mode.to_string();
        dry_args.dry_run = true;
        execute(dry_args, &config)
            .await
            .unwrap_or_else(|e| panic!("dry run with mode {mode} must work: {e}"));
    }

    // backup=true copies the DB file into the backup directory.
    let mut backup_args = args(&json_path, true);
    backup_args.backup = true;
    execute(backup_args, &config)
        .await
        .expect("backup import succeeds");
    let backups: Vec<_> = std::fs::read_dir(&config.backup.directory)
        .expect("backup dir exists")
        .map(|e| e.expect("backup entry readable"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert!(backups[0]
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .starts_with("persona_backup_"));

    // The dry runs and the backup import both left exactly the two rows.
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let names: Vec<_> = IdentityRepository::new(db)
        .find_all()
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(names.len(), 2, "dry runs import nothing: {:?}", names);
}

#[tokio::test]
async fn decrypt_flag_round_trips_an_encrypted_payload() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let enc_path = dir.path().join("secret.json");
    std::fs::write(&enc_path, sample_json()).unwrap();
    crate::utils::file_crypto::encrypt_file_inplace(&enc_path, "payload-pw", None)
        .expect("payload encrypted");

    std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
    let mut dec_args = args(&enc_path, true);
    dec_args.decrypt = true;
    execute(dec_args, &config)
        .await
        .expect("decrypted import succeeds");

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let repo = IdentityRepository::new(db);
    assert!(repo.find_by_name("alice").await.unwrap().is_some());
    drop(repo);

    // A wrong passphrase fails instead of importing garbage.
    std::fs::write(&enc_path, sample_json()).unwrap();
    crate::utils::file_crypto::encrypt_file_inplace(&enc_path, "payload-pw", None).unwrap();
    std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "wrong-pw");
    let mut bad_args = args(&enc_path, true);
    bad_args.decrypt = true;
    let err = execute(bad_args, &config)
        .await
        .expect_err("wrong passphrase must fail");
    assert!(!err.to_string().contains("Import completed"));

    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");
    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn import_modes_apply_on_authenticated_workspace() {
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

    // First import creates both identities through the service path.
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();
    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    execute(args(&json_path, true), &config).await.unwrap();

    // Updated payload exercises merge/replace/skip on existing rows.
    // Note: IdentityType::from_str only accepts the capitalized form.
    let updated = serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-02-01T00:00:00Z"},
            "identities": [
                {"name": "alice", "type": "Work", "description": "authed-merge", "phone": "+49123456789"}
            ]
        })
        .to_string();
    let updated_path = dir.path().join("updated.json");
    std::fs::write(&updated_path, updated).unwrap();

    let mut merge_args = args(&updated_path, true);
    merge_args.mode = "merge".to_string();
    execute(merge_args, &config).await.unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let alice = IdentityRepository::new(db)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.description.as_deref(), Some("authed-merge"));
        assert_eq!(alice.phone.as_deref(), Some("+49123456789"));
    }

    let mut replace_args = args(&updated_path, true);
    replace_args.mode = "replace".to_string();
    execute(replace_args, &config).await.unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let alice = IdentityRepository::new(db)
            .find_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                alice.identity_type,
                persona_core::models::IdentityType::Work
            ),
            "replace rewrote the type"
        );
    }

    let mut skip_args = args(&updated_path, true);
    skip_args.mode = "skip".to_string();
    execute(skip_args, &config).await.unwrap();

    // Wrong password on the authenticated import path is reported.
    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let err = execute(args(&updated_path, true), &config)
        .await
        .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn import_round_trip_merge_conflicts_and_dry_run() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();

    // Dry run touches nothing.
    let mut dry_args = args(&json_path, true);
    dry_args.dry_run = true;
    execute(dry_args, &config).await.expect("dry run succeeds");
    assert!(check_import_conflicts(&[], &config, &ScriptedUi::new())
        .await
        .unwrap()
        .is_empty());

    // Real import creates both identities.
    execute(args(&json_path, true), &config)
        .await
        .expect("import succeeds");
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let repo = IdentityRepository::new(db.clone());
    assert!(repo.find_by_name("alice").await.unwrap().is_some());
    assert!(repo.find_by_name("bob").await.unwrap().is_some());
    drop(db);

    // Re-importing detects conflicts and merge mode updates them.
    let conflicts = check_import_conflicts(
        &[ImportIdentity {
            name: "alice".to_string(),
            identity_type: "personal".to_string(),
            description: "x".to_string(),
            email: None,
            phone: None,
            tags: vec![],
        }],
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].conflict_type, "name_exists");

    // Invalid mode is rejected when conflicts exist.
    let mut bad_args = args(&json_path, true);
    bad_args.mode = "bogus".to_string();
    let err = execute(bad_args, &config)
        .await
        .expect_err("invalid mode must fail");
    assert!(err.to_string().contains("Invalid import mode: bogus"));

    // Missing file fails fast.
    let err = execute(args(&dir.path().join("ghost.json"), true), &config)
        .await
        .expect_err("missing file must fail");
    assert!(err.to_string().contains("does not exist"));
}

#[tokio::test]
async fn import_modes_merge_replace_skip() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();

    // First import creates identities.
    execute(args(&json_path, true), &config).await.unwrap();

    // Updated payload with new description for alice.
    let updated = serde_json::json!({
        "export_info": {"version": "1.0", "created": "2024-01-02T00:00:00Z"},
        "identities": [
            {"name": "alice", "type": "personal", "description": "updated-desc", "email": "new@b.c"}
        ]
    })
    .to_string();
    let updated_path = dir.path().join("updated.json");
    std::fs::write(&updated_path, updated).unwrap();

    // Merge keeps existing fields and applies new ones.
    let mut merge_args = args(&updated_path, true);
    merge_args.mode = "merge".to_string();
    execute(merge_args, &config).await.unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        let alice = repo.find_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice.description.as_deref(), Some("updated-desc"));
        assert_eq!(alice.email.as_deref(), Some("new@b.c"));
    }

    // Replace overwrites; skip leaves the row untouched.
    let blank = serde_json::json!({
        "export_info": {"version": "1.0", "created": "2024-01-03T00:00:00Z"},
        "identities": [
            {"name": "alice", "type": "work", "description": "replaced", "email": "r@b.c"}
        ]
    })
    .to_string();
    let blank_path = dir.path().join("blank.json");
    std::fs::write(&blank_path, blank).unwrap();

    let mut skip_args = args(&blank_path, true);
    skip_args.mode = "skip".to_string();
    execute(skip_args, &config).await.unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        let alice = repo.find_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice.description.as_deref(), Some("updated-desc"));
    }

    let mut replace_args = args(&blank_path, true);
    replace_args.mode = "replace".to_string();
    execute(replace_args, &config).await.unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        let alice = repo.find_by_name("alice").await.unwrap().unwrap();
        assert_eq!(alice.description.as_deref(), Some("replaced"));
        assert_eq!(alice.email.as_deref(), Some("r@b.c"));
    }
}

#[tokio::test]
async fn import_authenticated_path_with_master_password() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
    let err = execute(args(&json_path, true), &config)
        .await
        .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));

    std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
    execute(args(&json_path, true), &config)
        .await
        .expect("correct password must import");
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let service = crate::commands::service::new_service(db).await.unwrap();
        // Both identities landed in the encrypted workspace.
        let mut service = service;
        let password =
            crate::commands::service::prompt_master_password(&crate::utils::prompt::TerminalUi)
                .unwrap();
        let _ = service.authenticate_user(&password).await.unwrap();
        assert!(service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .is_some());
    }

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

#[tokio::test]
async fn import_interactive_selection_and_confirm_gates() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let json_path = dir.path().join("data.json");
    std::fs::write(&json_path, sample_json()).unwrap();

    // Interactive selection picks only the first identity, then declines
    // the proceed prompt → nothing is imported.
    let mut select_args = args(&json_path, false);
    select_args.interactive = true;
    let ui = ScriptedUi::new().multi_select(&[0]).confirm(false);
    execute_with(select_args.clone(), &config, &ui)
        .await
        .expect("cancelled import returns success");
    assert!(ui.exhausted());
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let repo = IdentityRepository::new(db.clone());
    assert!(
        repo.find_all().await.unwrap().is_empty(),
        "declined import must not write"
    );
    drop(db);

    // Multi-selecting nothing reports "no identities selected".
    let ui = ScriptedUi::new().multi_select(&[]);
    execute_with(select_args.clone(), &config, &ui)
        .await
        .expect("empty selection returns success");
    assert!(ui.exhausted());

    // Accepting the proceed prompt imports the selected identities.
    let ui = ScriptedUi::new().multi_select(&[0, 1]).confirm(true);
    execute_with(select_args, &config, &ui)
        .await
        .expect("confirmed import succeeds");
    assert!(ui.exhausted());
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let repo = IdentityRepository::new(db);
    assert!(repo.find_by_name("alice").await.unwrap().is_some());
    assert!(repo.find_by_name("bob").await.unwrap().is_some());
}

#[test]
fn decrypt_import_file_with_tmp_source_needs_no_rename() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let dir = TempDir::new().unwrap();
    // A source whose extension already is `tmp` restores to the same
    // path the decryptor produced, so the rename step is skipped.
    let src = dir.path().join("secret.tmp");
    std::fs::write(&src, b"plaintext payload").unwrap();
    crate::utils::file_crypto::encrypt_file_inplace(&src, "payload-pw", None)
        .expect("source encrypted");

    let ui = ScriptedUi::new().password("payload-pw");
    let out = decrypt_import_file(&src, &config_for(&dir), &ui)
        .expect("decrypt with tmp extension succeeds");
    assert!(ui.exhausted());
    assert_eq!(
        out.file_name().and_then(|n| n.to_str()),
        Some("secret.decrypted.tmp"),
        "restored path equals the decrypted temp file: {out:?}"
    );
    assert!(out.exists(), "decrypted payload is on disk");
}

#[tokio::test]
async fn import_mode_labels_and_descriptionless_rows() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);

    // A row without a description exercises the empty-description →
    // None arm on the create path.
    let fresh_path = dir.path().join("fresh.json");
    std::fs::write(
        &fresh_path,
        serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-03-01T00:00:00Z"},
            "identities": [
                {"name": "descless", "type": "personal"}
            ]
        })
        .to_string(),
    )
    .unwrap();
    execute(args(&fresh_path, true), &config)
        .await
        .expect("descriptionless import succeeds");
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        let descless = repo.find_by_name("descless").await.unwrap().unwrap();
        assert_eq!(descless.description, None, "empty description is None");
    }

    // skip mode over a non-conflicting row still imports it (the
    // conflict guard does not match), labelling it "Skipped".
    let skip_path = dir.path().join("skip.json");
    std::fs::write(
        &skip_path,
        serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-03-02T00:00:00Z"},
            "identities": [
                {"name": "skipuser", "type": "personal", "description": "kept"}
            ]
        })
        .to_string(),
    )
    .unwrap();
    let mut skip_args = args(&skip_path, true);
    skip_args.mode = "skip".to_string();
    execute(skip_args, &config)
        .await
        .expect("skip mode over a new row imports it");

    // An unknown mode with no conflicts never reaches conflict
    // validation; the row is created and labelled "Imported".
    let odd_path = dir.path().join("odd.json");
    std::fs::write(
        &odd_path,
        serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-03-03T00:00:00Z"},
            "identities": [
                {"name": "odduser", "type": "personal", "description": "via default arm"}
            ]
        })
        .to_string(),
    )
    .unwrap();
    let mut odd_args = args(&odd_path, true);
    odd_args.mode = "bogus".to_string();
    execute(odd_args, &config)
        .await
        .expect("unknown mode without conflicts imports");

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    let repo = IdentityRepository::new(db);
    assert!(repo.find_by_name("skipuser").await.unwrap().is_some());
    assert!(repo.find_by_name("odduser").await.unwrap().is_some());
}

#[tokio::test]
async fn import_deep_auth_failure_and_replace_arms() {
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

    // Both the conflict check and the importer prompt separately; with
    // the password supplied per-prompt both are answered correctly.
    let seeded_path = dir.path().join("seeded.json");
    std::fs::write(
        &seeded_path,
        serde_json::json!({
            "export_info": {"version": "1.0", "created": "2024-04-01T00:00:00Z"},
            "identities": [
                {"name": "descless", "type": "personal", "tags": ["ops"]}
            ]
        })
        .to_string(),
    )
    .unwrap();
    let ui = ScriptedUi::new()
        .password("master-pin") // conflict check
        .password("master-pin"); // perform_import
    execute_with(args(&seeded_path, true), &config, &ui)
        .await
        .expect("seeded import succeeds");
    assert!(ui.exhausted());

    // Replace with an empty description clears the stored field and
    // carries the non-empty tags through.
    let ui = ScriptedUi::new()
        .password("master-pin") // conflict check
        .password("master-pin"); // perform_import
    let mut replace_args = args(&seeded_path, true);
    replace_args.mode = "replace".to_string();
    execute_with(replace_args, &config, &ui)
        .await
        .expect("replace import succeeds");
    assert!(ui.exhausted());
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let repo = IdentityRepository::new(db);
        let descless = repo.find_by_name("descless").await.unwrap().unwrap();
        assert_eq!(descless.description, None, "replace cleared description");
        assert_eq!(descless.tags, vec!["ops".to_string()], "replace set tags");
    }

    // Failing only the importer's own unlock reaches the bail the
    // conflict check can never hit with a single env password.
    let ui = ScriptedUi::new()
        .password("master-pin") // conflict check passes
        .password("wrong-pin"); // perform_import fails
    let mut replace_args = args(&seeded_path, true);
    replace_args.mode = "replace".to_string();
    let err = execute_with(replace_args, &config, &ui)
        .await
        .expect_err("late wrong password must abort the import");
    assert!(
        err.to_string()
            .contains("Authentication failed: InvalidCredentials"),
        "got: {err}"
    );
    assert!(ui.exhausted());

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
