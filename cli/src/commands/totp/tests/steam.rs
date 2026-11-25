use super::super::codes::generate_codes;
use super::super::steam::{collect_ma_file_paths, import_steam_mafiles};
use super::*;

#[tokio::test]
async fn ma_file_collection_handles_file_dir_and_missing_paths() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("one.maFile");
    std::fs::write(&file, b"{}").unwrap();

    // Single file passes through directly
    assert_eq!(collect_ma_file_paths(&file).unwrap(), vec![file.clone()]);
    // Directory: list all .maFiles inside it
    let second = dir.path().join("two.maFile");
    std::fs::write(&second, b"{}").unwrap();
    let mut listed = collect_ma_file_paths(dir.path()).unwrap();
    listed.sort();
    assert_eq!(listed, vec![file, second]);
    // Nonexistent path
    let missing = dir.path().join("nope").join("x.maFile");
    let err = collect_ma_file_paths(&missing).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err}");

    // An empty directory already errors at the collect layer (so the import
    // "Nothing to import" fallback branch is actually unreachable, defensive code only)
    let empty = TempDir::new().unwrap();
    let err = collect_ma_file_paths(empty.path()).unwrap_err();
    assert!(err.to_string().contains("No .maFile files found"), "{err}");
}

/// The parse phase runs before unlocking the vault: when every file is bad, report
/// the first failure right away without touching the workspace (config needs no real vault).
#[tokio::test]
async fn import_steam_mafiles_reports_first_unparseable_file() {
    let dir = TempDir::new().unwrap();
    let bad = dir.path().join("broken.maFile");
    std::fs::write(&bad, b"definitely not json").unwrap();

    let mut config = crate::config::CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();

    let err = import_steam_mafiles(
        &config,
        &crate::utils::prompt::scripted::ScriptedUi::new(),
        "someone".to_string(),
        bad.clone(),
        None,
        None,
        true,
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("No .maFile could be imported") && msg.contains("broken.maFile"),
        "{msg}"
    );
}

/// An SDA-shaped maFile: authenticator fields + a Session object + assorted fields.
fn sample_mafile_json() -> String {
    r#"{
            "account_name": "alice_steam",
            "shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo=",
            "identity_secret": "cGVyc29uYS12ZWN0b3ItYg==",
            "device_id": "mobile1234567",
            "revocation_code": "R12345",
            "fully_enrolled": true,
            "Session": {
                "SessionID": "deadbeef-session",
                "SteamLogin": "alice_steam",
                "SteamLoginSecure": "76561198000000000%7C%7Cfake",
                "WebCookie": "cookie-jar",
                "OAuthToken": "eyJhbGciOi.eyJzdWIiOiJhbGljZQ",
                "steamid": "76561198000000000"
            }
        }"#
    .to_string()
}

/// Import end-to-end: session fields are never stored; identity_secret/device_id go
/// into the encrypted payload; the Code subcommand generates codes for imported
/// entries as the Steam type.
#[tokio::test]
async fn import_steam_mafile_stores_verifier_fields_only() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let mafile_dir = dir.path().join("maFiles");
    std::fs::create_dir(&mafile_dir).unwrap();
    let mafile_path = mafile_dir.join("alice_steam.maFile");
    std::fs::write(&mafile_path, sample_mafile_json()).unwrap();
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

    execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: mafile_path.clone(),
                name: None,
                url: Some("store.steampowered.com".to_string()),
                yes: true,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect("maFile import succeeds");

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
    assert_eq!(creds.len(), 1, "exactly one credential imported");
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
    match &data {
        CredentialData::GameToken(gt) => {
            assert_eq!(gt.provider, "steam_guard");
            assert_eq!(gt.secret_key, "MDAxMjM0NTY3ODlhYmNkZWZnaGo=");
            assert_eq!(
                gt.identity_secret.as_deref(),
                Some("cGVyc29uYS12ZWN0b3ItYg==")
            );
            assert_eq!(gt.device_id.as_deref(), Some("mobile1234567"));
            assert_eq!(gt.account_name, "alice_steam");
        }
        other => panic!("unexpected data: {:?}", other),
    }

    // Session content assertions: the high-risk credentials inside the Session object
    // must not appear on any stored surface (decrypted payload + plaintext metadata
    // + username/url).
    let stored_view = format!(
        "{:?}{:?}{:?}{:?}",
        data, creds[0].metadata, creds[0].username, creds[0].url
    );
    for leak in [
        "deadbeef-session",
        "SteamLoginSecure",
        "cookie-jar",
        "OAuthToken",
        "eyJhbGciOi",
    ] {
        assert!(
            !stored_view.contains(leak),
            "session content `{leak}` leaked into the stored credential"
        );
    }
    drop(service);

    // Code generation dispatch by type: GameToken entries go through the steam route (5-letter code)
    generate_codes(
        &config,
        &crate::utils::prompt::TerminalUi,
        creds[0].id,
        false,
        None,
    )
    .await
    .expect("code generated for imported Steam Guard entry");

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}

/// Batch import: bad files do not block good ones, and the exit code reports failure;
/// declining confirmation means nothing is stored; a directory without .maFiles and
/// --name combined with a directory both error out.
#[tokio::test]
async fn import_steam_batch_reports_failures_and_respects_decline() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let mafile_dir = dir.path().join("maFiles");
    std::fs::create_dir(&mafile_dir).unwrap();
    std::fs::write(mafile_dir.join("good.maFile"), sample_mafile_json()).unwrap();
    // Bad file missing account_name
    std::fs::write(
        mafile_dir.join("broken.maFile"),
        r#"{"shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo="}"#,
    )
    .unwrap();
    // A JSON file that is not a maFile: the extension filter would normally exclude it,
    // but when specified as a single file it must be rejected
    std::fs::write(mafile_dir.join("manifest.json"), r#"{"files": []}"#).unwrap();
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

    // Batch: good files are imported, bad files are reported, then the whole thing fails (non-zero exit semantics)
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: mafile_dir.clone(),
                name: None,
                url: None,
                yes: true,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("batch with a broken file must report failure");
    assert!(
        err.to_string().contains("1 file(s) failed to import"),
        "got: {err}"
    );

    // Despite the overall failure, the good files were stored
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
    assert_eq!(creds.len(), 1, "the good file was imported");
    assert_eq!(creds[0].name, "Steam (alice_steam)");
    drop(service);

    // Directory containing only manifest.json: no importable files after the extension filter
    let json_only = dir.path().join("json_only");
    std::fs::create_dir(&json_only).unwrap();
    std::fs::write(json_only.join("manifest.json"), r#"{"files": []}"#).unwrap();
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: json_only,
                name: None,
                url: None,
                yes: true,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("directory without .maFile must fail");
    assert!(err.to_string().contains("No .maFile files found"));

    // --name and directory batch are mutually exclusive
    let err = execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: mafile_dir.clone(),
                name: Some("dup".to_string()),
                url: None,
                yes: true,
            },
        },
        &config,
        &crate::utils::prompt::TerminalUi,
    )
    .await
    .expect_err("--name with a directory must fail");
    assert!(err.to_string().contains("--name is only valid"));

    // Declining confirmation: the single file parses fine but is not stored
    let declined_dir = dir.path().join("declined");
    std::fs::create_dir(&declined_dir).unwrap();
    std::fs::write(
        declined_dir.join("bob.maFile"),
        r#"{"account_name": "bob", "shared_secret": "cGVyc29uYS12ZWN0b3ItYg=="}"#,
    )
    .unwrap();
    execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: declined_dir.join("bob.maFile"),
                name: None,
                url: None,
                yes: false,
            },
        },
        &config,
        &crate::utils::prompt::scripted::ScriptedUi::new().confirm(false),
    )
    .await
    .expect("declined import is not an error");
    let service = init_service(&config, &crate::utils::prompt::TerminalUi)
        .await
        .unwrap();
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 1, "declined file must not be stored");

    // Stored after accepting the confirmation
    execute_with(
        TotpArgs {
            command: TotpCommand::ImportSteam {
                identity: "alice".to_string(),
                file: declined_dir.join("bob.maFile"),
                name: None,
                url: None,
                yes: false,
            },
        },
        &config,
        &crate::utils::prompt::scripted::ScriptedUi::new().confirm(true),
    )
    .await
    .expect("confirmed import succeeds");
    let creds = service
        .get_credentials_for_identity(&alice.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(creds.len(), 2, "confirmed file stored");
    assert!(
        creds.iter().any(|c| c.name == "Steam (bob)"),
        "confirmed file stored: {:?}",
        creds.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
    );

    std::env::remove_var("PERSONA_MASTER_PASSWORD");
}
