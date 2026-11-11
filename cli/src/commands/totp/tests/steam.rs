use super::super::codes::generate_codes;
use super::super::steam::{collect_ma_file_paths, import_steam_mafiles};
use super::*;

#[tokio::test]
async fn ma_file_collection_handles_file_dir_and_missing_paths() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("one.maFile");
    std::fs::write(&file, b"{}").unwrap();

    // 单文件直通
    assert_eq!(collect_ma_file_paths(&file).unwrap(), vec![file.clone()]);
    // 目录：列出其中全部 .maFile
    let second = dir.path().join("two.maFile");
    std::fs::write(&second, b"{}").unwrap();
    let mut listed = collect_ma_file_paths(dir.path()).unwrap();
    listed.sort();
    assert_eq!(listed, vec![file, second]);
    // 不存在的路径
    let missing = dir.path().join("nope").join("x.maFile");
    let err = collect_ma_file_paths(&missing).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err}");

    // 空目录在 collect 层即报错（因此 import 的 "Nothing to import"
    // 兜底分支实际不可达，属防御性代码）
    let empty = TempDir::new().unwrap();
    let err = collect_ma_file_paths(empty.path()).unwrap_err();
    assert!(err.to_string().contains("No .maFile files found"), "{err}");
}

/// 解析阶段在解锁库之前：全部文件坏掉时直接报首个失败，
/// 不触碰 workspace（config 无需真实库）。
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

/// SDA 形状的 maFile：验证器字段 + Session 会话对象 + 杂项字段。
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

/// 导入端到端：会话字段永不入库；identity_secret/device_id 进加密
/// 负载；Code 子命令对导入条目按 Steam 类型出码。
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

    // 会话内容断言：Session 对象里的高危凭据不得出现在任何入库面
    // （解密后的负载 + 明文 metadata + username/url）。
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

    // 类型分流出码：GameToken 条目走 steam 路由（5 位字母码）
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

/// 批量导入：坏文件不阻断好文件、退出码报失败；拒绝确认则不入库；
/// 目录里没有 .maFile、--name 配目录都报错。
#[tokio::test]
async fn import_steam_batch_reports_failures_and_respects_decline() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_MASTER_PASSWORD");

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let mafile_dir = dir.path().join("maFiles");
    std::fs::create_dir(&mafile_dir).unwrap();
    std::fs::write(mafile_dir.join("good.maFile"), sample_mafile_json()).unwrap();
    // 缺 account_name 的坏文件
    std::fs::write(
        mafile_dir.join("broken.maFile"),
        r#"{"shared_secret": "MDAxMjM0NTY3ODlhYmNkZWZnaGo="}"#,
    )
    .unwrap();
    // 非 maFile 的 JSON：扩展名过滤本应排除它，但单文件指定时必须拒绝
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

    // 批量：好文件导入、坏文件汇报后整体失败（非零退出语义）
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

    // 尽管整体报失败，好文件已经入库
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

    // 目录里只有 manifest.json：扩展名过滤后没有可导入文件
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

    // --name 与目录批量互斥
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

    // 拒绝确认：单个文件解析成功但不落库
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

    // 接受确认后落库
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
