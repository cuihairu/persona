use super::*;

use crate::utils::prompt::scripted::ScriptedUi;

#[test]
fn resolve_passphrase_prefers_explicit_env_var() {
    let _guard = env_guard();
    std::env::set_var("PERSONA_BACKUP_TEST_PW", "from-var");
    // 不预载答案：若实现误走 prompt，ScriptedUi 直接 panic（更强的保护）
    let ui = ScriptedUi::new();
    let got = resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap();
    assert_eq!(got, "from-var");
    assert!(ui.exhausted(), "explicit var must skip the prompt");

    // 显式指定的变量缺失/空白是配置错误，不静默回退
    std::env::set_var("PERSONA_BACKUP_TEST_PW", "  ");
    let err = resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap_err();
    assert!(err.to_string().contains("--passphrase-env"));
    std::env::remove_var("PERSONA_BACKUP_TEST_PW");
}

#[test]
fn resolve_passphrase_falls_back_to_payload_env_then_prompt() {
    let _guard = env_guard();
    std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
    let ui = ScriptedUi::new();
    let got = resolve_passphrase(None, "backup", &ui, true).unwrap();
    assert_eq!(got, "payload-pw");
    assert!(ui.exhausted());
    std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

    let ui = ScriptedUi::new().password("typed-pw");
    let got = resolve_passphrase(None, "backup", &ui, false).unwrap();
    assert_eq!(got, "typed-pw");
    assert!(ui.exhausted());
}

#[test]
fn client_from_env_fails_closed_without_both_vars() {
    let _guard = env_guard();
    std::env::set_var("PERSONA_SERVER_URL", "http://127.0.0.1:9");
    std::env::remove_var("PERSONA_SERVER_TOKEN");
    let err = match client_from_env() {
        Ok(_) => panic!("client must not be constructed without both env vars"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("must both be set"));
    std::env::remove_var("PERSONA_SERVER_URL");
}

#[tokio::test]
async fn push_requires_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let args = BackupArgs {
        command: BackupCommand::Push {
            passphrase_env: Some("PERSONA_BACKUP_TEST_PW".to_string()),
        },
    };
    std::env::set_var("PERSONA_BACKUP_TEST_PW", "pw");
    let err = execute_with(args, &config, &ScriptedUi::new())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("persona migrate"));
    std::env::remove_var("PERSONA_BACKUP_TEST_PW");
}

#[tokio::test]
async fn restore_from_file_swaps_vault_and_keeps_bak() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let db_path = config.get_database_path();

    // 库 v1（1 个 identity）→ 备份；随后库继续长到 2 个
    let db = seeded_db(&db_path).await;
    let blob = create_backup_bytes(db.pool(), "backup-pass", None)
        .await
        .unwrap();
    let ciphertext_path = dir.path().join("vault.persenc");
    std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
    let repo = IdentityRepository::new(db.clone());
    repo.create(&Identity::new(
        "After Backup".to_owned(),
        IdentityType::Personal,
    ))
    .await
    .unwrap();
    db.close().await;
    assert_eq!(identity_count(&db_path).await, 2);

    // 恢复：确认 yes + 口令（restore 无确认式双录）
    let ui = ScriptedUi::new().confirm(true).password("backup-pass");
    let args = BackupArgs {
        command: BackupCommand::Restore {
            id: None,
            file: Some(ciphertext_path.clone()),
            passphrase_env: None,
            yes: false,
        },
    };
    execute_with(args, &config, &ui).await.unwrap();
    assert!(ui.exhausted());

    // 库回到备份时刻（1 个），.bak 保留覆盖前的状态（2 个）
    let mut bak = db_path.clone();
    bak.set_extension("bak");
    assert_eq!(identity_count(&db_path).await, 1, "restored vault");
    assert_eq!(identity_count(&bak).await, 2, "pre-restore copy");
    let mut staged = db_path.clone();
    staged.set_extension("restore.tmp");
    assert!(!staged.exists(), "staging file must be renamed away");
}

#[tokio::test]
async fn restore_rejects_wrong_passphrase_and_leaves_vault_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let db_path = config.get_database_path();
    let db = seeded_db(&db_path).await;
    let blob = create_backup_bytes(db.pool(), "right-pass", None)
        .await
        .unwrap();
    let ciphertext_path = dir.path().join("vault.persenc");
    std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
    db.close().await;

    let ui = ScriptedUi::new().confirm(true).password("wrong-pass");
    let args = BackupArgs {
        command: BackupCommand::Restore {
            id: None,
            file: Some(ciphertext_path),
            passphrase_env: None,
            yes: true,
        },
    };
    let err = execute_with(args, &config, &ui).await.unwrap_err();
    assert!(
        err.to_string().contains("not touched"),
        "unexpected error: {err}"
    );
    assert_eq!(identity_count(&db_path).await, 1, "vault unchanged");
    let mut bak = db_path.clone();
    bak.set_extension("bak");
    assert!(!bak.exists(), "no .bak on failed restore");
}

#[tokio::test]
async fn restore_requires_exactly_one_source() {
    // 两个来源都给 / 都不给：在碰 env、碰磁盘之前就 bail，故无需
    // env_guard 也无需桩服务器。
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);

    let both = restore_args(Some("b1"), Some(dir.path().join("x.persenc")));
    let text = execute_with(both, &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(text.contains("not both"), "unexpected: {text}");

    let neither = restore_args(None, None);
    let text = execute_with(neither, &config, &ScriptedUi::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        text.contains("pass a backup id or --file"),
        "unexpected: {text}"
    );
}

#[tokio::test]
async fn restore_from_a_missing_file_names_the_read_failure() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let missing = dir.path().join("gone.persenc");
    let text = execute_with(
        restore_args(None, Some(missing)),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(text.contains("failed to read"), "unexpected: {text}");
}

#[test]
fn blank_payload_passphrase_env_still_prompts() {
    let _guard = env_guard();
    // 已设但全空白：视同没设，必须走交互（否则拿空串当口令）
    let _payload = TempEnv::set("PERSONA_PAYLOAD_PASSPHRASE", "   ");
    let ui = ScriptedUi::new().password("typed-after-blank");
    let got = resolve_passphrase(None, "backup", &ui, false).unwrap();
    assert_eq!(got, "typed-after-blank");
    assert!(ui.exhausted());
}

#[test]
fn client_from_env_rejects_blank_values_and_accepts_a_complete_pair() {
    let _guard = env_guard();
    let _blank = TempEnv::set("PERSONA_SERVER_URL", "  ");
    let _token = TempEnv::set("PERSONA_SERVER_TOKEN", "tok");
    assert!(
        client_from_env().is_err(),
        "空白 URL 视同缺失（fail-closed）"
    );
    let _url = TempEnv::set("PERSONA_SERVER_URL", "http://127.0.0.1:9/");
    assert!(client_from_env().is_ok(), "两个都非空才构造客户端");
}

#[tokio::test]
async fn restore_requires_confirmation_when_not_forced() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let db_path = config.get_database_path();
    let db = seeded_db(&db_path).await;
    let blob = create_backup_bytes(db.pool(), "backup-pass", None)
        .await
        .unwrap();
    let ciphertext_path = dir.path().join("vault.persenc");
    std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
    db.close().await;

    // confirm(false) → 取消；口令提示不应到达（确认在前）
    let ui = ScriptedUi::new().confirm(false);
    let args = BackupArgs {
        command: BackupCommand::Restore {
            id: None,
            file: Some(ciphertext_path),
            passphrase_env: None,
            yes: false,
        },
    };
    execute_with(args, &config, &ui).await.unwrap();
    assert!(ui.exhausted());
    assert_eq!(
        identity_count(&db_path).await,
        1,
        "cancelled restore is a no-op"
    );
    let mut bak = db_path.clone();
    bak.set_extension("bak");
    assert!(!bak.exists());
}
