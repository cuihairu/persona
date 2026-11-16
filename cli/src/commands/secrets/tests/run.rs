use super::*;

// ---- run ----

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_injects_env_and_propagates_success() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    let args = SecretsArgs {
        command: SecretsCommand::Run {
            env: vec!["GITHUB_TOKEN=work/deploy/api_key".to_string()],
            command: vec![
                "sh".into(),
                "-c".into(),
                "test \"$GITHUB_TOKEN\" = \"sk-123\"".into(),
            ],
        },
    };
    execute_with(args, &config, &ScriptedUi::new())
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_resolves_all_refs_before_spawning() {
    let _guard = env_guard();
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;

    // 第二个引用是坏的：子进程不该被启动（探针文件不存在 = 未 spawn）
    let probe =
        std::env::temp_dir().join(format!("persona-secrets-run-probe-{}", std::process::id()));
    let _ = std::fs::remove_file(&probe);
    let args = SecretsArgs {
        command: SecretsCommand::Run {
            env: vec![
                "A=work/deploy/api_key".to_string(),
                "B=work/ghost/password".to_string(),
            ],
            command: vec!["sh".into(), "-c".into(), format!("touch {probe:?}").into()],
        },
    };
    let err = execute_with(args, &config, &ScriptedUi::new())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("not found"), "{err}");
    assert!(!probe.exists(), "bad ref must not spawn the child");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn spawn_with_env_forwards_nonzero_exit_code() {
    let status = spawn_with_env(&[], &["sh".into(), "-c".into(), "exit 7".into()])
        .await
        .unwrap();
    assert_eq!(status.code(), Some(7));
    let missing = spawn_with_env(&[], &["definitely-not-a-binary-xyz".into()])
        .await
        .unwrap_err();
    assert!(missing.to_string().contains("failed to spawn"), "{missing}");
}

// ---- run / k8s 入参校验（解锁前的 bail） ----

#[tokio::test]
async fn run_rejects_empty_command_before_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let args = SecretsArgs {
        command: SecretsCommand::Run {
            env: vec![],
            command: vec![],
        },
    };
    let err = execute_with(args, &config_for(&dir), &ScriptedUi::new())
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("run requires a command"),
        "{err}"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn top_level_execute_routes_through_terminal_ui() {
    let _guard = env_guard();
    // PERSONA_MASTER_PASSWORD 优先于 ui 提示：TerminalUi 不会触交互
    let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let (_dir, config) = seeded_workspace().await;
    execute(resolve_args(&["work/login/name"]), &config)
        .await
        .unwrap();
}
