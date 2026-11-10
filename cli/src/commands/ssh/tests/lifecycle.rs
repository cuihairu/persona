use super::super::agent::{
    agent_binary_name, agent_state_dir, find_agent_binary_near, resolve_agent_binary,
    with_startup_deadline,
};
#[cfg(unix)]
use super::protocol::serve_one_identity_query;
use super::*;

#[tokio::test]
async fn run_with_host_validates_command_and_exit_status() {
    let _env = lock_process_env();
    let state_dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&state_dir);
    let dir = TempDir::new().unwrap();
    let config = userless_workspace(&dir).await;

    // A stored socket file makes the env branch pass the socket down.
    std::fs::write(
        agent_state_dir().join("ssh-agent.sock"),
        "/tmp/persona-run.sock",
    )
    .unwrap();

    // An empty command list is refused.
    let err = run_with_host("example.com", Vec::new(), &config)
        .await
        .expect_err("empty command must fail");
    assert!(err.to_string().contains("Provide a command after --"));

    // A successful command cleans the host file up afterwards. Extra
    // tokens after the binary are forwarded as arguments.
    let echo_cmd = if cfg!(target_os = "windows") {
        vec![
            "cmd".to_string(),
            "/C".to_string(),
            "echo".to_string(),
            "persona-ok".to_string(),
        ]
    } else {
        vec!["/bin/echo".to_string(), "persona-ok".to_string()]
    };
    execute_with(
        ssh_args(SshSubcommand::Run {
            host: "example.com".to_string(),
            command: echo_cmd,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("successful command works");
    assert!(
        !agent_state_dir().join("agent-target-host").exists(),
        "host file cleaned up"
    );

    // A failing command surfaces its exit status.
    let fail_cmd = if cfg!(target_os = "windows") {
        vec![
            "cmd".to_string(),
            "/C".to_string(),
            "exit".to_string(),
            "1".to_string(),
        ]
    } else {
        vec!["/bin/false".to_string()]
    };
    let err = run_with_host("example.com", fail_cmd, &config)
        .await
        .expect_err("failing command must fail");
    assert!(err.to_string().contains("Command exited with status"));
}

// ------------------------------------------------------------------
// status / stop / agent lifecycle.
// ------------------------------------------------------------------

#[tokio::test]
async fn execute_and_status_dispatch_without_service() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);
    let config = userless_workspace(&dir).await;

    // The thin execute() wrapper (TerminalUi): Status never touches the
    // service, so it is prompt-free even without a TTY.
    execute(ssh_args(SshSubcommand::Status), &config)
        .await
        .expect("status dispatch works");

    execute_with(
        ssh_args(SshSubcommand::AgentStatus),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("agent status dispatch works");

    // StopAgent without a PID file just reports.
    execute_with(
        ssh_args(SshSubcommand::StopAgent),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("stop without an agent works");
}

#[cfg(unix)]
#[tokio::test]
async fn agent_status_reports_files_and_queries_mock_agent() {
    use tokio::net::UnixListener;

    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);
    let _sock = EnvVarGuard::remove("SSH_AUTH_SOCK");
    let config = userless_workspace(&dir).await;

    // No state files: reports "not running".
    agent_status(&config)
        .await
        .expect("status without agent works");

    // Socket + pid files are reported.
    std::fs::write(
        dir.path().join("ssh-agent.sock"),
        "/tmp/persona-status.sock\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("ssh-agent.pid"), "424242\n").unwrap();
    agent_status(&config)
        .await
        .expect("status with files works");

    // A reachable agent answers the identity query — via the state file's
    // socket even while SSH_AUTH_SOCK points elsewhere (e.g. the system
    // agent): one status report must describe one agent.
    let listener = UnixListener::bind(dir.path().join("query.sock")).unwrap();
    let server = tokio::spawn(serve_one_identity_query(listener, 3));
    let stray_listener = UnixListener::bind(dir.path().join("stray.sock")).unwrap();
    let _env_sock = EnvVarGuard::set(
        "SSH_AUTH_SOCK",
        dir.path().join("stray.sock").to_string_lossy().to_string(),
    );
    std::fs::write(
        dir.path().join("ssh-agent.sock"),
        dir.path().join("query.sock").to_string_lossy().to_string(),
    )
    .unwrap();
    agent_status(&config)
        .await
        .expect("status with a live agent works");
    server.await.unwrap();
    // The env-pointed agent was never consulted.
    let stray_hit = tokio::time::timeout(
        std::time::Duration::from_millis(150),
        stray_listener.accept(),
    )
    .await;
    assert!(
        stray_hit.is_err(),
        "SSH_AUTH_SOCK must not be queried while a state file exists"
    );
    drop(stray_listener);

    // With no state file, the SSH_AUTH_SOCK socket is the fallback source.
    std::fs::remove_file(dir.path().join("ssh-agent.sock")).unwrap();
    let fallback_listener = UnixListener::bind(dir.path().join("fallback.sock")).unwrap();
    let _env_sock_fallback = EnvVarGuard::set(
        "SSH_AUTH_SOCK",
        dir.path()
            .join("fallback.sock")
            .to_string_lossy()
            .to_string(),
    );
    let fallback_server = tokio::spawn(serve_one_identity_query(fallback_listener, 1));
    agent_status(&config)
        .await
        .expect("status falls back to the env socket");
    fallback_server.await.unwrap();
}

#[cfg(unix)]
#[test]
fn stop_agent_handles_missing_empty_and_live_pid_files() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);

    // No PID file at all.
    stop_agent().expect("stop without a pid file works");

    // Whitespace-only PID file.
    std::fs::write(dir.path().join("ssh-agent.pid"), "  \n").unwrap();
    stop_agent().expect("stop with an empty pid file works");

    // A live process is stopped and the state files are cleaned up.
    // 通过 sh 的 $0 位置传入 "persona-ssh-agent"，让 /proc/<pid>/cmdline
    // 含 agent 名（否则会按"非 agent 进程"拒绝，无法走到杀进程分支）。
    // 不用改名软链：本机 coreutils 是按 argv[0] 分发的单二进制，改 argv[0]
    // 会直接拒绝运行（Security violation）。
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 5")
        .arg("persona-ssh-agent")
        .spawn()
        .expect("agent-named sh spawns");
    std::fs::write(dir.path().join("ssh-agent.pid"), child.id().to_string()).unwrap();
    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/persona-stop.sock").unwrap();
    stop_agent().expect("stop with a live pid works");
    let _ = child.wait(); // reap
    assert!(
        !dir.path().join("ssh-agent.pid").exists(),
        "pid file removed"
    );
    assert!(
        !dir.path().join("ssh-agent.sock").exists(),
        "sock file removed"
    );

    // A stale pidfile (PID already gone) is treated as already-stopped and
    // cleaned up, without erroring.
    std::fs::write(dir.path().join("ssh-agent.pid"), "99999999").unwrap();
    stop_agent().expect("a stale pidfile reports and cleans without error");
    assert!(
        !dir.path().join("ssh-agent.pid").exists(),
        "stale pid file removed"
    );
}

#[test]
fn agent_state_dir_falls_back_to_home_when_unset() {
    let _env = lock_process_env();
    let _state = EnvVarGuard::remove("PERSONA_AGENT_STATE_DIR");

    let dir = agent_state_dir();
    assert!(
        dir.ends_with(".persona"),
        "unset env falls back to ~/.persona, got {}",
        dir.display()
    );

    // The env override wins when present.
    let custom = TempDir::new().unwrap();
    let _override = EnvVarGuard::set("PERSONA_AGENT_STATE_DIR", custom.path());
    assert_eq!(agent_state_dir(), custom.path());
}

#[test]
fn resolve_agent_binary_env_overrides_and_fallbacks() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();

    // A valid file path is taken verbatim.
    let fake = dir.path().join("fake-agent");
    std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &fake);
    assert_eq!(resolve_agent_binary().unwrap(), fake);
    drop(_bin);

    // A non-file path is rejected.
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", dir.path().join("missing"));
    let err = resolve_agent_binary().expect_err("missing binary must fail");
    assert!(err.to_string().contains("does not point to a file"));
    drop(_bin);

    // Unset: falls back to a lookup near the current executable or the
    // bare name (which the shell would resolve).
    let _bin = EnvVarGuard::remove("PERSONA_SSH_AGENT_BIN");
    let resolved = resolve_agent_binary().unwrap();
    assert!(resolved.ends_with(agent_binary_name()));
}

#[test]
fn find_agent_binary_near_walks_exe_dir_then_deps_then_parent() {
    // The candidate order is the whole point of PATH-independent
    // resolution: cargo drops the agent beside the persona binary, `deps`
    // covers alternate layouts, and the parent covers target-rooted
    // installs. Pure filesystem walk — no process, no daemon — so every
    // platform (Windows included) covers the fallback order.
    let root = TempDir::new().unwrap();
    let exe_dir = root.path().join("debug");
    std::fs::create_dir_all(&exe_dir).unwrap();
    let exe = exe_dir.join("persona");
    let parent_planted = root.path().join("agent");

    // Nothing planted anywhere: no hit rather than a wrong guess.
    assert!(find_agent_binary_near(&exe, "agent").is_none());

    // Parent dir alone.
    std::fs::write(&parent_planted, b"").unwrap();
    assert_eq!(
        find_agent_binary_near(&exe, "agent"),
        Some(parent_planted.clone())
    );
    std::fs::remove_file(&parent_planted).unwrap();

    // `deps` outranks the parent dir.
    let deps_planted = exe_dir.join("deps").join("agent");
    std::fs::create_dir_all(exe_dir.join("deps")).unwrap();
    std::fs::write(&deps_planted, b"").unwrap();
    std::fs::write(&parent_planted, b"").unwrap();
    assert_eq!(
        find_agent_binary_near(&exe, "agent"),
        Some(deps_planted.clone())
    );

    // And the exe dir outranks `deps` — the layout cargo actually produces.
    let exe_planted = exe_dir.join("agent");
    std::fs::write(&exe_planted, b"").unwrap();
    assert_eq!(find_agent_binary_near(&exe, "agent"), Some(exe_planted));
}

#[tokio::test]
async fn startup_deadline_converts_silence_to_timeout_error() {
    // A daemon that stays silent must surface as a TimedOut error once
    // the deadline lapses, not hang the caller forever.
    let err = with_startup_deadline(
        std::time::Duration::from_millis(50),
        std::future::pending::<std::io::Result<()>>(),
    )
    .await
    .expect_err("a silent agent must surface as a timeout");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn startup_deadline_passes_through_completed_result() {
    let value = with_startup_deadline(std::time::Duration::from_secs(30), async { Ok(7) })
        .await
        .expect("completed futures pass through untouched");
    assert_eq!(value, 7);
}

#[cfg(unix)]
#[tokio::test]
async fn start_agent_parses_socket_line_and_failure_paths() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

    // Userless workspace: ensure_service never prompts; the agent's own
    // password prompt is bypassed by the non-interactive config.
    let mut config = userless_workspace(&dir).await;
    config.ui.interactive = false;

    // Success: the agent prints its socket; export lines are printed.
    let agent = write_executable(
        &dir,
        "agent-ok",
        "#!/bin/sh\necho \"SSH_AUTH_SOCK=/tmp/persona-fake.sock\"\n",
    );
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
    execute_with(
        ssh_args(SshSubcommand::StartAgent { print_export: true }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("fake agent with a socket line works");

    // The add-to-agent alias reaches the same code path.
    execute_with(
        ssh_args(SshSubcommand::AddToAgent {
            identity: None,
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("add-to-agent alias works");
    drop(_bin);

    // Early non-zero exit with stderr. start_agent detects the early exit
    // after stdout hits EOF; there is an inherent scheduling window where
    // the child is gone from the pipe but try_wait still reports None, so
    // retry a few times until the run resolves as a failure.
    let agent = write_executable(&dir, "agent-fail", "#!/bin/sh\necho boom >&2\nexit 3\n");
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
    let mut err = None;
    for _ in 0..10 {
        if let Some(e) = execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .err()
        {
            err = Some(e);
            break;
        }
    }
    let err = err.expect("failing agent must fail");
    assert!(err.to_string().contains("exited early with status"));
    assert!(err.to_string().contains("boom"), "stderr is surfaced");
    drop(_bin);

    // Early non-zero exit without stderr.
    let agent = write_executable(&dir, "agent-silent", "#!/bin/sh\nexit 7\n");
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
    let mut err = None;
    for _ in 0..10 {
        if let Some(e) = execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .err()
        {
            err = Some(e);
            break;
        }
    }
    let err = err.expect("silently failing agent must fail");
    assert!(err.to_string().contains("exited early with status"));
    drop(_bin);

    // Clean exit without a socket line degrades to a warning.
    let agent = write_executable(&dir, "agent-quiet", "#!/bin/sh\necho hello\n");
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
    execute_with(
        ssh_args(SshSubcommand::StartAgent {
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("quiet agent returns success");
    drop(_bin);

    // An interactive config is asked once for the agent's master
    // password; an empty answer is allowed. The fake agent sleeps so the
    // spawned process is still alive when start_agent returns.
    let agent_slow = write_executable(
        &dir,
        "agent-slow",
        "#!/bin/sh\necho \"SSH_AUTH_SOCK=/tmp/persona-slow.sock\"\nsleep 2\n",
    );
    let _bin_slow = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent_slow);
    config.ui.interactive = true;
    execute_with(
        ssh_args(SshSubcommand::StartAgent {
            print_export: false,
        }),
        &config,
        &ScriptedUi::new().password(""),
    )
    .await
    .expect("interactive start accepts an empty agent password");

    // A non-interactive start forwards PERSONA_MASTER_PASSWORD instead.
    config.ui.interactive = false;
    let _pw_env = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "env-pin");
    execute_with(
        ssh_args(SshSubcommand::StartAgent {
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("non-interactive start forwards the env password");

    // A failing interactive password prompt aborts before the agent
    // binary is even resolved.
    let dir2 = TempDir::new().unwrap();
    let _state2 = sandbox_agent_state_dir(&dir2);
    let mut config2 = userless_workspace(&dir2).await;
    config2.ui.interactive = true;
    let inner = ScriptedUi::new();
    let ui = FailOn::new(&inner, PromptKind::Password);
    let err = execute_with(
        ssh_args(SshSubcommand::StartAgent {
            print_export: false,
        }),
        &config2,
        &ui,
    )
    .await
    .expect_err("failing agent password prompt must abort");
    assert!(err.to_string().contains("failing ui: password prompt"));
}

#[cfg(unix)]
#[tokio::test]
async fn add_to_agent_identity_filter_env_reaches_the_agent() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);
    let _pw = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");
    let _no_filter = EnvVarGuard::remove("PERSONA_AGENT_IDENTITY");

    let mut config = unlocked_workspace(&dir, "master-pin").await;
    config.ui.interactive = false;

    // The fake agent records the filter env it was spawned with, then
    // reports its socket so start_agent completes.
    let capture = dir.path().join("identity-env");
    let agent = write_executable(
        &dir,
        "agent-capture",
        &format!(
            "#!/bin/sh\nprintf '%s' \"$PERSONA_AGENT_IDENTITY\" > \"{}\"\necho \"SSH_AUTH_SOCK=/tmp/persona-fake.sock\"\n",
            capture.display()
        ),
    );
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);

    execute_with(
        ssh_args(SshSubcommand::AddToAgent {
            identity: Some("bob".to_string()),
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("add-to-agent with --identity works");
    assert_eq!(
        std::fs::read_to_string(&capture).unwrap(),
        "bob",
        "the resolved identity name must reach the agent"
    );

    // Without --identity the env var is never passed.
    let _ = std::fs::remove_file(&capture);
    execute_with(
        ssh_args(SshSubcommand::StartAgent {
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("start-agent without --identity works");
    assert_eq!(
        std::fs::read_to_string(&capture).unwrap(),
        "",
        "no filter must leave the agent env empty"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn add_to_agent_unknown_identity_fails_before_spawn() {
    let _env = lock_process_env();
    let dir = TempDir::new().unwrap();
    let _state = sandbox_agent_state_dir(&dir);
    let _pw = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");

    let mut config = unlocked_workspace(&dir, "master-pin").await;
    config.ui.interactive = false;

    // The fake agent exits non-zero if it is ever reached — resolution
    // of an unknown identity must abort before spawning.
    let agent = write_executable(&dir, "agent-never", "#!/bin/sh\nexit 7\n");
    let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
    let err = execute_with(
        ssh_args(SshSubcommand::AddToAgent {
            identity: Some("ghost".to_string()),
            print_export: false,
        }),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown identity must abort before the agent starts");
    assert!(err.to_string().contains("Identity 'ghost' not found"));
}

#[tokio::test]
async fn list_skips_non_ssh_keys_and_agent_resolution_plants_binary() {
    let _env = lock_process_env();
    let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");
    let dir = TempDir::new().unwrap();
    let config = unlocked_workspace(&dir, "master-pin").await;

    // alice owns one SSH key and one API-key credential.
    let ui = ScriptedUi::new().password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::Generate {
            identity: "alice".to_string(),
            name: None,
            key_type: "ed25519".to_string(),
            comment: None,
            favorite: false,
        }),
        &config,
        &ui,
    )
    .await
    .expect("ssh key generated");
    assert!(ui.exhausted());
    {
        let _pw_env = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let service = ensure_service(&config, &ScriptedUi::new())
            .await
            .expect("service unlocks via env");
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        service
            .create_credential(
                identity.id,
                "api-token".to_string(),
                persona_core::models::CredentialType::ApiKey,
                persona_core::models::SecurityLevel::Medium,
                &persona_core::models::CredentialData::ApiKey(ApiKeyData {
                    api_key: "k".to_string(),
                    api_secret: None,
                    token: None,
                    permissions: Vec::new(),
                    expires_at: None,
                }),
            )
            .await
            .unwrap();
    }

    // Per-identity and global listings skip the non-SSH row. Each
    // execute_with call re-unlocks the workspace, so the scripted UI
    // needs a master password per subcommand.
    let ui = ScriptedUi::new()
        .password("master-pin")
        .password("master-pin");
    execute_with(
        ssh_args(SshSubcommand::List {
            identity: "alice".to_string(),
        }),
        &config,
        &ui,
    )
    .await
    .expect("per-identity list skips non-ssh rows");
    execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
        .await
        .expect("global list skips non-ssh rows");

    // A binary planted next to the current executable wins over the bare
    // PATH fallback once the env override is unset.
    let exe_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let planted = exe_dir.join(agent_binary_name());
    std::fs::write(&planted, b"#!/bin/sh\n").unwrap();
    let resolved = resolve_agent_binary().unwrap();
    std::fs::remove_file(&planted).unwrap();
    assert_eq!(resolved, planted);
}
