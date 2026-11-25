//! Command-layer integration tests — `ssh` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[cfg(unix)]
#[tokio::test]
async fn ssh_agent_status_reflects_state_files() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);

    // No handle, no state files: not running.
    let app = mock_app();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let status = resp.data.unwrap();
    assert!(!status.running);
    assert_eq!(status.socket_path, None);
    assert_eq!(status.pid, None);
    assert_eq!(status.state_dir, dir.path().to_string_lossy().to_string());

    // A socket file surfaces the path, but with no live agent task and no
    // connectable socket it must NOT flip running: the old `hint || files`
    // OR-chain stayed green on stale files left by a crashed agent (the
    // "click start, nothing happens" bug). key_count stays None either way.
    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/nowhere.sock").unwrap();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert!(
        !status.running,
        "stale socket file without a live agent is not running"
    );
    assert_eq!(status.socket_path.as_deref(), Some("/tmp/nowhere.sock"));
    assert_eq!(status.key_count, None);

    // External agent (no desktop task handle): a genuinely listening socket
    // at the recorded path probes alive → running stays truthful for the
    // CLI-launched daemon scenario.
    let ext = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(ext.path().join("live.sock")).unwrap();
    let ext_path = ext.path().join("live.sock").to_string_lossy().to_string();
    std::fs::write(dir.path().join("ssh-agent.sock"), &ext_path).unwrap();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert!(
        status.running,
        "connectable socket means an external agent is alive"
    );
    assert_eq!(status.socket_path.as_deref(), Some(ext_path.as_str()));
    drop(listener);

    // A pid file surfaces the parsed pid.
    std::fs::write(dir.path().join("ssh-agent.pid"), "424242\n").unwrap();
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    assert_eq!(status.pid, Some(424242));
}
#[tokio::test]
async fn start_stop_ssh_agent_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    // Bind inside the sandbox dir: the real stable socket path is probed by
    // the parallel ssh_integration analysis tests (socket_alive), so a
    // lifecycle bind there makes them see a live agent and flake.
    // sandbox_with_socket holds the process env lock for the whole test,
    // which also serializes against the bind-failure test.
    #[cfg(unix)]
    let _guard = StateDirGuard::sandbox_with_socket(&dir, &dir.path().join("agent.sock"));
    #[cfg(not(unix))]
    let _guard = StateDirGuard::sandbox(&dir);
    let app = mock_app();

    // Start before initialization: db path unknown. Boundary discipline:
    // infrastructure failures come back as Ok(ApiResponse::error), never as
    // an invoke-layer Err(String).
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );

    init_service_ok(&app, "correct-horse").await;

    // One SSH key in the vault: after start the agent must have loaded it
    // through the injected master password (regression: the password is
    // passed as a parameter now, not via PERSONA_MASTER_PASSWORD).
    let resp = create_identity(
        CreateIdentityRequest {
            name: "Agent Loader".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let identity_id = resp.data.expect("identity created").id;
    let resp = generate_ssh_key(
        GenerateSshKeyRequest {
            identity_id: identity_id.clone(),
            key_type: "ed25519".to_string(),
            comment: Some("lifecycle@test".to_string()),
            name: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "key generation failed: {:?}", resp.error);

    // Start boots the in-process agent; status reports running.
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "agent start failed: {:?}", resp.error);
    assert!(resp.data.unwrap().running, "agent handle is alive");

    // Regression: the agent must be configured via explicit parameters, the
    // spawn task must not leak the master password into the process env.
    assert!(
        std::env::var("PERSONA_MASTER_PASSWORD").is_err(),
        "master password must not linger in the environment"
    );

    // The agent bound its socket in the sandboxed state dir.
    let sock = dir.path().join("ssh-agent.sock");
    let bound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !sock.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "agent socket never appeared at {sock:?}");

    // The injected master password unlocked the vault and the key loaded.
    // Keys are loaded after the socket binds (argon2 unlock takes seconds in
    // debug builds, longer under full-suite CPU contention), so the probe
    // retries with a ~30s budget until the accept loop is serving.
    #[cfg(unix)]
    {
        // the state file records the endpoint the daemon actually bound
        let endpoint = std::fs::read_to_string(&sock).expect("read agent endpoint");
        let mut count = None;
        for _ in 0..40 {
            if let Ok(n) = query_agent_key_count(endpoint.trim()) {
                count = Some(n);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        assert_eq!(count, Some(1), "agent must serve the vault's SSH key");
    }

    // A second start while running returns the current status (no reboot).
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().running);

    // Stop aborts the agent and clears pending approvals.
    let resp = stop_ssh_agent(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(!resp.data.unwrap().running, "no handle and no socket left");
}
/// get_ssh_keys picks out only SshKey credentials with their identity name; health_scan produces a report.
#[tokio::test]
async fn get_ssh_keys_and_health_scan() {
    let app = mock_app();

    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = health_scan(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let (app, identity_id) = app_with_identity().await;

    // One SSH key + one Password credential: only the former appears in the list.
    let ssh_req = CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: "GitHub SSH".to_string(),
        credential_type: "SshKey".to_string(),
        security_level: "High".to_string(),
        url: None,
        username: Some("git".to_string()),
        notes: None,
        tags: Some(vec!["git".to_string()]),
        credential_data: CredentialDataRequest::SshKey {
            private_key: "data:private-key-blob".to_string(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB test@persona".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        },
    };
    let resp = create_credential(ssh_req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let keys = resp.data.unwrap();
    assert_eq!(keys.len(), 1, "only the SshKey credential is listed");
    assert_eq!(keys[0].name, "GitHub SSH");
    assert_eq!(keys[0].identity_name, "Cred Holder");
    assert_eq!(keys[0].tags, vec!["git".to_string()]);

    // Health scan: both no-arg defaults and custom thresholds produce a report.
    let resp = health_scan(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let report = resp.data.expect("health report");
    assert_eq!(report.total_credentials, 2);

    let resp = health_scan(
        Some(HealthScanRequest {
            min_password_score: Some(3),
            expiry_warning_days: Some(30),
            stale_after_days: Some(90),
            check_breaches: Some(false),
        }),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().total_credentials, 2);
}
/// `query_agent_key_count` uses a std synchronous socket (bypassing the tokio
/// reactor, so it is not poisoned by the mock runtime): a local fake agent
/// server replies with scripted protocol responses, covering the success count
/// and every error branch.
#[cfg(unix)]
#[test]
fn query_agent_key_count_protocol_matrix() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();

    // Fake agent: reads the 5-byte request_identities request and replies with `payload`.
    // Returns (socket path, responder handle); join must happen after the client
    // connects, otherwise the responder blocks in accept while the client never
    // gets to run -- a guaranteed deadlock.
    let serve_once = |payload: Vec<u8>| -> (String, std::thread::JoinHandle<()>) {
        let sock_path = dir
            .path()
            .join(format!("agent-{}.sock", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&sock_path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 5];
            stream.read_exact(&mut req).unwrap();
            // SSH_AGENTC_REQUEST_IDENTITIES = 11
            assert_eq!(req[4], 11, "client must ask for identities");
            let mut resp = vec![0, 0, 0, payload.len() as u8];
            resp.extend_from_slice(&payload);
            stream.write_all(&resp).unwrap();
        });
        let path = sock_path.to_string_lossy().to_string();
        (path, handle)
    };

    // Success: SSH_AGENT_IDENTITIES_ANSWER(12) + 3 keys.
    let (path, responder) = serve_once(vec![12, 0, 0, 0, 3]);
    assert_eq!(query_agent_key_count(&path).unwrap(), 3);
    responder.join().unwrap();

    // First byte not 12 -> "Unexpected agent response".
    let (path, responder) = serve_once(vec![99, 0, 0, 0, 3]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Unexpected agent response"
    );
    responder.join().unwrap();

    // Response too short -> "Malformed agent response".
    let (path, responder) = serve_once(vec![12, 0]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Malformed agent response"
    );
    responder.join().unwrap();

    // Cannot connect -> connection error.
    let err = query_agent_key_count(&dir.path().join("absent.sock").to_string_lossy()).unwrap_err();
    assert!(err.starts_with("Failed to connect to agent"), "{}", err);
}
/// No panic when the state file contents are malformed: pid parse failure degrades to None.
#[cfg(unix)]
#[tokio::test]
async fn ssh_agent_status_tolerates_malformed_state_files() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);
    let app = mock_app();

    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/empty-sock\n").unwrap();
    std::fs::write(dir.path().join("ssh-agent.pid"), "not-a-number").unwrap();

    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    let status = resp.data.unwrap();
    // The malformed content itself must not panic; the path the socket points to is
    // not connectable (file absent) and there is no task handle -> not running
    // (fields echoed as-is, pid parse failure degrades to None).
    assert!(
        !status.running,
        "malformed state files with no live agent must not mean running"
    );
    assert_eq!(status.socket_path.as_deref(), Some("/tmp/empty-sock"));
    assert_eq!(status.pid, None, "unparseable pid degrades to None");
}
/// When PERSONA_AGENT_STATE_DIR is unset, agent_state_dir falls back to ~/.persona.
#[test]
fn agent_state_dir_falls_back_to_home_when_env_unset() {
    let _guard = crate::command_layer_tests::StateDirGuard::without_env();
    let dir = agent_state_dir();
    assert!(
        dir.ends_with(".persona"),
        "fallback should be ~/.persona, got {dir:?}"
    );
}
#[cfg(unix)]
#[test]
fn query_agent_key_count_fails_on_dead_socket() {
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("dead.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    // Server: drops the connection immediately after accepting, producing a peer EOF.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("client connects");
        drop(stream);
    });

    let result = query_agent_key_count(sock_path.to_str().unwrap());
    assert!(result.is_err(), "dead socket must error, not hang");

    server.join().unwrap();
}
/// The uninitialized/dead-DB arms of get_ssh_keys and the no-op arm of
/// stop_ssh_agent (with no agent to stop it still returns success and cleans
/// up the environment variables).
#[tokio::test]
async fn ssh_key_listing_and_agent_stop_small_arms() {
    // stop_ssh_agent cleans up state files in the current agent state dir;
    // without a sandbox + the process env lock it deletes the state files of
    // whatever agent test runs in parallel.
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);
    let app = mock_app();
    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = stop_ssh_agent(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data, Some(true));

    // Unlocked but the DB is a garbage file: get_identities' repo error lands in the ApiResponse.
    let app = app_with_garbage_db_service().await;
    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Failed to load identities") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );
}
#[tokio::test]
async fn read_agent_status_requires_state_file_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let _guard = StateDirGuard::sandbox(&dir);

    // Empty state dir + task handle "alive": no socket/pid evidence must not report running.
    // The old implementation passed running_hint straight through -- startup failure was
    // swallowed into a false green; this assertion pins the fix.
    let status = crate::commands::read_agent_status(true);
    assert!(!status.running);
    assert!(status.socket_path.is_none());
    assert!(status.pid.is_none());

    // Handle alive + state files present -> running, fields read back faithfully.
    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/persona-fake.sock").unwrap();
    std::fs::write(dir.path().join("ssh-agent.pid"), "12345").unwrap();
    let status = crate::commands::read_agent_status(true);
    assert!(status.running);
    assert_eq!(
        status.socket_path.as_deref(),
        Some("/tmp/persona-fake.sock")
    );
    assert_eq!(status.pid, Some(12345));

    // Handle dead (hint=false): leftover state files do not count as running.
    let status = crate::commands::read_agent_status(false);
    assert!(!status.running);
}
#[cfg(unix)]
#[tokio::test]
async fn start_ssh_agent_surfaces_bind_failure_as_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // Inject a socket path in a nonexistent directory -> daemon bind fails and exits. Before the
    // fix: the error was swallowed by eprintln and the command slept 400ms then unconditionally
    // reported "running". After the fix it must return an error response stating the reason
    // (same code path on Windows; on-device acceptance pending a machine).
    // Both agent envs are injected by the same guard holding the same lock (non-reentrant;
    // splitting them deadlocks).
    let _guard = StateDirGuard::sandbox_with_socket(
        &dir,
        &dir.path().join("no-such-subdir/persona-agent.sock"),
    );
    let resp = start_ssh_agent(
        StartAgentRequest {
            master_password: Some("correct-horse".to_string()),
        },
        app.state::<AppState>(),
        app.handle().clone(),
    )
    .await
    .unwrap();
    assert!(
        !resp.success,
        "bind failure must not report success: {:?}",
        resp.data
    );
    let err = resp.error.clone().unwrap_or_default();
    assert!(
        err.contains("SSH agent failed to start"),
        "error must state the failure, got: {err}"
    );

    // The failure path clears the state files, leaving no false evidence.
    assert!(!dir.path().join("ssh-agent.sock").exists());
    assert!(!dir.path().join("ssh-agent.pid").exists());

    // Status query faithfully reports stopped.
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success);
    assert!(!resp.data.unwrap().running);
}
