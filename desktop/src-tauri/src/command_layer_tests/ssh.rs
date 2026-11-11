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
/// get_ssh_keys 只挑出 SshKey 凭据并带 identity 名；health_scan 出报告。
#[tokio::test]
async fn get_ssh_keys_and_health_scan() {
    let app = mock_app();

    let resp = get_ssh_keys(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = health_scan(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let (app, identity_id) = app_with_identity().await;

    // 一个 SSH key + 一个 Password 凭据：只有前者出现在列表里。
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

    // 健康扫描：无参数默认值 + 自定义阈值都出报告。
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
/// `query_agent_key_count` 走 std 同步 socket（不经过 tokio reactor，不受
/// mock 运行时毒化影响）：起一个本地假 agent 服务端按脚本回协议响应，
/// 覆盖成功计数与各错误分支。
#[cfg(unix)]
#[test]
fn query_agent_key_count_protocol_matrix() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();

    // 假 agent：读 5 字节 request_identities 请求，回 `payload`。
    // 返回 (socket 路径, responder 句柄)；join 必须发生在客户端连接之后，
    // 否则 responder 卡在 accept 而客户端还没跑起来，直接死锁。
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

    // 成功：SSH_AGENT_IDENTITIES_ANSWER(12) + 3 把钥匙。
    let (path, responder) = serve_once(vec![12, 0, 0, 0, 3]);
    assert_eq!(query_agent_key_count(&path).unwrap(), 3);
    responder.join().unwrap();

    // 首 byte 非 12 → "Unexpected agent response"。
    let (path, responder) = serve_once(vec![99, 0, 0, 0, 3]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Unexpected agent response"
    );
    responder.join().unwrap();

    // 响应过短 → "Malformed agent response"。
    let (path, responder) = serve_once(vec![12, 0]);
    assert_eq!(
        query_agent_key_count(&path).unwrap_err(),
        "Malformed agent response"
    );
    responder.join().unwrap();

    // 连不上 → 连接错误。
    let err = query_agent_key_count(&dir.path().join("absent.sock").to_string_lossy()).unwrap_err();
    assert!(err.starts_with("Failed to connect to agent"), "{}", err);
}
/// 状态文件内容畸形时不 panic：pid 解析失败降级为 None。
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
    // 畸形内容本身不许 panic；socket 指向的路径不可连接（无此文件），无
    // 任务句柄 → 不算运行中（字段照常回显，pid 解析失败降级 None）。
    assert!(
        !status.running,
        "malformed state files with no live agent must not mean running"
    );
    assert_eq!(status.socket_path.as_deref(), Some("/tmp/empty-sock"));
    assert_eq!(status.pid, None, "unparseable pid degrades to None");
}
/// PERSONA_AGENT_STATE_DIR 未设置时 agent_state_dir 回落 ~/.persona。
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

    // 服务端：接受连接后立刻丢弃，制造对端 EOF。
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("client connects");
        drop(stream);
    });

    let result = query_agent_key_count(sock_path.to_str().unwrap());
    assert!(result.is_err(), "dead socket must error, not hang");

    server.join().unwrap();
}
/// get_ssh_keys 的未初始化/死库臂与 stop_ssh_agent 的空转臂（无 agent 可停
/// 也要返回成功并清理环境变量）。
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

    // 已解锁但 DB 是垃圾文件：get_identities 的 repo 错误落 ApiResponse。
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

    // 空 state 目录 + 任务句柄"存活"：没有 socket/pid 证据不许报运行中。
    // 旧实现 running_hint 直通——启动失败被吞成假绿，此断言钉死修复。
    let status = crate::commands::read_agent_status(true);
    assert!(!status.running);
    assert!(status.socket_path.is_none());
    assert!(status.pid.is_none());

    // 句柄存活 + state 文件在 → 运行中，字段如实回读。
    std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/persona-fake.sock").unwrap();
    std::fs::write(dir.path().join("ssh-agent.pid"), "12345").unwrap();
    let status = crate::commands::read_agent_status(true);
    assert!(status.running);
    assert_eq!(
        status.socket_path.as_deref(),
        Some("/tmp/persona-fake.sock")
    );
    assert_eq!(status.pid, Some(12345));

    // 句柄已死（hint=false）：残留 state 文件不算运行中。
    let status = crate::commands::read_agent_status(false);
    assert!(!status.running);
}
#[cfg(unix)]
#[tokio::test]
async fn start_ssh_agent_surfaces_bind_failure_as_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = mock_app();
    init_service_ok(&app, "correct-horse").await;

    // 注入指向不存在目录的 socket 路径 → daemon bind 失败退出。修复前：
    // 错误被 eprintln 吞掉、命令睡 400ms 后无条件报"运行中"。修复后必须
    // 回 error 响应并写明原因（Windows 同一代码路径，实机验收待装机器）。
    // 两个 agent env 由同一 guard 持同一把锁注入（不可重入，分开即死锁）。
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

    // 失败路径清掉 state 文件，不留假证据。
    assert!(!dir.path().join("ssh-agent.sock").exists());
    assert!(!dir.path().join("ssh-agent.pid").exists());

    // 状态查询如实报 stopped。
    let resp = get_ssh_agent_status(app.state::<AppState>()).await.unwrap();
    assert!(resp.success);
    assert!(!resp.data.unwrap().running);
}
