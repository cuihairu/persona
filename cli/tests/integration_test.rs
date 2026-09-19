use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::tempdir;

/// CLI integration tests
///
/// These tests verify that the CLI commands work correctly
/// and integrate properly with the persona-core library.

#[test]
fn test_cli_help() -> Result<()> {
    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Master your digital identity"));

    Ok(())
}

#[test]
fn test_cli_version() -> Result<()> {
    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));

    Ok(())
}

#[test]
fn test_init_command() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .arg("--encrypted")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Persona workspace initialized successfully",
        ));

    // Verify that workspace structure was created
    assert!(workspace_path.join("identities").exists());
    assert!(workspace_path.join("backups").exists());
    assert!(workspace_path.join("config.toml").exists());
    assert!(workspace_path.join("identities.db").exists());

    // Verify config file contents
    let config_content = fs::read_to_string(workspace_path.join("config.toml"))?;
    assert!(config_content.contains("encryption_enabled = true"));

    Ok(())
}

#[test]
fn test_init_without_encryption() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .assert()
        .success();

    let config_content = fs::read_to_string(workspace_path.join("config.toml"))?;
    assert!(config_content.contains("encryption_enabled = false"));

    Ok(())
}

#[test]
fn test_add_command_requires_workspace() -> Result<()> {
    let temp_dir = tempdir()?;
    let non_workspace_path = temp_dir.path();

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("add")
        .arg("Test Identity")
        .current_dir(non_workspace_path)
        .assert()
        .failure();
    // Should fail because no workspace is initialized

    Ok(())
}

#[test]
fn test_list_command_empty_workspace() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();

    // First initialize a workspace
    let mut init_cmd = Command::cargo_bin("persona")?;
    init_cmd
        .arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .assert()
        .success();

    // Then try to list identities (should be empty)
    let mut list_cmd = Command::cargo_bin("persona")?;
    list_cmd
        .arg("list")
        .current_dir(workspace_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("No identities found"));

    Ok(())
}

#[test]
fn test_workspace_validation() -> Result<()> {
    let temp_dir = tempdir()?;
    let invalid_path = temp_dir.path().join("nonexistent").join("path");

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(&invalid_path)
        .arg("--yes")
        .assert()
        .failure();
    // Should fail due to invalid path

    Ok(())
}

#[test]
fn test_config_file_generation() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .arg("--backup-dir")
        .arg(workspace_path.join("custom_backups"))
        .assert()
        .success();

    let config_content = fs::read_to_string(workspace_path.join("config.toml"))?;

    // Verify specific configuration values
    assert!(config_content.contains("version = \"0.1.0\""));
    assert!(config_content.contains("auto_lock_timeout = 300"));
    assert!(config_content.contains("color_enabled = true"));
    assert!(config_content.contains("custom_backups"));

    Ok(())
}

#[test]
fn test_init_config_toml_roundtrip() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();
    let backup_dir = workspace_path.join("custom_backups");

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .arg("--encrypted")
        .arg("--backup-dir")
        .arg(&backup_dir)
        .assert()
        .success();

    let config_content = fs::read_to_string(workspace_path.join("config.toml"))?;
    let config: toml::Value = toml::from_str(&config_content)?;

    assert_eq!(
        config
            .get("workspace")
            .and_then(|v| v.get("path"))
            .and_then(toml::Value::as_str),
        Some(workspace_path.to_string_lossy().as_ref())
    );
    assert_eq!(
        config
            .get("security")
            .and_then(|v| v.get("encryption_enabled"))
            .and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        config
            .get("backup")
            .and_then(|v| v.get("directory"))
            .and_then(toml::Value::as_str),
        Some(backup_dir.to_string_lossy().as_ref())
    );
    assert_eq!(
        config
            .get("ui")
            .and_then(|v| v.get("default_output_format"))
            .and_then(toml::Value::as_str),
        Some("table")
    );

    Ok(())
}

#[test]
fn test_init_with_master_password() -> Result<()> {
    let temp_dir = tempdir()?;
    let workspace_path = temp_dir.path();

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .arg("--encrypted")
        .arg("--master-password")
        .arg("test_password_123")
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized user authentication"));

    // Verify database was created and initialized
    assert!(workspace_path.join("identities.db").exists());
    let db_size = fs::metadata(workspace_path.join("identities.db"))?.len();
    assert!(
        db_size > 0,
        "Database should not be empty after initialization"
    );

    Ok(())
}

/// Test CLI argument validation
#[test]
fn test_invalid_arguments() -> Result<()> {
    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("nonexistent-command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));

    Ok(())
}

/// Test CLI global options
#[test]
fn test_verbose_flag() -> Result<()> {
    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("--verbose").arg("--help").assert().success();

    Ok(())
}

/// Test error handling for missing dependencies
#[test]
fn test_missing_config() -> Result<()> {
    let temp_dir = tempdir()?;

    let mut cmd = Command::cargo_bin("persona")?;
    cmd.arg("list")
        .current_dir(temp_dir.path())
        .assert()
        .failure();
    // Should fail because no workspace is configured

    Ok(())
}

#[test]
fn test_ssh_agent_status_and_stop_agent_without_running_agent() -> Result<()> {
    let workspace_dir = tempdir()?;
    let state_dir = tempdir()?;

    let mut init_cmd = Command::cargo_bin("persona")?;
    init_cmd
        .arg("init")
        .arg("--path")
        .arg(workspace_dir.path())
        .arg("--yes")
        .assert()
        .success();

    let mut status_cmd = Command::cargo_bin("persona")?;
    status_cmd
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("agent-status")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("persona-ssh-agent is not running"));

    let mut legacy_status_cmd = Command::cargo_bin("persona")?;
    legacy_status_cmd
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("status")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("persona-ssh-agent is not running"));

    let mut stop_cmd = Command::cargo_bin("persona")?;
    stop_cmd
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("stop-agent")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No agent PID file found"));

    Ok(())
}

#[test]
fn test_ssh_generate_export_remove_roundtrip() -> Result<()> {
    let workspace_dir = tempdir()?;
    let master_password = "test_password_123";

    let mut init_cmd = Command::cargo_bin("persona")?;
    init_cmd
        .arg("init")
        .arg("--path")
        .arg(workspace_dir.path())
        .arg("--yes")
        .assert()
        .success();

    let mut add_cmd = Command::cargo_bin("persona")?;
    add_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("add")
        .arg("Alice")
        .arg("--yes")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    let output = Command::cargo_bin("persona")?
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("generate")
        .arg("--identity")
        .arg("Alice")
        .arg("--name")
        .arg("Test Key")
        .current_dir(workspace_dir.path())
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let id_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("ID:"))
        .ok_or_else(|| anyhow::anyhow!("Expected an 'ID:' line in ssh generate output"))?;
    let id_str = id_line
        .split_once(':')
        .map(|(_, value)| value.trim())
        .unwrap_or("");
    let id = uuid::Uuid::parse_str(id_str)?;

    let mut export_cmd = Command::cargo_bin("persona")?;
    export_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("export-pub")
        .arg("--id")
        .arg(id.to_string())
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh-ed25519 "));

    let mut list_cmd = Command::cargo_bin("persona")?;
    list_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("list")
        .arg("--identity")
        .arg("Alice")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(id.to_string()));

    let mut list_all_cmd = Command::cargo_bin("persona")?;
    list_all_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("list-all")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Identity: Alice"))
        .stdout(predicate::str::contains(id.to_string()));

    let mut remove_cmd = Command::cargo_bin("persona")?;
    remove_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("remove")
        .arg("--id")
        .arg(id.to_string())
        .arg("--yes")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    let mut list_cmd = Command::cargo_bin("persona")?;
    list_cmd
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("list")
        .arg("--identity")
        .arg("Alice")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No SSH keys for this identity"));

    Ok(())
}

#[test]
fn test_ssh_start_agent_resolves_local_binary_without_path_entry() -> Result<()> {
    let workspace_dir = tempdir()?;
    let state_dir = tempdir()?;
    let master_password = "test_password_123";

    Command::cargo_bin("persona")?
        .arg("init")
        .arg("--path")
        .arg(workspace_dir.path())
        .arg("--yes")
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("add")
        .arg("Alice")
        .arg("--yes")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("generate")
        .arg("--identity")
        .arg("Alice")
        .arg("--name")
        .arg("Agent Key")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    let original_path = std::env::var("PATH").unwrap_or_default();
    let filtered_path = original_path
        .split(':')
        .filter(|entry| !entry.contains("/Users/cui/Workspaces/persona/target"))
        .collect::<Vec<_>>()
        .join(":");

    let build_status = StdCommand::new("cargo")
        .args(["build", "-p", "persona-ssh-agent"])
        .status()?;
    assert!(build_status.success(), "failed to build persona-ssh-agent");

    Command::cargo_bin("persona")?
        .env("PATH", filtered_path)
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("start-agent")
        .arg("--print-export")
        .current_dir(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Agent socket:"));

    Command::cargo_bin("persona")?
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("stop-agent")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Ok(())
}

#[cfg(not(windows))]
#[test]
fn test_ssh_run_injects_agent_socket_from_state_dir() -> Result<()> {
    let workspace_dir = tempdir()?;
    let state_dir = tempdir()?;
    let master_password = "test_password_123";

    Command::cargo_bin("persona")?
        .arg("init")
        .arg("--path")
        .arg(workspace_dir.path())
        .arg("--yes")
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("add")
        .arg("Alice")
        .arg("--yes")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .arg("ssh")
        .arg("generate")
        .arg("--identity")
        .arg("Alice")
        .arg("--name")
        .arg("Run Key")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    let build_status = StdCommand::new("cargo")
        .args(["build", "-p", "persona-ssh-agent"])
        .status()?;
    assert!(build_status.success(), "failed to build persona-ssh-agent");

    Command::cargo_bin("persona")?
        .env_remove("SSH_AUTH_SOCK")
        .env("PERSONA_NON_INTERACTIVE", "1")
        .env("PERSONA_MASTER_PASSWORD", master_password)
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("start-agent")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env_remove("SSH_AUTH_SOCK")
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("run")
        .arg("--host")
        .arg("github.com")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test -S \"$SSH_AUTH_SOCK\"")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Command::cargo_bin("persona")?
        .env("PERSONA_AGENT_STATE_DIR", state_dir.path())
        .arg("ssh")
        .arg("stop-agent")
        .current_dir(workspace_dir.path())
        .assert()
        .success();

    Ok(())
}

// ---------------------------------------------------------------------------
// 审计事件上报（PERSONA_SERVER_URL + PERSONA_SERVER_TOKEN）端到端
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

/// 单请求上报捕获：请求行 + authorization/content-encoding 头 + body。
struct CapturedRequest {
    request_line: String,
    authorization: String,
    content_encoding: String,
    body: String,
}

/// 头部完整且 body 读满 Content-Length 即收全（上报 JSON body 可能分片）。
fn request_complete(buf: &[u8]) -> bool {
    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..pos]);
    let content_length = head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if !k.trim().eq_ignore_ascii_case("content-length") {
            return None;
        }
        v.trim().parse::<usize>().ok()
    });
    match content_length {
        Some(len) => buf.len() >= pos + 4 + len,
        None => true,
    }
}

/// 读取并解析一个请求，回 202，把捕获写进共享 log（std 线程版假服务器，
/// 与 core/src/events/server_sink.rs 的 tokio 版同型）。
fn serve_one(mut stream: std::net::TcpStream, log: Arc<Mutex<Vec<CapturedRequest>>>) {
    use std::io::{Read, Write};
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if request_complete(&buf) {
                    break;
                }
            }
        }
    }
    let raw = String::from_utf8_lossy(&buf).to_string();
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut authorization = String::new();
    let mut content_encoding = String::new();
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case("authorization") {
            authorization = v.trim().to_string();
        } else if k.eq_ignore_ascii_case("content-encoding") {
            content_encoding = v.trim().to_string();
        }
    }
    let body_start = raw.find("\r\n\r\n").map_or(raw.len(), |i| i + 4);
    let body = raw[body_start.min(raw.len())..].to_string();
    let response_body = r#"{"accepted":1,"duplicates":0}"#;
    let response = format!(
        "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
    log.lock().unwrap().push(CapturedRequest {
        request_line,
        authorization,
        content_encoding,
        body,
    });
}

#[test]
fn audit_events_reported_when_server_env_configured() -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let log = Arc::new(Mutex::new(Vec::<CapturedRequest>::new()));
    let thread_log = log.clone();
    std::thread::spawn(move || {
        // 测试进程生命周期内逐个 accept；足够收完 init 的上报
        for stream in listener.incoming().flatten() {
            serve_one(stream, thread_log.clone());
        }
    });

    let temp_dir = tempdir()?;
    // init 必须实际建户（-e + --master-password → initialize_user 内部
    // log_audit）才有审计事件可报；--yes 无 -e 时不构造 service、零事件。
    // 经 main 尾部 stop() 最终 flush 上报。
    Command::cargo_bin("persona")?
        .arg("init")
        .arg("--path")
        .arg(temp_dir.path())
        .arg("--yes")
        .arg("-e")
        .arg("--master-password")
        .arg("smoke-master-pin")
        .env("PERSONA_SERVER_URL", format!("http://{addr}"))
        .env("PERSONA_SERVER_TOKEN", "dev")
        .assert()
        .success();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while log.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let requests = log.lock().unwrap();
    assert!(
        !requests.is_empty(),
        "init should report its audit events to the stub server"
    );
    assert!(
        requests[0]
            .request_line
            .starts_with("POST /api/v1/events HTTP/1.1"),
        "unexpected request line: {}",
        requests[0].request_line
    );
    assert_eq!(requests[0].authorization, "Bearer dev");
    // init 批远小于 1 KiB 阈值 → 明文直发（压缩路径由 core 测试覆盖）
    assert!(
        requests[0].content_encoding.is_empty(),
        "small batch must go plaintext, got content-encoding: {}",
        requests[0].content_encoding
    );
    assert!(
        requests[0].body.contains("\"events\""),
        "body should wrap events: {}",
        requests[0].body
    );

    Ok(())
}

#[test]
fn event_reporting_disabled_when_token_missing() -> Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let temp_dir = tempdir()?;
    // 只设 URL 缺 token → warn 并禁用，命令照常成功但没有任何上报
    Command::cargo_bin("persona")?
        .arg("init")
        .arg("--path")
        .arg(temp_dir.path())
        .arg("--yes")
        .env("PERSONA_SERVER_URL", format!("http://{addr}"))
        .env("PERSONA_SERVER_TOKEN", "")
        .assert()
        .success();

    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((_stream, _)) => panic!("no report should be sent without a token"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
