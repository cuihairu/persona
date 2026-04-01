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
    let id_str = id_line.splitn(2, ':').nth(1).unwrap_or("").trim();
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
