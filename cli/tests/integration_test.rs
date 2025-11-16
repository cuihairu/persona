use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use std::fs;

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
        .stdout(predicate::str::contains("Persona workspace initialized successfully"));

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
    init_cmd.arg("init")
        .arg("--path")
        .arg(workspace_path)
        .arg("--yes")
        .assert()
        .success();

    // Then try to list identities (should be empty)
    let mut list_cmd = Command::cargo_bin("persona")?;
    list_cmd.arg("list")
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
    assert!(db_size > 0, "Database should not be empty after initialization");

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
    cmd.arg("--verbose")
        .arg("--help")
        .assert()
        .success();

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