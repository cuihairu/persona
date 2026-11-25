use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;
use anyhow::{bail, Context, Result};

use super::open_unlocked;
use super::refs::{parse_env_assignments, resolve_ref};

// -----------------------------------------------------------------------
// run (the generic shell plugins mechanism: env injection + foreground forwarding)
// -----------------------------------------------------------------------

/// Spawn a child process: inherits the parent environment plus the injected resolved
/// variables; stdio passes straight through. Kept as a separate function so the exit-code
/// branches can be tested (bypassing execute's exit short-circuit).
pub(crate) async fn spawn_with_env(
    assignments: &[(String, String)],
    command: &[std::ffi::OsString],
) -> Result<std::process::ExitStatus> {
    let (program, rest) = command
        .split_first()
        .with_context(|| "run requires a command after `--`")?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(rest);
    for (name, value) in assignments {
        cmd.env(name, value);
    }
    cmd.status()
        .await
        .with_context(|| format!("failed to spawn {}", program.to_string_lossy()))
}

pub(super) async fn run_command(
    config: &CliConfig,
    ui: &dyn PromptUi,
    env_specs: &[String],
    command: &[std::ffi::OsString],
) -> Result<()> {
    if command.is_empty() {
        bail!("run requires a command after `--`");
    }
    let parsed = parse_env_assignments(env_specs)?;
    let service = open_unlocked(config, ui).await?;
    // Resolve everything before spawning: a bad reference must not launch a child with a half-injected environment
    let mut assignments = Vec::with_capacity(parsed.len());
    for (name, secret_ref) in &parsed {
        let value = resolve_ref(&service, secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        assignments.push((name.clone(), value));
    }
    let status = spawn_with_env(&assignments, command).await?;
    if status.success() {
        return Ok(());
    }
    // Forward the child's exit code (tests only go through spawn_with_env, never this exit short-circuit)
    std::process::exit(status.code().unwrap_or(1));
}
