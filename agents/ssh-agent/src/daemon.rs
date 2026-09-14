//! Daemon lifecycle for the Persona SSH Agent.
//!
//! This module hosts the process-level code that cannot run inside a test
//! process:
//! - [`run_agent`]: initializes the global logger, binds the platform socket,
//!   writes agent state files, loads keys, and loops forever accepting
//!   connections. The accept loop never returns, so it cannot be exercised by
//!   a unit test.
//! - [`prompt_confirm_blocking`]: interactive consent prompt attached to
//!   `/dev/tty` (with a stdin/stdout fallback). It requires a real terminal,
//!   which does not exist in a test harness.
//!
//! Both functions are excluded from coverage measurement by passing this file
//! to `cargo llvm-cov` via `--ignore-filename-regex` (e.g.
//! `--ignore-filename-regex 'agents/ssh-agent/src/daemon.rs'`). Everything
//! testable lives in `lib.rs`, `policy.rs`, and `transport.rs`.

use anyhow::{anyhow, Context, Result};
use persona_core::RedactedLoggerBuilder;
use std::path::PathBuf;
use tracing::{info, warn, Level};

use crate::transport::{default_agent_path, AgentListener};
use crate::{handle_connection, resolve_persona_db_path, Agent};

/// Run the SSH agent daemon: bind the agent socket, load keys from the
/// Persona vault, and serve agent requests until the process is killed.
pub async fn run_agent() -> Result<()> {
    RedactedLoggerBuilder::new(Level::INFO)
        .include_target(false)
        .init()?;

    let socket_path = default_agent_path();
    let db_path = resolve_persona_db_path();

    // Create listener using cross-platform abstraction
    let mut listener = AgentListener::bind(&socket_path)
        .await
        .with_context(|| format!("Failed to bind socket {}", socket_path.display()))?;
    let mut endpoint = listener.address();
    if endpoint == "unknown" {
        endpoint = socket_path.display().to_string();
    }
    info!("persona-ssh-agent listening at {}", endpoint);
    println!("SSH_AUTH_SOCK={}", endpoint);

    // Write state files
    let state_dir = std::env::var("PERSONA_AGENT_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        });
    let _ = std::fs::create_dir_all(&state_dir);
    let sock_file = state_dir.join("ssh-agent.sock");
    let pid_file = state_dir.join("ssh-agent.pid");
    let _ = std::fs::write(&sock_file, &endpoint);
    let _ = std::fs::write(&pid_file, std::process::id().to_string());

    // Load keys from Persona
    let mut agent = Agent::new();
    agent
        .load_keys_from_persona(&db_path)
        .await
        .map_err(|e| anyhow!(e))?;
    info!("Loaded {} SSH keys from Persona", agent.keys.len());

    loop {
        let stream = listener.accept().await?;
        let mut agent_clone = agent.clone_shallow();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut agent_clone, stream).await {
                warn!("Connection error: {}", e);
            }
        });
    }
}

/// Blocking yes/no confirmation prompt.
///
/// Prefers `/dev/tty` so the question is always shown to the controlling
/// terminal even when stdout is redirected; falls back to stdin/stdout.
pub(crate) fn prompt_confirm_blocking(prompt: &str) -> Result<bool> {
    use std::io::{Read, Write};
    // Prefer /dev/tty for interactive consent
    if let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        let _ = write!(tty, "{}", prompt);
        let _ = tty.flush();
        let mut buf = [0u8; 3];
        let n = tty.read(&mut buf).unwrap_or(0);
        let s = String::from_utf8_lossy(&buf[..n]).to_lowercase();
        return Ok(s.starts_with('y'));
    }
    // Fallback to stdin/stdout
    print!("{}", prompt);
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let s = input.trim().to_lowercase();
        return Ok(s == "y" || s == "yes");
    }
    Ok(false)
}
