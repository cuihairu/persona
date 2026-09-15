//! Daemon lifecycle for the Persona SSH Agent.
//!
//! This module hosts the process-level entry points:
//! - [`run_agent`]: initializes the global logger, binds the platform socket,
//!   writes agent state files, loads keys, and loops forever accepting
//!   connections. The accept loop never returns on its own; the integration
//!   test in `tests/daemon_test.rs` drives it through the real socket with
//!   env-injected paths and keys, then aborts the task.
//! - [`prompt_confirm_blocking`]: interactive consent prompt attached to
//!   `/dev/tty` (with a stdin/stdout fallback). It needs a real terminal, so
//!   only its decision parsing (`tty_confirm_from_bytes` /
//!   `stdin_confirm_from_line`) is unit-tested here.

use anyhow::{anyhow, Context, Result};
use persona_core::RedactedLoggerBuilder;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, Level};

use crate::approval::ApprovalHandler;
use crate::transport::{default_agent_path, AgentListener};
use crate::{handle_connection, resolve_persona_db_path, Agent};

/// Run the SSH agent daemon: bind the agent socket, load keys from the
/// Persona vault, and serve agent requests until the process is killed.
pub async fn run_agent() -> Result<()> {
    run_agent_with_approval(None).await
}

/// Run the SSH agent daemon with a custom approval handler.
///
/// `None` keeps the default terminal prompt (TTY); hosts with a GUI
/// (e.g. the desktop app) inject their own [`ApprovalHandler`] so signature
/// confirmations surface as UI instead of stdin.
pub async fn run_agent_with_approval(approval: Option<Arc<dyn ApprovalHandler>>) -> Result<()> {
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
    if let Some(handler) = approval {
        agent = agent.with_approval_handler(handler);
    }
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
        return Ok(tty_confirm_from_bytes(&buf[..n]));
    }
    // Fallback to stdin/stdout
    print!("{}", prompt);
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        return Ok(stdin_confirm_from_line(&input));
    }
    Ok(false)
}

/// Parse a `/dev/tty` confirmation: the first bytes already decide, so "y",
/// "Y", and "yes" all allow (anything else denies).
pub(crate) fn tty_confirm_from_bytes(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes)
        .to_lowercase()
        .starts_with('y')
}

/// Parse a stdin confirmation line: only the exact answers "y"/"yes" (case
/// and surrounding whitespace insensitive) allow.
pub(crate) fn stdin_confirm_from_line(line: &str) -> bool {
    let s = line.trim().to_lowercase();
    s == "y" || s == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_confirm_accepts_y_prefix_answers() {
        for input in [&b"y"[..], &b"Y"[..], b"yes", b"ye!", b"Yes?"] {
            assert!(tty_confirm_from_bytes(input), "{input:?} should allow");
        }
    }

    #[test]
    fn tty_confirm_denies_everything_else() {
        for input in [&b"n"[..], b"no", b"", &b"\n"[..], b"0xff!?"] {
            assert!(!tty_confirm_from_bytes(input), "{input:?} should deny");
        }
    }

    #[test]
    fn stdin_confirm_requires_exact_answer() {
        assert!(stdin_confirm_from_line("y"));
        assert!(stdin_confirm_from_line("YES"));
        assert!(stdin_confirm_from_line("  yes\r\n"));
        assert!(!stdin_confirm_from_line("ye"));
        assert!(!stdin_confirm_from_line("yes please"));
        assert!(!stdin_confirm_from_line(""));
        assert!(!stdin_confirm_from_line("no"));
    }
}
