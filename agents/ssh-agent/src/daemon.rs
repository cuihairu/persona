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
use persona_core::BiometricProvider;

/// Explicit host-supplied configuration for an in-process agent.
///
/// Every set field takes precedence over the corresponding environment
/// variable (`PERSONA_MASTER_PASSWORD` / `PERSONA_DB_PATH` /
/// `PERSONA_AGENT_STATE_DIR` / `PERSONA_AGENT_SOCKET_PATH` /
/// `PERSONA_AGENT_REQUIRE_CONFIRM`), so hosts that run the agent inside a
/// multi-threaded process (e.g. the desktop app) never have to write
/// process-global environment state — a `std::env::set_var` in a running
/// multi-threaded process is a data race against concurrent `getenv`
/// calls, and a master password placed in the environment lingers there
/// for the whole process lifetime.
#[derive(Debug, Default, Clone)]
pub struct AgentEnvOverrides {
    /// Preferred over `PERSONA_MASTER_PASSWORD`. Consumed while loading
    /// keys, so it does not stay resident in memory afterwards.
    pub master_password: Option<String>,
    /// Preferred over `PERSONA_DB_PATH`.
    pub db_path: Option<PathBuf>,
    /// Preferred over `PERSONA_AGENT_STATE_DIR` (default `~/.persona`).
    pub state_dir: Option<PathBuf>,
    /// Preferred over `PERSONA_AGENT_SOCKET_PATH`.
    pub socket_path: Option<PathBuf>,
    /// Preferred over `PERSONA_AGENT_REQUIRE_CONFIRM`.
    pub require_confirm: Option<bool>,
}

/// Run the SSH agent daemon: bind the agent socket, load keys from the
/// Persona vault, and serve agent requests until the process is killed.
pub async fn run_agent() -> Result<()> {
    run_agent_with_hooks(None, None).await
}

/// Run the SSH agent daemon with a custom approval handler.
///
/// `None` keeps the default terminal prompt (TTY); hosts with a GUI
/// (e.g. the desktop app) inject their own [`ApprovalHandler`] so signature
/// confirmations surface as UI instead of stdin.
pub async fn run_agent_with_approval(approval: Option<Arc<dyn ApprovalHandler>>) -> Result<()> {
    run_agent_with_hooks(approval, None).await
}

/// Run the SSH agent daemon with both host-injected hooks.
///
/// `biometric` overrides the fail-closed default provider so
/// `require_biometric` policies can pass via the OS-backed ceremony; `None`
/// keeps the default (deny). `approval` as in
/// [`run_agent_with_approval`].
pub async fn run_agent_with_hooks(
    approval: Option<Arc<dyn ApprovalHandler>>,
    biometric: Option<Arc<dyn BiometricProvider>>,
) -> Result<()> {
    run_agent_with_hooks_and_env(approval, biometric, AgentEnvOverrides::default()).await
}

/// [`run_agent_with_hooks`] plus explicit [`AgentEnvOverrides`] for hosts
/// that must not touch the process environment.
pub async fn run_agent_with_hooks_and_env(
    approval: Option<Arc<dyn ApprovalHandler>>,
    biometric: Option<Arc<dyn BiometricProvider>>,
    env_overrides: AgentEnvOverrides,
) -> Result<()> {
    // 日志初始化绝不拦启动：内嵌进 desktop 时宿主壳已先装全局 subscriber
    // （文件 writer），此处再装只是无害地保持已装的。即便 init 将来出现
    // 其它失败形态，也不得让它变成 "SSH agent failed to start"。
    let _ = RedactedLoggerBuilder::new(Level::INFO)
        .include_target(false)
        .with_writer(|| Box::new(AgentLogSink))
        .init();

    let socket_path = env_overrides
        .socket_path
        .clone()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(default_agent_path);
    let db_path = match env_overrides.db_path.clone() {
        Some(db_path) => db_path,
        None => resolve_persona_db_path(),
    };

    // Create listener using cross-platform abstraction
    let mut listener = AgentListener::bind(&socket_path)
        .await
        .with_context(|| format!("Failed to bind socket {}", socket_path.display()))?;
    let mut endpoint = listener.address();
    if endpoint == "unknown" {
        endpoint = socket_path.display().to_string();
    }
    info!("persona-ssh-agent listening at {}", endpoint);

    // The parent that consumes the SSH_AUTH_SOCK line (e.g. `persona ssh
    // add-to-agent`) usually exits right after reading it, closing its ends
    // of both piped std streams. Every later stdout write then hits a broken
    // pipe; with the default SIGPIPE disposition that kills the daemon, so
    // the signal must be ignored. Ignoring alone is not enough: tracing
    // would then report the swallowed write error on stderr — and a failed
    // stderr write makes `eprintln!` panic, taking the connection task down.
    // `AgentLogSink` below drops broken-pipe output before tracing ever sees
    // an error. Windows has no SIGPIPE; the sink alone covers it there.
    #[cfg(unix)]
    // SAFETY: a plain signal-disposition call, no memory touched.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    println!("SSH_AUTH_SOCK={}", endpoint);

    // Write state files
    let state_dir = env_overrides
        .state_dir
        .clone()
        .or_else(|| {
            std::env::var("PERSONA_AGENT_STATE_DIR")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        });
    // State files are the host's readiness and status contract (the desktop
    // polls for the socket record file to decide "agent started"). A silent
    // write failure left the agent running while the host aborted it as
    // failed — surface the real cause instead.
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("Failed to create agent state dir {}", state_dir.display()))?;
    let sock_file = state_dir.join("ssh-agent.sock");
    let pid_file = state_dir.join("ssh-agent.pid");
    std::fs::write(&sock_file, &endpoint)
        .with_context(|| format!("Failed to write agent state file {}", sock_file.display()))?;
    std::fs::write(&pid_file, std::process::id().to_string())
        .with_context(|| format!("Failed to write agent state file {}", pid_file.display()))?;

    // Load keys from Persona
    let mut agent = Agent::new();
    if let Some(confirm) = env_overrides.require_confirm {
        agent = agent.with_require_confirm(confirm);
    }
    if let Some(password) = env_overrides.master_password {
        agent = agent.with_master_password(Some(password));
    }
    if let Some(handler) = approval {
        agent = agent.with_approval_handler(handler);
    }
    if let Some(provider) = biometric {
        agent = agent.with_biometric_provider(provider);
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

/// Best-effort stdout sink for daemon logging.
///
/// A daemon whose parent (e.g. `persona ssh add-to-agent`) has exited owns
/// no live reader for its stdout; writes fail there forever. Surfacing those
/// errors would make tracing-subscriber report them on stderr — and `eprintln!`
/// panics when stderr fails too, killing the connection task. So the sink
/// attempts the write and drops the event on any error; a foreground run
/// with a live terminal is unaffected.
struct AgentLogSink;

impl std::io::Write for AgentLogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        Ok(())
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

    #[tokio::test]
    async fn unwritable_state_dir_fails_startup_with_cause() {
        // The host's readiness check depends on the state files; a state dir
        // that cannot be written must fail the run with the real cause
        // instead of leaving a running agent the host will abort as failed.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"file").unwrap();
        let overrides = crate::AgentEnvOverrides {
            state_dir: Some(blocker.clone()),
            socket_path: Some(dir.path().join("agent.sock")),
            ..Default::default()
        };
        let err = run_agent_with_hooks_and_env(None, None, overrides)
            .await
            .expect_err("unwritable state dir must fail the run");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-dir") && msg.contains("state"),
            "error must name the state dir: {msg}"
        );
    }

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
