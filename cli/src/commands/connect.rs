//! `persona connect …`: Connect local automation (token management + serve).
//!
//! Gating and scope decisions live in core (`persona_core::connect` plus the
//! service method family), the HTTP surface lives in a separate crate
//! (`persona_connect_server`, sharing the same router/three defense lines/
//! rate limits with the desktop). This module only orchestrates: unlock, scope
//! parameter parsing, one-time plaintext display, and foreground serve (exit on
//! Ctrl-C, no daemonization — DR-1 A2; the systemd user unit is configured by
//! the user). Master password resolution follows the service.rs convention
//! (`PERSONA_MASTER_PASSWORD` env takes priority), and serve additionally
//! supports `--passphrase-env VAR` (the explicit variable must already be set
//! and non-empty; no silent fallback).

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::core_ext::CoreResultExt;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};
use persona_core::storage::Database;
use persona_core::PersonaService;

#[derive(Args)]
pub struct ConnectArgs {
    #[command(subcommand)]
    command: ConnectCommand,
}

#[derive(Subcommand)]
enum ConnectCommand {
    /// Manage Connect tokens (plaintext shown only once, at creation)
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Start the Connect listener in the foreground (loopback TCP or unix socket, exits on Ctrl-C)
    Serve {
        /// Port to listen on (default 0 = assigned by the OS; TCP transport only)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Use a Unix domain socket instead (0600 file + owner uid check; may carry a
        /// path, defaulting to $XDG_RUNTIME_DIR/persona/connect.sock, falling back to
        /// ~/.persona/connect.sock when XDG_RUNTIME_DIR is unset). Mutually exclusive
        /// with --port; errors on Windows
        #[arg(long, value_name = "PATH", num_args = 0..=1)]
        unix_socket: Option<Option<std::path::PathBuf>>,
        /// Read the master password from the given environment variable (must be set and non-empty)
        #[arg(long)]
        passphrase_env: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a token: scope uses "default = all" semantics, narrowing whenever limits are given
    Create {
        /// Token label (e.g. "my CI script")
        #[arg(long)]
        label: String,
        /// Restrict readable identities (by name, repeatable; default = all identities)
        #[arg(long = "identity")]
        identities: Vec<String>,
        /// Restrict readable entry types (snake_case, repeatable; default = all authorizable types)
        #[arg(long = "type")]
        item_types: Vec<String>,
        /// Validity duration (<positive integer><s|m|h|d>, e.g. 30d / 12h / 30m; default = never expires)
        #[arg(long = "expires-in")]
        expires_in: Option<String>,
    },
    /// List tokens (including revoked; fingerprints only, the plaintext is not recoverable)
    List,
    /// Revoke a token (takes effect immediately, idempotent; accepts an id or a fingerprint)
    Revoke {
        /// Token id (UUID) or fingerprint (the hex shown in the list)
        target: String,
    },
}

pub async fn execute(args: ConnectArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: ConnectArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        ConnectCommand::Token { command } => match command {
            TokenCommand::Create {
                label,
                identities,
                item_types,
                expires_in,
            } => {
                create_token(
                    config,
                    ui,
                    &label,
                    &identities,
                    &item_types,
                    expires_in.as_deref(),
                )
                .await
            }
            TokenCommand::List => list_tokens(config, ui).await,
            TokenCommand::Revoke { target } => revoke_token(config, ui, &target).await,
        },
        ConnectCommand::Serve {
            port,
            unix_socket,
            passphrase_env,
        } => serve(config, ui, port, unix_socket, passphrase_env.as_deref()).await,
    }
}

// -----------------------------------------------------------------------
// Unlock (serve's --passphrase-env explicit variable takes priority; token subcommands follow the convention chain)
// -----------------------------------------------------------------------

/// Open the vault + migrate + build the service and unlock (bails immediately on auth failure / not initialized).
async fn open_unlocked(
    config: &CliConfig,
    ui: &dyn PromptUi,
    passphrase_env: Option<&str>,
) -> Result<PersonaService> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {}", e))?;
    let mut service = crate::commands::service::new_service(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {}", e))?;
    if !service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {}", e))?
    {
        bail!("Workspace not initialized. Run `persona init` first");
    }

    let password = match passphrase_env {
        Some(var) => std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"))?,
        None => crate::commands::service::prompt_master_password(ui)?,
    };
    match service
        .authenticate_user(&password)
        .await
        .map_err(|e| anyhow!("Failed to authenticate user: {}", e))?
    {
        persona_core::auth::authentication::AuthResult::Success => Ok(service),
        other => bail!("Authentication failed: {:?}", other),
    }
}

// -----------------------------------------------------------------------
// token management
// -----------------------------------------------------------------------

/// Scope vocabulary parsing: consistent with the serde snake_case of core `ConnectItemType`.
/// The error message lists every legal value (fail-fast, no nearest-neighbor guessing).
fn parse_item_type(raw: &str) -> Result<ConnectItemType> {
    let value = serde_json::Value::String(raw.to_string());
    serde_json::from_value(value).map_err(|_| {
        anyhow!(
            "unknown item type {raw:?} (valid: password, api_key, totp, note, \
                 bank_card, server_config, certificate, game_account, identity, \
                 software_license)"
        )
    })
}

/// Parse the `--expires-in` duration: `<positive integer><s|m|h|d>` (e.g. `30d`, `12h`, `30m`).
/// A relative duration counted from creation time; omitting it means never expiring (existing semantics).
fn parse_expires_in(raw: &str) -> Result<chrono::Duration> {
    let Some(idx) = raw.find(|c: char| !c.is_ascii_digit()) else {
        bail!("invalid duration {raw:?}: expected <number><unit> like 30d, 12h, 30m");
    };
    let (digits, unit) = raw.split_at(idx);
    let amount: i64 = digits
        .parse()
        .map_err(|_| anyhow!("invalid duration {raw:?}: number out of range"))?;
    if amount <= 0 {
        bail!("invalid duration {raw:?}: must be positive");
    }
    let multiplier: i64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => bail!("invalid duration {raw:?}: unknown unit {other:?} (valid: s, m, h, d)"),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("invalid duration {raw:?}: out of range"))?;
    chrono::Duration::try_seconds(seconds)
        .ok_or_else(|| anyhow!("invalid duration {raw:?}: out of range"))
}

fn type_name(t: &ConnectItemType) -> &'static str {
    match t {
        ConnectItemType::Password => "password",
        ConnectItemType::ApiKey => "api_key",
        ConnectItemType::Totp => "totp",
        ConnectItemType::Note => "note",
        ConnectItemType::BankCard => "bank_card",
        ConnectItemType::ServerConfig => "server_config",
        ConnectItemType::Certificate => "certificate",
        ConnectItemType::GameAccount => "game_account",
        ConnectItemType::Identity => "identity",
        ConnectItemType::SoftwareLicense => "software_license",
    }
}

/// Scope summary (same information as the desktop list): identity + type + read-only.
fn scope_summary(scope: &ConnectTokenScope) -> String {
    let identity_part = if scope.identities.is_empty() {
        "all identities".to_string()
    } else {
        format!("{} identit{}", scope.identities.len(), {
            if scope.identities.len() == 1 {
                "y"
            } else {
                "ies"
            }
        })
    };
    let type_part = if scope.item_types.is_empty() {
        "all types".to_string()
    } else {
        scope
            .item_types
            .iter()
            .map(type_name)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{identity_part} · {type_part} · read-only")
}

async fn create_token(
    config: &CliConfig,
    ui: &dyn PromptUi,
    label: &str,
    identity_names: &[String],
    item_types: &[String],
    expires_in: Option<&str>,
) -> Result<()> {
    let label = label.trim();
    if label.is_empty() {
        bail!("--label must not be blank");
    }
    if label.len() > 128 {
        bail!("--label must be at most 128 bytes");
    }

    // Type/duration parsing happens before unlocking: wrong parameters should not prompt for a password
    let types = item_types
        .iter()
        .map(|raw| parse_item_type(raw))
        .collect::<Result<Vec<_>>>()?;
    let ttl = expires_in.map(parse_expires_in).transpose()?;

    let service = open_unlocked(config, ui, None).await?;

    let mut identity_ids = Vec::new();
    for name in identity_names {
        let identity = service
            .get_identity_by_name(name)
            .await
            .map_err(|e| anyhow!("Failed to load identity: {}", e))?
            .with_context(|| format!("Identity '{name}' not found"))?;
        identity_ids.push(identity.id);
    }

    let scope = ConnectTokenScope {
        identities: identity_ids,
        item_types: types,
        verbs: vec![ConnectVerb::Read],
    };
    let (token, row) = service
        .create_connect_token(
            label.to_string(),
            scope,
            None,
            ttl.map(|d| chrono::Utc::now() + d),
        )
        .await
        .into_anyhow()
        .context("failed to create connect token")?;

    println!("{}", "🔑 Connect token created".cyan().bold());
    println!("{}", token.green().bold());
    println!(
        "{}",
        "⚠️  Copy it now — the plaintext is shown only once and cannot be recovered.".yellow()
    );
    println!("   label:      {label}");
    println!("   id:         {}", row.id);
    println!("   fingerprint: {}", row.fingerprint);
    println!("   scope:      {}", scope_summary(&row.scope));
    match row.expires_at {
        Some(at) => println!("   expires at: {}", at.to_rfc3339()),
        None => {
            println!("   expires at: never (pass --expires-in <n><s|m|h|d> to bound the lifetime)")
        }
    }
    println!(
        "   {}",
        "Point your tool at http://127.0.0.1:<port>/api/v1/connect/ with".bright_black()
    );
    println!(
        "   {}",
        "`Authorization: Bearer <token>`; start the listener with `persona connect serve`."
            .bright_black()
    );
    Ok(())
}

async fn list_tokens(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    let service = open_unlocked(config, ui, None).await?;
    let tokens = service
        .list_connect_tokens()
        .await
        .into_anyhow()
        .context("failed to list connect tokens")?;

    println!("{}", "🔑 Connect tokens".cyan().bold());
    if tokens.is_empty() {
        println!("(none) — create one with `persona connect token create`");
        return Ok(());
    }
    for row in tokens {
        let expired = row.expired();
        let state = if row.revoked_at.is_some() {
            "revoked".red()
        } else if expired {
            "expired".yellow()
        } else {
            "active".green()
        };
        println!(
            "{}  {:<24} {}  {}",
            state,
            row.label,
            row.fingerprint.bright_black(),
            scope_summary(&row.scope)
        );
        println!("    id: {}  {}", row.id, {
            match (&row.last_used_at, &row.revoked_at) {
                (_, Some(at)) => format!("revoked at {}", at.to_rfc3339()),
                (Some(at), None) => format!("last used {}", at.to_rfc3339()),
                (None, None) => "never used".to_string(),
            }
        });
        if let Some(at) = row.expires_at {
            if row.revoked_at.is_none() {
                println!("    expires at: {}", at.to_rfc3339());
            }
        }
    }
    Ok(())
}

async fn revoke_token(config: &CliConfig, ui: &dyn PromptUi, target: &str) -> Result<()> {
    let service = open_unlocked(config, ui, None).await?;

    // UUID matches by id; otherwise exact-match by fingerprint (the list shows fingerprints, so copy-paste just works)
    let id = match uuid::Uuid::parse_str(target) {
        Ok(id) => id,
        Err(_) => {
            let hit = service
                .list_connect_tokens()
                .await
                .into_anyhow()
                .context("failed to list connect tokens")?
                .into_iter()
                .find(|row| row.fingerprint == target)
                .with_context(|| format!("no token with id or fingerprint {target:?}"))?;
            hit.id
        }
    };
    let already_revoked = !service
        .revoke_connect_token(&id)
        .await
        .into_anyhow()
        .context("failed to revoke connect token")?;
    // Idempotent: core returns false for an already-revoked token (and does not re-audit) — report it as-is
    if already_revoked {
        println!(
            "{}",
            format!("Token {id} was already revoked (no-op)").yellow()
        );
    } else {
        println!("{}", format!("✓ Token {id} revoked").green());
    }
    Ok(())
}

// -----------------------------------------------------------------------
// serve (DR-1 A2: foreground process + Ctrl-C, no daemonization)
// -----------------------------------------------------------------------

async fn serve(
    config: &CliConfig,
    ui: &dyn PromptUi,
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
    passphrase_env: Option<&str>,
) -> Result<()> {
    // Register SIGTERM at construction time (before starting the listener): any later
    // systemd stop / kill goes through the same graceful-shutdown path, eliminating the
    // window of "default signal kills the process → stale unix socket".
    let shutdown = shutdown_signal()?;
    serve_until(config, ui, port, unix_socket, passphrase_env, shutdown).await
}

/// The production shutdown-signal future. Returns `Ok(())` as soon as either SIGTERM or Ctrl-C fires.
///
/// - **SIGTERM**: `shutdown_signal()` installs the OS handler synchronously at
///   construction time (tokio `signal()`'s `signal_enable` is a construction-time
///   call) — serve() calls this function before starting the listener, so SIGTERM
///   is taken over at any phase of the process; if the signal arrives during
///   unlock, tokio's watch channel buffers the delivery and it is handled as soon
///   as `shutdown.await` resolves (graceful, nothing lost, no leftovers).
/// - **Ctrl-C(SIGINT)**: deliberately kept lazy (registered only at the select's
///   first poll). The console password prompt only clears ECHO, leaving ISIG on —
///   if SIGINT were taken over during the prompt, the user's Ctrl-C would be
///   swallowed by tokio and the prompt could not be canceled. The cost: Ctrl-C
///   during the unlock window still exits by the default behavior and may leave a
///   stale socket, which self-heals on the next start via stale-socket takeover (verified on a real machine).
fn shutdown_signal() -> Result<impl std::future::Future<Output = Result<()>>> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                r = tokio::signal::ctrl_c() => r.context("failed to listen for Ctrl-C"),
                _ = term.recv() => Ok(()),
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            tokio::signal::ctrl_c()
                .await
                .context("failed to listen for Ctrl-C")
        })
    }
}

/// The `serve` body, with "wait for the exit signal" parameterized — this is the
/// test seam: production feeds Ctrl-C, tests feed a controllable future, so the
/// full path of unlock → start → print endpoints → stop → cleanup is unit-testable
/// (otherwise serve could only be smoke-tested manually in a real terminal).
async fn serve_until<F>(
    config: &CliConfig,
    ui: &dyn PromptUi,
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
    passphrase_env: Option<&str>,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    let transport = resolve_transport(port, unix_socket)?;
    // Start the listener first, unlock second: health becomes probeable immediately
    // (argon2's seconds-scale unlock delay no longer sits in front of the fleet probe);
    // before unlock completes the data plane honestly reports 503 vault_locked — the
    // same semantics as "vault locked", and the EXTERNAL_INTEGRATION retry discipline
    // (503 backoff-and-retry) already covers that window, so consumers need not know
    // about the "password being typed" intermediate state.
    let slot = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let handle =
        persona_connect_server::start_connect_server_with_transport(slot.clone(), transport)
            .await?;
    match &handle.socket_path {
        Some(path) => {
            println!(
                "{}",
                format!(
                    "🔌 Connect listener on unix://{} (0600 + uid-checked) — Ctrl-C to stop",
                    path.display()
                )
                .cyan()
                .bold()
            );
            println!(
                "{}",
                format!(
                    "   probe: curl --unix-socket {} http://localhost/api/v1/connect/health",
                    path.display()
                )
                .bright_black()
            );
        }
        None => {
            println!(
                "{}",
                format!(
                    "🔌 Connect listener on http://127.0.0.1:{} — Ctrl-C to stop",
                    handle.port
                )
                .cyan()
                .bold()
            );
        }
    }
    // Unlock (listener already up). On failure: graceful shutdown first (wait for the
    // port/socket to actually release), then re-raise as-is — never leave the
    // half-initialized state of "error exit while the listener is still hanging around".
    let service = match open_unlocked(config, ui, passphrase_env).await {
        Ok(service) => service,
        Err(err) => {
            handle.stop_and_wait().await;
            return Err(err);
        }
    };
    *slot.lock().await = Some(service);

    shutdown.await?;
    // stop_and_wait: wait for the listener task to finish (the serve loop exits and the
    // socket file is deleted). A fire-and-forget stop may lose the cleanup task in the
    // subsequent process-exit race.
    handle.stop_and_wait().await;
    println!("{}", "Connect listener stopped".bright_black());
    Ok(())
}

/// The `serve` flags → transport layer (pure function; unit-test entrypoint).
///
/// - No `--unix-socket` → loopback TCP (`--port`, 0 = OS-assigned);
/// - Bare `--unix-socket` → unix socket, path from [`default_socket_path`];
/// - `--unix-socket <path>` → unix socket, the given path;
/// - `--port` (non-0) together with `--unix-socket` → error (unix has no TCP port;
///   silently ignoring either side would send the caller debugging against the wrong endpoint).
fn resolve_transport(
    port: u16,
    unix_socket: Option<Option<std::path::PathBuf>>,
) -> Result<persona_connect_server::ConnectTransport> {
    match unix_socket {
        None => Ok(persona_connect_server::ConnectTransport::Tcp { port }),
        Some(explicit) => {
            if port != 0 {
                anyhow::bail!(
                    "--port cannot be combined with --unix-socket (a unix socket has no TCP port)"
                );
            }
            // Windows: reject before unlocking (fail-fast — demanding the master password
            // first and only then reporting "platform not supported" hides the capability
            // boundary behind interaction). The vault-side start_connect_server_with_transport
            // keeps the same-semantics backstop (any caller may pass Unix; the library must defend itself).
            #[cfg(not(unix))]
            {
                let _ = explicit;
                anyhow::bail!(
                    "unix socket transport is not supported on this platform; \
                     use TCP loopback instead (drop --unix-socket)"
                );
            }
            #[cfg(unix)]
            {
                let path = explicit.unwrap_or_else(default_socket_path);
                Ok(persona_connect_server::ConnectTransport::Unix { path })
            }
        }
    }
}

/// The default path when `--unix-socket` is used bare.
///
/// Prefers `$XDG_RUNTIME_DIR/persona/connect.sock` (the XDG runtime directory is
/// cleaned up on session logout and is 0700 owner-private); when XDG_RUNTIME_DIR is
/// absent (SSH/non-XDG environments, macOS, the Windows fallback branch) it falls
/// back to `~/.persona/connect.sock` (same directory as connect.port, the local
/// location agreed with consumers).
///
/// On Windows there is no production caller (resolve_transport's unix branch is
/// cfg(unix)), but unit tests still verify the fallback shape here (the openclaw
/// real-machine run caught a slash-assertion bug) — a conditional allow instead of
/// cfg-ing it out, preserving the cross-platform shape coverage.
#[cfg_attr(not(unix), allow(dead_code))]
fn default_socket_path() -> std::path::PathBuf {
    socket_path_from(dirs::runtime_dir(), dirs::home_dir())
}

/// The pure-function kernel of [`default_socket_path`] (unit-test entrypoint):
/// with a runtime directory → `$runtime/persona/connect.sock`; otherwise
/// `$home/.persona/connect.sock`; with home unavailable as well →
/// `./.persona/connect.sock` (a relative path following cwd, the last fallback).
fn socket_path_from(
    runtime_dir: Option<std::path::PathBuf>,
    home_dir: Option<std::path::PathBuf>,
) -> std::path::PathBuf {
    if let Some(runtime) = runtime_dir {
        return runtime.join("persona").join("connect.sock");
    }
    home_dir
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".persona")
        .join("connect.sock")
}

// -----------------------------------------------------------------------
// Tests: ScriptedUi seam + env serialization (same fixture style as travel.rs)
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{IdentityType, Workspace};
    use persona_core::storage::WorkspaceRepository;
    use persona_core::Repository;

    /// The process env is a single slot: serialized through the global lock shared
    /// with the env tests of bridge/switch/ssh/backup/travel (poison recovery prevents cascades).
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct EnvVar(&'static str);

    impl EnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// Build a vault with a master user (one identity plus one password credential).
    async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        WorkspaceRepository::new(db.clone())
            .create(&Workspace::new(
                dir.path().to_path_buf(),
                "test".to_string(),
            ))
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity("work".to_string(), IdentityType::Work)
            .await
            .unwrap();
        service
            .create_credential(
                identity.id,
                "login".to_string(),
                persona_core::models::CredentialType::Password,
                persona_core::models::SecurityLevel::High,
                &persona_core::models::CredentialData::Password(
                    persona_core::models::PasswordCredentialData {
                        password: "secret".to_string(),
                        email: None,
                        security_questions: vec![],
                    },
                ),
            )
            .await
            .unwrap();
        (dir, config)
    }

    fn create_args(label: &str, identities: &[&str], types: &[&str]) -> ConnectArgs {
        create_args_with_ttl(label, identities, types, None)
    }

    fn create_args_with_ttl(
        label: &str,
        identities: &[&str],
        types: &[&str],
        expires_in: Option<&str>,
    ) -> ConnectArgs {
        ConnectArgs {
            command: ConnectCommand::Token {
                command: TokenCommand::Create {
                    label: label.to_string(),
                    identities: identities.iter().map(|s| s.to_string()).collect(),
                    item_types: types.iter().map(|s| s.to_string()).collect(),
                    expires_in: expires_in.map(|s| s.to_string()),
                },
            },
        }
    }

    async fn token_rows(config: &CliConfig) -> Vec<persona_core::connect::ConnectTokenRow> {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        persona_core::storage::ConnectTokenRepository::new(db)
            .list_all()
            .await
            .unwrap()
    }

    async fn audit_count(config: &CliConfig, action: &str) -> i64 {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(1) FROM audit_logs WHERE action = '{action}'"
        )))
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_shows_plaintext_once_and_persists_hashed_row() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let ui = ScriptedUi::new();
        execute_with(create_args("ci", &[], &[]), &config, &ui)
            .await
            .unwrap();

        // The vault holds only the hashed rows; the plaintext pconn_ is never stored
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hash.len(), 64);
        assert!(!rows[0].hash.contains("pconn_"));
        assert_eq!(rows[0].fingerprint.len(), 16);
        assert!(rows[0].scope.identities.is_empty(), "缺省 = 全部身份");
        assert!(rows[0].scope.item_types.is_empty(), "缺省 = 全部类型");
        assert_eq!(audit_count(&config, "connect_token_created").await, 1);
        assert!(rows[0].expires_at.is_none(), "缺省 = 永不过期");
    }

    /// `--expires-in` parsing: <positive integer><s|m|h|d>; zero/negative/empty digits/
    /// unknown units/overflow are all rejected.
    #[test]
    fn expires_in_parses_units_and_rejects_bad_input() {
        assert_eq!(parse_expires_in("45s").unwrap().num_seconds(), 45);
        assert_eq!(parse_expires_in("30m").unwrap().num_seconds(), 1800);
        assert_eq!(parse_expires_in("12h").unwrap().num_seconds(), 43200);
        assert_eq!(parse_expires_in("30d").unwrap().num_seconds(), 2_592_000);

        for bad in ["", "d", "0d", "-5h", "1x", "1h30m", "99999999999999999999d"] {
            assert!(parse_expires_in(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// Created with `--expires-in`: the row's expires_at lands about 1h in the future (± tolerance);
    /// the plaintext-row-not-stored semantics are unchanged.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_expires_in_persists_future_expiry() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(
            create_args_with_ttl("ttl-ci", &[], &[], Some("1h")),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();

        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        let expires_at = rows[0].expires_at.expect("expiry must be persisted");
        let delta = expires_at - chrono::Utc::now();
        assert!(
            delta.num_seconds() > 3500 && delta.num_seconds() <= 3600,
            "expiry should be ~1h ahead, got {delta:?}"
        );
    }

    /// A bad duration is rejected before unlocking (no PERSONA_MASTER_PASSWORD is set:
    /// if execution actually reached unlock it would stall on ScriptedUi or fail with a
    /// different error; an error containing invalid duration proves the parameter gate
    /// precedes the password prompt).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_bad_duration_fails_before_prompt() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        let err = execute_with(
            create_args_with_ttl("bad", &[], &[], Some("1x")),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "{err}");
        assert!(
            token_rows(&config).await.is_empty(),
            "no row must be written"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn create_with_scopes_narrows_and_rejects_bad_input() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(
            create_args("scoped", &["work"], &["password", "totp"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].scope.item_types.len(), 2);
        assert_eq!(rows[0].scope.identities.len(), 1);

        // Unknown identity: bail without leaving a half-built token
        let err = execute_with(
            create_args("x", &["ghost"], &[]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert_eq!(token_rows(&config).await.len(), 1);

        // Illegal type vocabulary
        let err = execute_with(
            create_args("y", &[], &["passkey"]),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unknown item type"), "{err}");
        assert_eq!(token_rows(&config).await.len(), 1);
    }

    /// `connect token list`: the empty-list branch plus the full print paths of the
    /// active/revoked and never-used/revoked-at status lines.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn list_tokens_renders_empty_and_populated_states() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let list_args = || ConnectArgs {
            command: ConnectCommand::Token {
                command: TokenCommand::List,
            },
        };

        // Empty vault: takes the "(none)" early-exit branch
        execute_with(list_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // Two tokens, one revoked: covers both the active and revoked status lines
        execute_with(create_args("alpha", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(create_args("beta", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        let rows = token_rows(&config).await;
        assert_eq!(rows.len(), 2);
        execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke {
                        target: rows[0].fingerprint.clone(),
                    },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();

        execute_with(list_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn list_and_revoke_by_id_or_fingerprint() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        execute_with(create_args("a", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(create_args("b", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // Revoke by fingerprint (the list shows fingerprints)
        let fp = token_rows(&config).await[0].fingerprint.clone();
        execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke { target: fp },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap();
        let rows = token_rows(&config).await;
        assert!(rows[0].revoked_at.is_some());
        assert!(rows[1].revoked_at.is_none());

        // Revoke by UUID + idempotency
        let id = rows[1].id;
        for _ in 0..2 {
            execute_with(
                ConnectArgs {
                    command: ConnectCommand::Token {
                        command: TokenCommand::Revoke {
                            target: id.to_string(),
                        },
                    },
                },
                &config,
                &ScriptedUi::new(),
            )
            .await
            .unwrap();
        }
        assert!(token_rows(&config).await[1].revoked_at.is_some());
        // An idempotent repeat (false) does not re-audit: 1 fingerprint entry + 1 first UUID entry
        assert_eq!(audit_count(&config, "connect_token_revoked").await, 2);

        // Unknown target
        let err = execute_with(
            ConnectArgs {
                command: ConnectCommand::Token {
                    command: TokenCommand::Revoke {
                        target: "nope".to_string(),
                    },
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("no token with id or fingerprint"),
            "{err}"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn token_commands_require_unlocked_vault() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        // Wrong master password → auth failure (the SERVICE-side gating semantics are already covered in core/desktop)
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong");
        let err = execute_with(create_args("x", &[], &[]), &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(err.to_string().contains("Authentication failed"), "{err}");
        assert!(token_rows(&config).await.is_empty());
    }

    /// Smoke of the serve orchestration (TCP transport): serve_until's signal-injection
    /// seam puts the full path of resolve → unlock → start → print → stop into unit
    /// tests (health/router behavior is fully covered by the connect-server crate).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_pipeline_tcp_starts_prints_and_stops_on_signal() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        // Signal ready immediately: the full serve-orchestration path (resolve → unlock →
        // start → print the TCP endpoint arm → receive the signal → stop → final print)
        // must complete and return normally. The health smoke is not repeated here —
        // the connect-server lib's http_over_tcp tests already cover it fully (including
        // the three defense lines); what is pinned here is serve's own orchestration.
        serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            None,
            None,
            std::future::ready(Ok(())),
        )
        .await
        .unwrap();
    }

    /// Smoke of the serve orchestration (unix transport, driven by serve_until): the
    /// health response is a precondition of the exit signal — serve must really start
    /// the listener, print the unix endpoint arm, then stop and remove the socket file
    /// after the signal, with the full path executed in a unit test.
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_pipeline_over_unix_socket_serves_health_then_cleans_up() {
        let _guard = env_guard();
        let _pw = EnvVar::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let (_dir, config) = seeded_workspace().await;

        let socket = _dir.path().join("connect.sock");
        // Exit signal = the first successful health response (exit is only allowed once the listener is really up).
        let probe = async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Deliberately structured as "sleep first, probe after, flag-gated exit": the
            // sleep runs unconditionally; a success falls through rather than returning or
            // breaking out, so the block-closing braces execute on every successful
            // iteration (an early return would leave them a coverage hole that never fills).
            let mut answered = false;
            for _ in 0..300 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                if let Ok(mut stream) = tokio::net::UnixStream::connect(&socket).await {
                    let _ = stream
                        .write_all(
                            b"GET /api/v1/connect/health HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                    let mut buf = Vec::new();
                    let _ = stream.read_to_end(&mut buf).await;
                    let body = String::from_utf8_lossy(&buf);
                    if body.contains("\"ok\":true") && body.contains("persona-connect") {
                        answered = true;
                    }
                }
                if answered {
                    break;
                }
            }
            if !answered {
                anyhow::bail!("unix listener 未在 3s 内应答 health");
            }
            Ok(())
        };
        serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            Some(Some(socket.clone())),
            None,
            probe,
        )
        .await
        .unwrap();

        // Teardown: the socket file is removed by stop (polled, not a sleep-guessed duration)
        let mut gone = false;
        for _ in 0..100 {
            if !socket.exists() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone, "stop 后 socket 文件应移除: {}", socket.display());
    }

    /// SIGTERM goes through graceful shutdown (the entrypoint of systemd stop / kill):
    /// `shutdown_signal()` installs the OS handler synchronously at construction time
    /// (tokio `signal()` semantics), and any subsequent spontaneous SIGTERM is taken
    /// over by tokio and returns Ok — instead of the default behavior killing the
    /// process outright (which would leave a stale socket on unix). Ctrl-C is kept
    /// deliberately lazy in registration (the password prompt's ISIG is still on;
    /// taking it over early would swallow the user's cancel key — see the
    /// shutdown_signal docs).
    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_signal_returns_ok_on_sigterm() {
        let fut = shutdown_signal().expect("signal() 构造期应完成注册");
        // Registration finished at construction, so SIGTERM at this moment is taken over by tokio (it will not kill this test process)
        unsafe {
            libc::kill(std::process::id() as i32, libc::SIGTERM);
        }
        let result = fut.await;
        assert!(result.is_ok(), "SIGTERM 应触发关停信号: {result:?}");
    }

    /// Unlock failure leaves no half-initialized state: a wrong password → graceful
    ///
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_until_stops_listener_when_unlock_fails() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;
        std::env::set_var("PERSONA_MASTER_PASSWORD", "definitely-wrong");
        let socket = _dir.path().join("unlock-fail.sock");
        let result = serve_until(
            &config,
            &ScriptedUi::new(),
            0,
            Some(Some(socket.clone())),
            None,
            std::future::ready(Ok(())),
        )
        .await;
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let err = result.expect_err("错误密码必须失败");
        assert!(
            err.to_string().contains("Authentication failed"),
            "应是认证失败而非其它: {err}"
        );
        assert!(!socket.exists(), "解锁失败后 socket 文件必须已移除");
        assert!(
            tokio::net::UnixStream::connect(&socket).await.is_err(),
            "解锁失败后连接必须被拒"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn serve_passphrase_env_var_missing_is_a_hard_error() {
        let _guard = env_guard();
        let (_dir, config) = seeded_workspace().await;

        let err = execute_with(
            ConnectArgs {
                command: ConnectCommand::Serve {
                    port: 0,
                    unix_socket: None,
                    passphrase_env: Some("PERSONA_TEST_MISSING_VAR".to_string()),
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("is not set (or blank)"), "{err}");
    }

    // -------------------------------------------------------------------
    // resolve_transport / default_socket_path
    // -------------------------------------------------------------------

    #[test]
    fn resolve_transport_defaults_to_loopback_tcp() {
        // matches! + guard: the assertion is the decision, with no unreachable coverage corners from match+panic.
        let t = resolve_transport(0, None).unwrap();
        assert!(
            matches!(t, persona_connect_server::ConnectTransport::Tcp { port: 0 }),
            "未给 --unix-socket 应得 TCP(0): {t:?}"
        );
        let t = resolve_transport(8737, None).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Tcp { port: 8737 }
            ),
            "--port 应得对应端口 TCP: {t:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_transport_unix_bare_uses_default_path_and_explicit_path_wins() {
        // Bare use → the default path (consistent with default_socket_path)
        let t = resolve_transport(0, Some(None)).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Unix { ref path }
                    if *path == default_socket_path()
            ),
            "裸用应取缺省路径: {t:?}"
        );
        // The explicit path takes priority
        let explicit = std::path::PathBuf::from("/tmp/persona-test.sock");
        let t = resolve_transport(0, Some(Some(explicit.clone()))).unwrap();
        assert!(
            matches!(
                t,
                persona_connect_server::ConnectTransport::Unix { ref path }
                    if *path == explicit
            ),
            "显式路径应覆盖缺省: {t:?}"
        );
    }

    #[test]
    fn resolve_transport_rejects_port_plus_unix_socket() {
        // Giving both sides is a caller flag conflict: unix has no TCP port, and silently
        // ignoring either side would send the caller debugging against the wrong
        // endpoint — hard error.
        let err = resolve_transport(8737, Some(None)).unwrap_err();
        assert!(err.to_string().contains("--unix-socket"), "{err}");
    }

    /// Windows: the unix transport is rejected **before unlocking** (fail-fast, no
    /// master-password prompt first). The vault-side start_connect_server_with_transport
    /// carries its own same-semantics backstop (see its tests).
    #[cfg(not(unix))]
    #[test]
    fn resolve_transport_rejects_unix_before_unlock_on_windows() {
        let err = resolve_transport(0, Some(None)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not supported"), "应说明平台不支持: {msg}");
        assert!(msg.contains("TCP"), "应给出 TCP 替代指引: {msg}");
    }

    #[test]
    fn default_socket_path_is_stable_and_falls_back_under_persona_dir() {
        let path = default_socket_path();
        // display precomputed: the message-argument lines of a multi-line assert only run
        // on failure, so a passing test cannot fill that coverage hole — compute first,
        // then assert in one line.
        let shown = path.display().to_string();
        // Fixed shape: */persona/connect.sock or */.persona/connect.sock — consumers
        // locate it per the docs, and the shape must not jitter between versions. Use
        // Path::ends_with to compare by **component**: a string suffix containing slashes
        // necessarily false-fails on Windows (backslashes; caught on a real openclaw machine).
        let stable_shape =
            path.ends_with("persona/connect.sock") || path.ends_with(".persona/connect.sock");
        assert!(stable_shape, "缺省路径形态不符: {shown}");
        if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
            // XDG_RUNTIME_DIR is a unix environment variable (this branch never triggers on
            // Windows); the component-level prefix check follows the reasoning above, avoiding
            // separator binding.
            let anchored = path.starts_with(std::path::Path::new("/"));
            assert!(anchored, "有 XDG_RUNTIME_DIR 时应在运行时目录: {shown}");
        }
    }

    /// The three branches of the default-path kernel: runtime → home → cwd fallback
    /// (default_socket_path only wires dirs; the branch logic is pinned here).
    #[test]
    fn socket_path_from_prefers_runtime_then_home_then_cwd() {
        assert_eq!(
            socket_path_from(Some("/run/user/1000".into()), Some("/home/u".into())),
            std::path::PathBuf::from("/run/user/1000/persona/connect.sock")
        );
        assert_eq!(
            socket_path_from(None, Some("/home/u".into())),
            std::path::PathBuf::from("/home/u/.persona/connect.sock")
        );
        assert_eq!(
            socket_path_from(None, None),
            std::path::PathBuf::from("./.persona/connect.sock")
        );
    }
}
