use crate::utils::core_ext::CoreResultExt;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    models::{CredentialData, CredentialType, Identity as CoreIdentity, SecurityLevel, SshKeyData},
    Database, PersonaService,
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct SshArgs {
    #[command(subcommand)]
    command: SshSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum SshSubcommand {
    /// Generate a new SSH key and store it in the vault
    Generate {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Key label (credential name)
        #[arg(short, long)]
        name: Option<String>,
        /// Key type (ed25519|rsa). Only ed25519 implemented.
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
    },
    /// List SSH keys for an identity
    List {
        /// Identity name
        #[arg(short, long)]
        identity: String,
    },
    /// Remove an SSH key by credential id
    Remove {
        /// Credential UUID to remove
        #[arg(long)]
        id: Uuid,
        /// Require confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Show agent running status
    Status,
    /// Start persona-ssh-agent and optionally print shell export commands
    AddToAgent {
        /// Optional: identity name to filter (reserved for future use)
        #[arg(short, long)]
        identity: Option<String>,
        /// Print shell export command
        #[arg(long)]
        print_export: bool,
    },
    /// Show agent running status
    AgentStatus,
    /// Run a command while setting target host for agent policy
    Run {
        /// Target host (used for known_hosts policy)
        #[arg(long)]
        host: String,
        /// Command to execute (use -- to separate)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Start persona-ssh-agent (alias of add-to-agent)
    StartAgent {
        /// Print shell export command
        #[arg(long)]
        print_export: bool,
    },
    /// List SSH keys across all identities
    ListAll,
    /// Import SSH key from seed (base64/hex)
    Import {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Key label
        #[arg(short, long)]
        name: Option<String>,
        /// ed25519 private seed in base64
        #[arg(long, conflicts_with = "seed_hex")]
        seed_base64: Option<String>,
        /// ed25519 private seed in hex
        #[arg(long, conflicts_with = "seed_base64")]
        seed_hex: Option<String>,
    },
    /// Print OpenSSH public key for a credential
    ExportPub {
        /// Credential UUID
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Stop persona-ssh-agent
    StopAgent,
}

pub async fn execute(args: SshArgs, config: &crate::config::CliConfig) -> Result<()> {
    execute_with(args, config, &crate::utils::prompt::TerminalUi).await
}

pub(crate) async fn execute_with(
    args: SshArgs,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    match args.command {
        SshSubcommand::Generate {
            identity,
            name,
            key_type,
            favorite,
        } => generate_key(&identity, name, &key_type, favorite, config, ui).await,
        SshSubcommand::List { identity } => list_keys(&identity, config, ui).await,
        SshSubcommand::Remove { id, yes } => remove_key(id, yes, config, ui).await,
        SshSubcommand::Status => agent_status(config).await,
        SshSubcommand::AddToAgent {
            identity: _,
            print_export,
        } => start_agent(config, print_export, ui).await,
        SshSubcommand::AgentStatus => agent_status(config).await,
        SshSubcommand::StartAgent { print_export } => start_agent(config, print_export, ui).await,
        SshSubcommand::ListAll => list_all_keys(config, ui).await,
        SshSubcommand::Import {
            identity,
            name,
            seed_base64,
            seed_hex,
        } => import_seed(&identity, name, seed_base64, seed_hex, config, ui).await,
        SshSubcommand::ExportPub { id } => export_pubkey(id, config, ui).await,
        SshSubcommand::StopAgent => stop_agent(),
        SshSubcommand::Run { host, command } => run_with_host(&host, command, config).await,
    }
}

pub(crate) async fn ensure_service(
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db: persona_core::Database = Database::from_file::<std::path::PathBuf>(db_path.to_owned())
        .await
        .into_anyhow()
        .context("Failed to open database")?;
    db.migrate().await.context("Failed to run migrations")?;
    let mut service = crate::commands::service::new_service(db)
        .await
        .context("Failed to create PersonaService")?;
    if service.has_users().await? {
        let password = if config.ui.interactive {
            crate::commands::service::prompt_master_password(ui)?
        } else {
            std::env::var("PERSONA_MASTER_PASSWORD")
                .context("Master password required but PERSONA_MASTER_PASSWORD not set")?
        };
        match service.authenticate_user(&password).await? {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }
    Ok(service)
}

async fn resolve_identity(service: &PersonaService, name: &str) -> Result<CoreIdentity> {
    service
        .get_identity_by_name(name)
        .await?
        .with_context(|| format!("Identity '{}' not found", name))
}

async fn generate_key(
    identity_name: &str,
    label: Option<String>,
    key_type: &str,
    favorite: bool,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "🔑 Generating SSH key...".cyan().bold());
    if key_type.to_lowercase() != "ed25519" {
        anyhow::bail!("Only ed25519 is supported currently");
    }

    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // Generate ed25519 keypair
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    let mut rng = rand::rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let secret_bytes = signing_key.to_bytes(); // 32-byte seed
    let pub_bytes = verifying_key.to_bytes(); // 32-byte public

    // Encode to OpenSSH public line: base64 of [len:"ssh-ed25519"][b"ssh-ed25519"][len:pub][pub]
    let openssh_pub = encode_ssh_ed25519_public(&pub_bytes, None);
    let private_b64 = BASE64.encode(secret_bytes);

    let name = label.unwrap_or_else(|| format!("SSH Key ({})", identity.name));
    let data = SshKeyData {
        private_key: private_b64,
        public_key: openssh_pub.clone(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };
    let mut cred = service
        .create_credential(
            identity.id,
            name.clone(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(data.clone()),
        )
        .await?;

    println!("{} Created SSH key credential:", "✓".green().bold());
    println!("  Name: {}", name.cyan());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Public: {}", openssh_pub);
    println!("  ID: {}", cred.id);
    if favorite {
        cred.is_favorite = true;
        service.update_credential(&cred).await?;
        println!("  Favorite: {}", "yes".green());
    }
    Ok(())
}

async fn list_keys(
    identity_name: &str,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;
    let creds = service.get_credentials_for_identity(&identity.id).await?;
    let mut count = 0usize;
    for cred in creds {
        if matches!(cred.credential_type, CredentialType::SshKey) {
            count += 1;
            println!("{} {}", "#".dimmed(), count);
            println!("  ID: {}", cred.id);
            println!("  Name: {}", cred.name.cyan());
            println!("  Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S"));
            println!(
                "  Favorite: {}",
                if cred.is_favorite {
                    "yes".green()
                } else {
                    "no".dimmed()
                }
            );
        }
    }
    if count == 0 {
        println!("{}", "No SSH keys for this identity.".yellow());
    }
    Ok(())
}

async fn list_all_keys(
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identities = service.get_identities().await?;
    let mut count = 0usize;

    for identity in identities {
        let creds = service.get_credentials_for_identity(&identity.id).await?;
        for cred in creds {
            if matches!(cred.credential_type, CredentialType::SshKey) {
                count += 1;
                println!("{} {}", "#".dimmed(), count);
                println!("  ID: {}", cred.id);
                println!("  Name: {}", cred.name.cyan());
                println!("  Identity: {}", identity.name.cyan());
                println!("  Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S"));
                println!(
                    "  Favorite: {}",
                    if cred.is_favorite {
                        "yes".green()
                    } else {
                        "no".dimmed()
                    }
                );
            }
        }
    }

    if count == 0 {
        println!("{}", "No SSH keys found.".yellow());
    }

    Ok(())
}

async fn remove_key(
    id: Uuid,
    yes: bool,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    if !yes && !ui.confirm(&format!("Remove SSH key credential {}?", id), false)? {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }
    let _ = service.delete_credential(&id).await?;
    println!("{} Removed credential {}", "✓".green(), id);
    Ok(())
}

fn encode_ssh_ed25519_public(pubkey: &[u8; 32], comment: Option<&str>) -> String {
    // helper to build SSH public key format
    use byteorder::{BigEndian, WriteBytesExt};
    let mut buf: Vec<u8> = Vec::new();
    let algo = b"ssh-ed25519";
    buf.write_u32::<BigEndian>(algo.len() as u32).unwrap();
    buf.extend_from_slice(algo);
    buf.write_u32::<BigEndian>(pubkey.len() as u32).unwrap();
    buf.extend_from_slice(pubkey);
    let b64 = BASE64.encode(&buf);
    match comment {
        Some(c) if !c.is_empty() => format!("ssh-ed25519 {} {}", b64, c),
        _ => format!("ssh-ed25519 {}", b64),
    }
}

async fn start_agent(
    config: &crate::config::CliConfig,
    print_export: bool,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    println!("{}", "Starting persona-ssh-agent...".cyan().bold());
    let db_path = config.get_database_path();
    let agent_bin = resolve_agent_binary()?;
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).context("Failed to create agent state directory")?;
    let socket_path = state_dir.join("agent.socket");
    let mut cmd = Command::new(&agent_bin);
    cmd.env("PERSONA_DB_PATH", db_path.to_string_lossy().to_string());
    cmd.env("PERSONA_AGENT_SOCKET_PATH", &socket_path);
    // if vault encrypted, prompt for master password and pass via env
    let _ = ensure_service(config, ui).await?; // ensure migrations; may prompt
                                               // If ensure_service prompted, service is unlocked; but agent needs password via env for future reloads
                                               // Here we conservatively ask user again (not stored from ensure_service)
    let pass = if config.ui.interactive {
        ui.password(
            "Enter master password for agent (leave empty if not set)",
            true,
            None,
        )?
    } else {
        std::env::var("PERSONA_MASTER_PASSWORD").unwrap_or_default()
    };
    if !pass.is_empty() {
        cmd.env("PERSONA_MASTER_PASSWORD", pass);
    }
    // forward stdout to capture SSH_AUTH_SOCK
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("Failed to start persona-ssh-agent")?;
    let stdout = child.stdout.take().context("No stdout from agent")?;
    let mut reader = BufReader::new(stdout).lines();
    let mut sock_line = None;
    for _ in 0..8 {
        let Some(line) = reader.next_line().await? else {
            break;
        };
        if line.starts_with("SSH_AUTH_SOCK=") {
            sock_line = Some(line);
            break;
        }
        println!("{}", line);
    }
    if let Some(sock) = sock_line {
        let sock_value = sock
            .split_once('=')
            .map(|(_, value)| value.trim())
            .unwrap_or("");
        println!("{} {}", "Agent socket:".yellow(), sock_value.cyan());
        if print_export {
            println!();
            println!("{}", "Run the following in your shell:".dimmed());
            print_sock_export(sock_value);
        }
        // The daemon prints the socket line before loading keys, so it can
        // still die right after (e.g. a stale binary rejected by a newer db
        // migration). Poll briefly: a dead daemon must surface as an error,
        // not as the success message printed above.
        ensure_agent_alive(&mut child).await?;
    } else {
        // The child closed stdout without a socket line.
        ensure_agent_alive(&mut child).await?;
        println!(
            "{}",
            "Could not detect SSH_AUTH_SOCK from agent output.".yellow()
        );
    }

    Ok(())
}

/// Poll the freshly spawned agent briefly: a daemon that already exited
/// (stale binary, db migration failure, broken vault) must surface as an
/// error instead of a reported-successful start. `try_wait` can transiently
/// report None for a child that already exited but is not reaped yet, hence
/// the bounded loop rather than a single check.
async fn ensure_agent_alive(child: &mut tokio::process::Child) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut status = None;
    for _ in 0..20 {
        match child.try_wait()? {
            Some(exit) => {
                status = Some(exit);
                break;
            }
            None => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    let Some(status) = status else {
        return Ok(());
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr_output = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_output).await;
    }
    let stderr_output = stderr_output.trim();
    if stderr_output.is_empty() {
        anyhow::bail!("persona-ssh-agent exited early with status {}", status);
    }
    anyhow::bail!(
        "persona-ssh-agent exited early with status {}: {}",
        status,
        stderr_output
    );
}

fn resolve_agent_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PERSONA_SSH_AGENT_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
        anyhow::bail!(
            "PERSONA_SSH_AGENT_BIN is set but does not point to a file: {}",
            candidate.display()
        );
    }

    let binary_name = agent_binary_name();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(resolved) = find_agent_binary_near(&current_exe, binary_name) {
            return Ok(resolved);
        }
    }

    Ok(PathBuf::from(binary_name))
}

fn agent_state_dir() -> PathBuf {
    std::env::var("PERSONA_AGENT_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
        })
}

fn find_agent_binary_near(current_exe: &Path, binary_name: &str) -> Option<PathBuf> {
    let current_dir = current_exe.parent()?;
    let candidates = [
        current_dir.join(binary_name),
        current_dir.join("deps").join(binary_name),
        current_dir.parent().map(|dir| dir.join(binary_name))?,
        current_dir
            .parent()
            .map(|dir| dir.join("deps").join(binary_name))?,
    ];

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(unix)]
fn agent_binary_name() -> &'static str {
    "persona-ssh-agent"
}

#[cfg(windows)]
fn agent_binary_name() -> &'static str {
    "persona-ssh-agent.exe"
}

fn print_sock_export(sock_value: &str) {
    for line in format_sock_export_lines(sock_value) {
        println!("{line}");
    }
}

fn format_sock_export_lines(sock_value: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec![format!("  export SSH_AUTH_SOCK={}", sock_value)]
    }
    #[cfg(windows)]
    {
        vec![
            "  # PowerShell".to_string(),
            format!("  $env:SSH_AUTH_SOCK = '{}'", sock_value),
            "  # cmd.exe".to_string(),
            format!("  set SSH_AUTH_SOCK={}", sock_value),
        ]
    }
}

async fn agent_status(_config: &crate::config::CliConfig) -> Result<()> {
    let state_dir = agent_state_dir();
    let sock_file = state_dir.join("ssh-agent.sock");
    let pid_file = state_dir.join("ssh-agent.pid");
    let mut running = false;
    if sock_file.exists() {
        let sock = std::fs::read_to_string(&sock_file).unwrap_or_default();
        println!("{} {}", "Socket:".yellow(), sock.trim().cyan());
        running = true;
    }
    if pid_file.exists() {
        let pid = std::fs::read_to_string(&pid_file).unwrap_or_default();
        println!("{} {}", "PID:".yellow(), pid.trim().cyan());
        running = true;
    }
    // Try to query agent identities
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        if let Ok(count) = query_agent_identities(&sock).await {
            println!("{} {}", "Agent keys:".yellow(), count.to_string().cyan());
        }
    } else if sock_file.exists() {
        let sock = std::fs::read_to_string(&sock_file).unwrap_or_default();
        if let Ok(count) = query_agent_identities(sock.trim()).await {
            println!("{} {}", "Agent keys:".yellow(), count.to_string().cyan());
        }
    }
    if !running {
        println!("{}", "persona-ssh-agent is not running.".yellow());
    }
    Ok(())
}

#[cfg(unix)]
async fn query_agent_identities(sock_path: &str) -> Result<usize> {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("Failed to connect to agent at {}", sock_path))?;
    // Build request: len(4) + type(1)=11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11u8;
    stream.write_all(&pkt).await?;
    // Read response len
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    if resp.is_empty() || resp[0] != 12 {
        anyhow::bail!("Unexpected agent response");
    }
    // parse count
    if resp.len() < 5 {
        anyhow::bail!("Malformed agent response");
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(windows)]
async fn query_agent_identities(sock_path: &str) -> Result<usize> {
    use byteorder::{BigEndian, ByteOrder};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pipe_name = if sock_path.starts_with(r"\\.\pipe\") {
        sock_path.to_string()
    } else {
        format!(r"\\.\pipe\{}", sock_path)
    };

    let mut stream = open_named_pipe_with_retry(&pipe_name, 10, Duration::from_millis(50))
        .await
        .with_context(|| format!("Failed to connect to agent at {}", pipe_name))?;

    // Build request: len(4) + type(1)=11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11u8;
    stream.write_all(&pkt).await?;

    // Read response len
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    if resp.is_empty() || resp[0] != 12 {
        anyhow::bail!("Unexpected agent response");
    }
    // parse count
    if resp.len() < 5 {
        anyhow::bail!("Malformed agent response");
    }
    let count = BigEndian::read_u32(&resp[1..5]) as usize;
    Ok(count)
}

#[cfg(windows)]
async fn open_named_pipe_with_retry(
    pipe_name: &str,
    attempts: usize,
    delay: std::time::Duration,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..attempts {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) => {
                let retryable = matches!(err.raw_os_error(), Some(231)) // ERROR_PIPE_BUSY
                    || err.kind() == std::io::ErrorKind::NotFound;
                last_err = Some(err);
                if !retryable {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
    }

    Err(anyhow::anyhow!(
        "Failed to open named pipe {}: {}",
        pipe_name,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn run_with_host(
    host: &str,
    command: Vec<String>,
    _config: &crate::config::CliConfig,
) -> Result<()> {
    use tokio::process::Command;
    if command.is_empty() {
        anyhow::bail!("Provide a command after --");
    }
    // Write host to state file
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).ok();
    let host_file = state_dir.join("agent-target-host");
    std::fs::write(&host_file, host).context("Failed to write agent target host")?;
    // Spawn command
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    if let Some(sock) = current_or_stored_agent_socket(&state_dir) {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let status = cmd.status().await.context("Failed to run command")?;
    // Cleanup
    let _ = std::fs::remove_file(&host_file);
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("Command exited with status {}", status)
    }
}

fn current_or_stored_agent_socket(state_dir: &Path) -> Option<String> {
    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        let trimmed = sock.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let sock_file = state_dir.join("ssh-agent.sock");
    let sock = std::fs::read_to_string(sock_file).ok()?;
    let trimmed = sock.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

async fn import_seed(
    identity_name: &str,
    label: Option<String>,
    seed_b64: Option<String>,
    seed_hex: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "🔑 Importing SSH seed...".cyan().bold());
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    let seed = if let Some(b64) = seed_b64 {
        BASE64.decode(&b64).context("Invalid base64 seed")?
    } else if let Some(hexs) = seed_hex {
        let cleaned = hexs.trim();
        hex::decode(cleaned).context("Invalid hex seed")?
    } else {
        anyhow::bail!("Provide --seed-base64 or --seed-hex");
    };
    if seed.len() != 32 {
        anyhow::bail!("Seed must be 32 bytes for ed25519");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed[..32]);
    // Derive public key
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let signing = SigningKey::from_bytes(&arr);
    let verifying: VerifyingKey = signing.verifying_key();
    let pub_bytes = verifying.to_bytes();
    let public_openssh = encode_ssh_ed25519_public(&pub_bytes, None);
    let name = label.unwrap_or_else(|| "SSH Key (imported)".to_string());
    let ssh_data = SshKeyData {
        private_key: BASE64.encode(arr),
        public_key: public_openssh.clone(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };
    let cred = service
        .create_credential(
            identity.id,
            name.clone(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;
    println!("{} Imported SSH key:", "✓".green().bold());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Name: {}", name.cyan());
    println!("  Public: {}", public_openssh);
    println!("  ID: {}", cred.id);
    Ok(())
}

async fn export_pubkey(
    id: uuid::Uuid,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    if let Some(cred) = service.get_credential(&id).await? {
        if !matches!(cred.credential_type, CredentialType::SshKey) {
            anyhow::bail!("Credential is not an SSH key");
        }
        if let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&id).await? {
            println!("{}", ssh.public_key);
            Ok(())
        } else {
            anyhow::bail!("Unable to decrypt SSH key (locked?)");
        }
    } else {
        anyhow::bail!("Credential not found");
    }
}

fn stop_agent() -> Result<()> {
    let state_dir = agent_state_dir();
    let pid_file = state_dir.join("ssh-agent.pid");
    if !pid_file.exists() {
        println!("{}", "No agent PID file found.".yellow());
        return Ok(());
    }
    let pid_str = std::fs::read_to_string(&pid_file).unwrap_or_default();
    let pid = pid_str.trim();
    if pid.is_empty() {
        println!("{}", "Empty PID file.".yellow());
        return Ok(());
    }
    let stopped = stop_agent_pid(pid)?;
    if stopped {
        println!("{} Stopped persona-ssh-agent (pid {})", "✓".green(), pid);
        // Cleanup sock/pid files
        let _ = std::fs::remove_file(pid_file);
        let sock_file = state_dir.join("ssh-agent.sock");
        let _ = std::fs::remove_file(sock_file);
    } else {
        println!("{}", "Failed to stop agent".red());
    }
    Ok(())
}

#[cfg(unix)]
fn stop_agent_pid(pid: &str) -> Result<bool> {
    use std::process::Command;
    Ok(matches!(Command::new("kill").arg(pid).status(), Ok(s) if s.success()))
}

#[cfg(windows)]
fn stop_agent_pid(pid: &str) -> Result<bool> {
    use std::process::Command;

    let status = Command::new("taskkill").args(["/PID", pid, "/T"]).status();
    if matches!(status, Ok(s) if s.success()) {
        return Ok(true);
    }

    let status_force = Command::new("taskkill")
        .args(["/PID", pid, "/T", "/F"])
        .status();
    Ok(matches!(status_force, Ok(s) if s.success()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;
    #[allow(unused_imports)]
    use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
    use crate::utils::prompt::TerminalUi;
    use persona_core::auth::authentication::AuthResult;
    use persona_core::models::{ApiKeyData, IdentityType};
    use persona_core::storage::IdentityRepository;
    use persona_core::Repository;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes env reads against the tests that mutate
    /// `PERSONA_MASTER_PASSWORD` from other threads (env-first prompting
    /// would otherwise swallow their value instead of the scripted one).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_env() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            crate::commands::bridge::tests::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
        )
    }

    async fn ssh_test_config(dir: &TempDir) -> crate::config::CliConfig {
        let mut config = crate::config::CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        config
    }

    #[tokio::test]
    async fn ensure_service_unlocks_with_scripted_password() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = ssh_test_config(&dir).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }

        // Wrong scripted password fails authentication.
        let ui = ScriptedUi::new().password("wrong-pin");
        let Err(err) = ensure_service(&config, &ui).await else {
            panic!("wrong password must fail");
        };
        assert!(err.to_string().contains("Authentication failed"));
        assert!(ui.exhausted());

        // The correct scripted password unlocks the service.
        let ui = ScriptedUi::new().password("master-pin");
        let service = ensure_service(&config, &ui)
            .await
            .expect("correct password must unlock");
        assert!(service.has_users().await.unwrap());
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn remove_key_confirm_gate_cancels_or_deletes() {
        let _env = lock_process_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = ssh_test_config(&dir).await;
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            service.initialize_user("master-pin").await.unwrap();
        }
        let id = uuid::Uuid::new_v4();

        // Declining the confirmation keeps everything untouched. The unlock
        // password is consumed before the confirm gate.
        let ui = ScriptedUi::new().password("master-pin").confirm(false);
        remove_key(id, false, &config, &ui)
            .await
            .expect("declined removal returns success");
        assert!(ui.exhausted());

        // Accepting proceeds (the id does not exist; delete is a no-op).
        let ui = ScriptedUi::new().password("master-pin").confirm(true);
        remove_key(id, false, &config, &ui)
            .await
            .expect("confirmed removal returns success");
        assert!(ui.exhausted());

        // --yes skips the confirm prompt entirely.
        let ui = ScriptedUi::new().password("master-pin");
        remove_key(id, true, &config, &ui)
            .await
            .expect("forced removal returns success");
        assert!(ui.exhausted(), "--yes must not touch the confirm queue");

        // The CLI dispatch arm reaches the same flow.
        let ui = ScriptedUi::new().password("master-pin").confirm(false);
        execute_with(
            ssh_args(SshSubcommand::Remove { id, yes: false }),
            &config,
            &ui,
        )
        .await
        .expect("dispatched removal cancel works");
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn ensure_service_without_users_needs_no_prompt() {
        let dir = TempDir::new().unwrap();
        let config = ssh_test_config(&dir).await;
        let ui = ScriptedUi::new();
        let service = ensure_service(&config, &ui)
            .await
            .expect("userless workspace opens without prompting");
        assert!(!service.has_users().await.unwrap());
        assert!(ui.exhausted(), "no prompt consumed");

        // Keep TerminalUi referenced so the import stays honest.
        let _ = TerminalUi;
    }

    fn build_identities_answer(count: u32) -> Vec<u8> {
        use byteorder::{BigEndian, ByteOrder};
        let mut payload = Vec::with_capacity(1 + 4);
        payload.push(12u8);
        let mut count_buf = [0u8; 4];
        BigEndian::write_u32(&mut count_buf, count);
        payload.extend_from_slice(&count_buf);

        let mut out = Vec::with_capacity(4 + payload.len());
        let mut len_buf = [0u8; 4];
        BigEndian::write_u32(&mut len_buf, payload.len() as u32);
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn encode_ssh_ed25519_public_has_expected_prefix_and_blob() {
        let pubkey = [7u8; 32];
        let line = encode_ssh_ed25519_public(&pubkey, Some("comment"));
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" comment"));

        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 3);

        let decoded = BASE64.decode(parts[1]).unwrap();
        assert!(decoded.len() >= 4 + b"ssh-ed25519".len() + 4 + 32);
    }

    #[cfg(unix)]
    #[test]
    fn format_sock_export_lines_unix() {
        let lines = format_sock_export_lines("/tmp/persona.sock");
        assert_eq!(
            lines,
            vec!["  export SSH_AUTH_SOCK=/tmp/persona.sock".to_string()]
        );
    }

    #[cfg(windows)]
    #[test]
    fn format_sock_export_lines_windows() {
        let lines = format_sock_export_lines(r"\\.\pipe\persona-test");
        assert_eq!(
            lines,
            vec![
                "  # PowerShell".to_string(),
                "  $env:SSH_AUTH_SOCK = '\\\\.\\pipe\\persona-test'".to_string(),
                "  # cmd.exe".to_string(),
                "  set SSH_AUTH_SOCK=\\\\.\\pipe\\persona-test".to_string(),
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn query_agent_identities_unix_mock_server() {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("persona-test-agent.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let req_len = BigEndian::read_u32(&len_buf) as usize;
            let mut req = vec![0u8; req_len];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(req, vec![11u8]);

            let resp = build_identities_answer(0);
            stream.write_all(&resp).await.unwrap();
        });

        let count = query_agent_identities(sock_path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(count, 0);
        server_task.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(unused_mut)]
    async fn query_agent_identities_windows_mock_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(r"\\.\pipe\persona-test-agent-{}", Uuid::new_v4());
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .unwrap();

        let server_task = tokio::spawn(async move {
            server.connect().await.unwrap();

            let mut len_buf = [0u8; 4];
            server.read_exact(&mut len_buf).await.unwrap();
            let req_len = u32::from_be_bytes(len_buf) as usize;
            let mut req = vec![0u8; req_len];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req, vec![11u8]);

            let resp = build_identities_answer(0);
            server.write_all(&resp).await.unwrap();
        });

        let count = query_agent_identities(&pipe_name).await.unwrap();
        assert_eq!(count, 0);
        server_task.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(unused_mut)]
    async fn open_named_pipe_with_retry_waits_for_server() {
        use std::time::Duration;
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(r"\\.\pipe\persona-test-retry-{}", Uuid::new_v4());

        let pipe_name_for_client = pipe_name.clone();
        let client_task = tokio::spawn(async move {
            open_named_pipe_with_retry(&pipe_name_for_client, 50, Duration::from_millis(10))
                .await
                .unwrap()
        });

        tokio::time::sleep(Duration::from_millis(80)).await;

        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .unwrap();
        server.connect().await.unwrap();

        let _client = client_task.await.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stop_agent_pid_nonexistent_returns_false() {
        assert!(!stop_agent_pid("99999999").unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn stop_agent_pid_nonexistent_returns_false() {
        assert!(!stop_agent_pid("99999999").unwrap());
    }

    // ------------------------------------------------------------------
    // Helpers for the command-level flows.
    // ------------------------------------------------------------------

    fn ssh_args(command: SshSubcommand) -> SshArgs {
        SshArgs { command }
    }

    /// Workspace with an initialized user and the identities `alice`/`bob`.
    async fn unlocked_workspace(dir: &TempDir, master: &str) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in ["alice", "bob"] {
            repo.create(&CoreIdentity::new(name.to_string(), IdentityType::Personal))
                .await
                .unwrap();
        }
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user(master).await.unwrap();
        config
    }

    /// Migrated, userless workspace: `ensure_service` never prompts.
    async fn userless_workspace(dir: &TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        config
    }

    async fn alice_credentials(config: &CliConfig, master: &str) -> Vec<(Uuid, CredentialType)> {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        assert!(matches!(
            service.authenticate_user(master).await.unwrap(),
            AuthResult::Success
        ));
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        service
            .get_credentials_for_identity(&identity.id)
            .await
            .unwrap()
            .into_iter()
            .map(|c| (c.id, c.credential_type))
            .collect()
    }

    /// Points `PERSONA_AGENT_STATE_DIR` at `dir` for the duration of the
    /// test so pid/socket files never touch the real home directory.
    /// Drop-restores the previous value.
    struct StateDirGuard {
        prev: Option<std::ffi::OsString>,
    }

    impl Drop for StateDirGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(prev) => std::env::set_var("PERSONA_AGENT_STATE_DIR", prev),
                None => std::env::remove_var("PERSONA_AGENT_STATE_DIR"),
            }
        }
    }

    fn sandbox_agent_state_dir(dir: &TempDir) -> StateDirGuard {
        let prev = std::env::var("PERSONA_AGENT_STATE_DIR").ok();
        std::env::set_var("PERSONA_AGENT_STATE_DIR", dir.path());
        StateDirGuard {
            prev: prev.map(Into::into),
        }
    }

    /// Captures an env var and drop-restores it.
    struct EnvVarGuard {
        name: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var(name).ok();
            std::env::set_var(name, &value);
            EnvVarGuard {
                name,
                prev: prev.map(Into::into),
            }
        }

        fn remove(name: &'static str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::remove_var(name);
            EnvVarGuard {
                name,
                prev: prev.map(Into::into),
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(prev) => std::env::set_var(self.name, prev),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[cfg(unix)]
    fn write_executable(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    async fn serve_one_identity_query(listener: tokio::net::UnixListener, count: u32) {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let req_len = BigEndian::read_u32(&len_buf) as usize;
        let mut req = vec![0u8; req_len];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req, vec![11u8]);
        let resp = build_identities_answer(count);
        stream.write_all(&resp).await.unwrap();
    }

    /// Mock agent that replies with an arbitrary payload.
    #[cfg(unix)]
    async fn serve_raw_reply(listener: tokio::net::UnixListener, payload: Vec<u8>) {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let req_len = BigEndian::read_u32(&len_buf) as usize;
        let mut req = vec![0u8; req_len];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req, vec![11u8]);

        let mut out = Vec::with_capacity(4 + payload.len());
        let mut len_buf = [0u8; 4];
        BigEndian::write_u32(&mut len_buf, payload.len() as u32);
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(&payload);
        stream.write_all(&out).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn query_agent_identities_rejects_bad_responses() {
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();

        // A response with an unexpected type byte is refused.
        let listener = UnixListener::bind(dir.path().join("bad-type.sock")).unwrap();
        let server = tokio::spawn(serve_raw_reply(listener, vec![6u8]));
        let err = query_agent_identities(dir.path().join("bad-type.sock").to_str().unwrap())
            .await
            .expect_err("wrong response type must fail");
        assert!(err.to_string().contains("Unexpected agent response"));
        server.await.unwrap();

        // A truncated identities answer is refused.
        let listener = UnixListener::bind(dir.path().join("short.sock")).unwrap();
        let server = tokio::spawn(serve_raw_reply(listener, vec![12u8]));
        let err = query_agent_identities(dir.path().join("short.sock").to_str().unwrap())
            .await
            .expect_err("truncated response must fail");
        assert!(err.to_string().contains("Malformed agent response"));
        server.await.unwrap();
    }

    // ------------------------------------------------------------------
    // ensure_service: non-interactive env resolution.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn ensure_service_non_interactive_uses_env_password() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let mut config = unlocked_workspace(&dir, "master-pin").await;
        config.ui.interactive = false;

        // Without the env var there is no prompt to fall back to.
        let ui = ScriptedUi::new();
        let Err(err) = ensure_service(&config, &ui).await else {
            panic!("missing env password must fail");
        };
        assert!(err.to_string().contains("PERSONA_MASTER_PASSWORD"));
        assert!(ui.exhausted(), "non-interactive mode never prompts");

        // With the env var set the service unlocks without any prompt.
        let _pw = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");
        let ui = ScriptedUi::new();
        let service = ensure_service(&config, &ui)
            .await
            .expect("env password unlocks the service");
        assert!(service.has_users().await.unwrap());
        assert!(ui.exhausted());
    }

    // ------------------------------------------------------------------
    // generate / list / list-all / export-pub.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn generate_list_and_list_all_flows() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        // With no keys anywhere yet, list-all reports the empty state.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
            .await
            .expect("list-all on a keyless workspace works");
        assert!(ui.exhausted());

        // Non-ed25519 key types are refused before anything is unlocked.
        let ui = ScriptedUi::new();
        let err = execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: None,
                key_type: "rsa".to_string(),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("rsa must be refused");
        assert!(err.to_string().contains("Only ed25519"));
        assert!(ui.exhausted());

        // Generating with an explicit label and favorite flag.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: Some("work-key".to_string()),
                key_type: "ed25519".to_string(),
                favorite: true,
            }),
            &config,
            &ui,
        )
        .await
        .expect("generate with a label works");
        assert!(ui.exhausted());

        // Generating with the default label.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: None,
                key_type: "ed25519".to_string(),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect("generate with the default label works");
        assert!(ui.exhausted());

        // Generating against an unknown identity fails during resolution.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "ghost".to_string(),
                name: None,
                key_type: "ed25519".to_string(),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
        assert!(ui.exhausted());

        // List reports alice's keys…
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::List {
                identity: "alice".to_string(),
            }),
            &config,
            &ui,
        )
        .await
        .expect("list works");
        assert!(ui.exhausted());

        // …and the empty state for bob.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::List {
                identity: "bob".to_string(),
            }),
            &config,
            &ui,
        )
        .await
        .expect("empty list works");
        assert!(ui.exhausted());

        // List-all spans identities.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
            .await
            .expect("list-all works");
        assert!(ui.exhausted());
    }

    #[tokio::test]
    async fn export_pubkey_branches() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: Some("pubkey-src".to_string()),
                key_type: "ed25519".to_string(),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect("generate works");

        // A non-SSH credential to exercise the type guard.
        {
            let db = Database::from_file(config.get_database_path())
                .await
                .unwrap();
            let mut service = crate::commands::service::new_service(db).await.unwrap();
            assert!(matches!(
                service.authenticate_user("master-pin").await.unwrap(),
                AuthResult::Success
            ));
            let identity = service
                .get_identity_by_name("alice")
                .await
                .unwrap()
                .unwrap();
            service
                .create_credential(
                    identity.id,
                    "token".to_string(),
                    CredentialType::ApiKey,
                    SecurityLevel::Medium,
                    &CredentialData::ApiKey(ApiKeyData {
                        api_key: "k".to_string(),
                        api_secret: None,
                        token: None,
                        permissions: Vec::new(),
                        expires_at: None,
                    }),
                )
                .await
                .unwrap();
        }

        let creds = alice_credentials(&config, "master-pin").await;
        let ssh_id = creds
            .iter()
            .find(|(_, t)| matches!(t, CredentialType::SshKey))
            .expect("ssh key present")
            .0;
        let api_id = creds
            .iter()
            .find(|(_, t)| matches!(t, CredentialType::ApiKey))
            .expect("api key present")
            .0;

        // The happy path prints the OpenSSH line.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::ExportPub { id: ssh_id }),
            &config,
            &ui,
        )
        .await
        .expect("export pubkey works");
        assert!(ui.exhausted());

        // A non-SSH credential is refused.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ExportPub { id: api_id }),
            &config,
            &ui,
        )
        .await
        .expect_err("non-ssh credential must fail");
        assert!(err.to_string().contains("Credential is not an SSH key"));
        assert!(ui.exhausted());

        // An unknown id is refused.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ExportPub { id: Uuid::new_v4() }),
            &config,
            &ui,
        )
        .await
        .expect_err("unknown credential must fail");
        assert!(err.to_string().contains("Credential not found"));
        assert!(ui.exhausted());
    }

    // ------------------------------------------------------------------
    // import: base64/hex seeds and rejections.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn import_seed_variants_and_rejections() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;
        let seed = [9u8; 32];

        // base64 seed with an explicit label.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: Some("imported-b64".to_string()),
                seed_base64: Some(BASE64.encode(seed)),
                seed_hex: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("base64 import works");
        assert!(ui.exhausted());

        // hex seed (outer whitespace tolerated, default label).
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: None,
                seed_base64: None,
                seed_hex: Some(format!(" {} ", hex::encode(seed))),
            }),
            &config,
            &ui,
        )
        .await
        .expect("hex import works");
        assert!(ui.exhausted());

        // Neither seed source.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: None,
                seed_base64: None,
                seed_hex: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("missing seed must fail");
        assert!(err
            .to_string()
            .contains("Provide --seed-base64 or --seed-hex"));
        assert!(ui.exhausted());

        // A seed of the wrong length.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: None,
                seed_base64: Some(BASE64.encode([7u8; 16])),
                seed_hex: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("short seed must fail");
        assert!(err.to_string().contains("Seed must be 32 bytes"));

        // Undecodable base64.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: None,
                seed_base64: Some("!!not-base64!!".to_string()),
                seed_hex: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("bad base64 must fail");
        assert!(err.to_string().contains("Invalid base64 seed"));

        // Undecodable hex.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "alice".to_string(),
                name: None,
                seed_base64: None,
                seed_hex: Some("zz-nothex".to_string()),
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("bad hex must fail");
        assert!(err.to_string().contains("Invalid hex seed"));

        // Unknown identity.
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Import {
                identity: "ghost".to_string(),
                name: None,
                seed_base64: Some(BASE64.encode(seed)),
                seed_hex: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("unknown identity must fail");
        assert!(err.to_string().contains("Identity 'ghost' not found"));
    }

    // ------------------------------------------------------------------
    // run-with-host and socket resolution.
    // ------------------------------------------------------------------

    #[test]
    fn current_or_stored_agent_socket_prefers_env_then_file() {
        let _env = lock_process_env();
        let _sock = EnvVarGuard::remove("SSH_AUTH_SOCK");
        let dir = TempDir::new().unwrap();
        let state = dir.path();
        let sock_file = state.join("ssh-agent.sock");

        // Nothing recorded: no socket.
        assert_eq!(current_or_stored_agent_socket(state), None);

        // A stored sock file is picked up.
        std::fs::write(&sock_file, "/tmp/persona-stored.sock\n").unwrap();
        assert_eq!(
            current_or_stored_agent_socket(state).as_deref(),
            Some("/tmp/persona-stored.sock")
        );

        // A whitespace-only file counts as absent.
        std::fs::write(&sock_file, "   \n").unwrap();
        assert_eq!(current_or_stored_agent_socket(state), None);

        // A non-empty env var wins over the file…
        std::fs::write(&sock_file, "/tmp/persona-stored.sock").unwrap();
        let _env_sock = EnvVarGuard::set("SSH_AUTH_SOCK", "/tmp/persona-env.sock");
        assert_eq!(
            current_or_stored_agent_socket(state).as_deref(),
            Some("/tmp/persona-env.sock")
        );

        // …while a whitespace-only env falls back to the file.
        let _env_blank = EnvVarGuard::set("SSH_AUTH_SOCK", "   ");
        assert_eq!(
            current_or_stored_agent_socket(state).as_deref(),
            Some("/tmp/persona-stored.sock")
        );
    }

    #[tokio::test]
    async fn run_with_host_validates_command_and_exit_status() {
        let _env = lock_process_env();
        let state_dir = TempDir::new().unwrap();
        let _state = sandbox_agent_state_dir(&state_dir);
        let dir = TempDir::new().unwrap();
        let config = userless_workspace(&dir).await;

        // A stored socket file makes the env branch pass the socket down.
        std::fs::write(
            agent_state_dir().join("ssh-agent.sock"),
            "/tmp/persona-run.sock",
        )
        .unwrap();

        // An empty command list is refused.
        let err = run_with_host("example.com", Vec::new(), &config)
            .await
            .expect_err("empty command must fail");
        assert!(err.to_string().contains("Provide a command after --"));

        // A successful command cleans the host file up afterwards. Extra
        // tokens after the binary are forwarded as arguments.
        let echo_cmd = if cfg!(target_os = "windows") {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "echo".to_string(),
                "persona-ok".to_string(),
            ]
        } else {
            vec!["/bin/echo".to_string(), "persona-ok".to_string()]
        };
        execute_with(
            ssh_args(SshSubcommand::Run {
                host: "example.com".to_string(),
                command: echo_cmd,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("successful command works");
        assert!(
            !agent_state_dir().join("agent-target-host").exists(),
            "host file cleaned up"
        );

        // A failing command surfaces its exit status.
        let fail_cmd = if cfg!(target_os = "windows") {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "exit".to_string(),
                "1".to_string(),
            ]
        } else {
            vec!["/bin/false".to_string()]
        };
        let err = run_with_host("example.com", fail_cmd, &config)
            .await
            .expect_err("failing command must fail");
        assert!(err.to_string().contains("Command exited with status"));
    }

    // ------------------------------------------------------------------
    // status / stop / agent lifecycle.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn execute_and_status_dispatch_without_service() {
        let _env = lock_process_env();
        let dir = TempDir::new().unwrap();
        let _state = sandbox_agent_state_dir(&dir);
        let config = userless_workspace(&dir).await;

        // The thin execute() wrapper (TerminalUi): Status never touches the
        // service, so it is prompt-free even without a TTY.
        execute(ssh_args(SshSubcommand::Status), &config)
            .await
            .expect("status dispatch works");

        execute_with(
            ssh_args(SshSubcommand::AgentStatus),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("agent status dispatch works");

        // StopAgent without a PID file just reports.
        execute_with(
            ssh_args(SshSubcommand::StopAgent),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("stop without an agent works");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agent_status_reports_files_and_queries_mock_agent() {
        use tokio::net::UnixListener;

        let _env = lock_process_env();
        let dir = TempDir::new().unwrap();
        let _state = sandbox_agent_state_dir(&dir);
        let _sock = EnvVarGuard::remove("SSH_AUTH_SOCK");
        let config = userless_workspace(&dir).await;

        // No state files: reports "not running".
        agent_status(&config)
            .await
            .expect("status without agent works");

        // Socket + pid files are reported.
        std::fs::write(
            dir.path().join("ssh-agent.sock"),
            "/tmp/persona-status.sock\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("ssh-agent.pid"), "424242\n").unwrap();
        agent_status(&config)
            .await
            .expect("status with files works");

        // A reachable agent answers the identity query.
        let listener = UnixListener::bind(dir.path().join("query.sock")).unwrap();
        let server = tokio::spawn(serve_one_identity_query(listener, 3));
        let _env_sock = EnvVarGuard::set(
            "SSH_AUTH_SOCK",
            dir.path().join("query.sock").to_string_lossy().to_string(),
        );
        agent_status(&config)
            .await
            .expect("status with a live agent works");
        server.await.unwrap();

        // With SSH_AUTH_SOCK unset, the stored socket file is consulted.
        let _no_env_sock = EnvVarGuard::remove("SSH_AUTH_SOCK");
        let listener2 = UnixListener::bind(dir.path().join("query2.sock")).unwrap();
        let server2 = tokio::spawn(serve_one_identity_query(listener2, 1));
        std::fs::write(
            dir.path().join("ssh-agent.sock"),
            dir.path().join("query2.sock").to_string_lossy().to_string(),
        )
        .unwrap();
        agent_status(&config)
            .await
            .expect("status via the stored socket file works");
        server2.await.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stop_agent_handles_missing_empty_and_live_pid_files() {
        let _env = lock_process_env();
        let dir = TempDir::new().unwrap();
        let _state = sandbox_agent_state_dir(&dir);

        // No PID file at all.
        stop_agent().expect("stop without a pid file works");

        // Whitespace-only PID file.
        std::fs::write(dir.path().join("ssh-agent.pid"), "  \n").unwrap();
        stop_agent().expect("stop with an empty pid file works");

        // A live process is stopped and the state files are cleaned up.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        std::fs::write(dir.path().join("ssh-agent.pid"), child.id().to_string()).unwrap();
        std::fs::write(dir.path().join("ssh-agent.sock"), "/tmp/persona-stop.sock").unwrap();
        stop_agent().expect("stop with a live pid works");
        let _ = child.wait(); // reap
        assert!(
            !dir.path().join("ssh-agent.pid").exists(),
            "pid file removed"
        );
        assert!(
            !dir.path().join("ssh-agent.sock").exists(),
            "sock file removed"
        );

        // An unkillable pid reports failure without erroring.
        std::fs::write(dir.path().join("ssh-agent.pid"), "99999999").unwrap();
        stop_agent().expect("a failed stop reports but does not error");
    }

    #[test]
    fn agent_state_dir_falls_back_to_home_when_unset() {
        let _env = lock_process_env();
        let _state = EnvVarGuard::remove("PERSONA_AGENT_STATE_DIR");

        let dir = agent_state_dir();
        assert!(
            dir.ends_with(".persona"),
            "unset env falls back to ~/.persona, got {}",
            dir.display()
        );

        // The env override wins when present.
        let custom = TempDir::new().unwrap();
        let _override = EnvVarGuard::set("PERSONA_AGENT_STATE_DIR", custom.path());
        assert_eq!(agent_state_dir(), custom.path());
    }

    #[test]
    fn resolve_agent_binary_env_overrides_and_fallbacks() {
        let _env = lock_process_env();
        let dir = TempDir::new().unwrap();

        // A valid file path is taken verbatim.
        let fake = dir.path().join("fake-agent");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &fake);
        assert_eq!(resolve_agent_binary().unwrap(), fake);
        drop(_bin);

        // A non-file path is rejected.
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", dir.path().join("missing"));
        let err = resolve_agent_binary().expect_err("missing binary must fail");
        assert!(err.to_string().contains("does not point to a file"));
        drop(_bin);

        // Unset: falls back to a lookup near the current executable or the
        // bare name (which the shell would resolve).
        let _bin = EnvVarGuard::remove("PERSONA_SSH_AGENT_BIN");
        let resolved = resolve_agent_binary().unwrap();
        assert!(resolved.ends_with(agent_binary_name()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_agent_parses_socket_line_and_failure_paths() {
        let _env = lock_process_env();
        let dir = TempDir::new().unwrap();
        let _state = sandbox_agent_state_dir(&dir);
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        // Userless workspace: ensure_service never prompts; the agent's own
        // password prompt is bypassed by the non-interactive config.
        let mut config = userless_workspace(&dir).await;
        config.ui.interactive = false;

        // Success: the agent prints its socket; export lines are printed.
        let agent = write_executable(
            &dir,
            "agent-ok",
            "#!/bin/sh\necho \"SSH_AUTH_SOCK=/tmp/persona-fake.sock\"\n",
        );
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
        execute_with(
            ssh_args(SshSubcommand::StartAgent { print_export: true }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("fake agent with a socket line works");

        // The add-to-agent alias reaches the same code path.
        execute_with(
            ssh_args(SshSubcommand::AddToAgent {
                identity: None,
                print_export: false,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("add-to-agent alias works");
        drop(_bin);

        // Early non-zero exit with stderr. start_agent detects the early exit
        // after stdout hits EOF; there is an inherent scheduling window where
        // the child is gone from the pipe but try_wait still reports None, so
        // retry a few times until the run resolves as a failure.
        let agent = write_executable(&dir, "agent-fail", "#!/bin/sh\necho boom >&2\nexit 3\n");
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
        let mut err = None;
        for _ in 0..10 {
            if let Some(e) = execute_with(
                ssh_args(SshSubcommand::StartAgent {
                    print_export: false,
                }),
                &config,
                &ScriptedUi::new(),
            )
            .await
            .err()
            {
                err = Some(e);
                break;
            }
        }
        let err = err.expect("failing agent must fail");
        assert!(err.to_string().contains("exited early with status"));
        assert!(err.to_string().contains("boom"), "stderr is surfaced");
        drop(_bin);

        // Early non-zero exit without stderr.
        let agent = write_executable(&dir, "agent-silent", "#!/bin/sh\nexit 7\n");
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
        let mut err = None;
        for _ in 0..10 {
            if let Some(e) = execute_with(
                ssh_args(SshSubcommand::StartAgent {
                    print_export: false,
                }),
                &config,
                &ScriptedUi::new(),
            )
            .await
            .err()
            {
                err = Some(e);
                break;
            }
        }
        let err = err.expect("silently failing agent must fail");
        assert!(err.to_string().contains("exited early with status"));
        drop(_bin);

        // Clean exit without a socket line degrades to a warning.
        let agent = write_executable(&dir, "agent-quiet", "#!/bin/sh\necho hello\n");
        let _bin = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent);
        execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("quiet agent returns success");
        drop(_bin);

        // An interactive config is asked once for the agent's master
        // password; an empty answer is allowed. The fake agent sleeps so the
        // spawned process is still alive when start_agent returns.
        let agent_slow = write_executable(
            &dir,
            "agent-slow",
            "#!/bin/sh\necho \"SSH_AUTH_SOCK=/tmp/persona-slow.sock\"\nsleep 2\n",
        );
        let _bin_slow = EnvVarGuard::set("PERSONA_SSH_AGENT_BIN", &agent_slow);
        config.ui.interactive = true;
        execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config,
            &ScriptedUi::new().password(""),
        )
        .await
        .expect("interactive start accepts an empty agent password");

        // A non-interactive start forwards PERSONA_MASTER_PASSWORD instead.
        config.ui.interactive = false;
        let _pw_env = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "env-pin");
        execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("non-interactive start forwards the env password");

        // A failing interactive password prompt aborts before the agent
        // binary is even resolved.
        let dir2 = TempDir::new().unwrap();
        let _state2 = sandbox_agent_state_dir(&dir2);
        let mut config2 = userless_workspace(&dir2).await;
        config2.ui.interactive = true;
        let inner = ScriptedUi::new();
        let ui = FailOn::new(&inner, PromptKind::Password);
        let err = execute_with(
            ssh_args(SshSubcommand::StartAgent {
                print_export: false,
            }),
            &config2,
            &ui,
        )
        .await
        .expect_err("failing agent password prompt must abort");
        assert!(err.to_string().contains("failing ui: password prompt"));
    }

    #[tokio::test]
    async fn list_skips_non_ssh_keys_and_agent_resolution_plants_binary() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");
        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        // alice owns one SSH key and one API-key credential.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: None,
                key_type: "ed25519".to_string(),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect("ssh key generated");
        assert!(ui.exhausted());
        {
            let _pw_env = EnvVarGuard::set("PERSONA_MASTER_PASSWORD", "master-pin");
            let service = ensure_service(&config, &ScriptedUi::new())
                .await
                .expect("service unlocks via env");
            let identity = service
                .get_identity_by_name("alice")
                .await
                .unwrap()
                .unwrap();
            service
                .create_credential(
                    identity.id,
                    "api-token".to_string(),
                    persona_core::models::CredentialType::ApiKey,
                    persona_core::models::SecurityLevel::Medium,
                    &persona_core::models::CredentialData::ApiKey(ApiKeyData {
                        api_key: "k".to_string(),
                        api_secret: None,
                        token: None,
                        permissions: Vec::new(),
                        expires_at: None,
                    }),
                )
                .await
                .unwrap();
        }

        // Per-identity and global listings skip the non-SSH row. Each
        // execute_with call re-unlocks the workspace, so the scripted UI
        // needs a master password per subcommand.
        let ui = ScriptedUi::new()
            .password("master-pin")
            .password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::List {
                identity: "alice".to_string(),
            }),
            &config,
            &ui,
        )
        .await
        .expect("per-identity list skips non-ssh rows");
        execute_with(ssh_args(SshSubcommand::ListAll), &config, &ui)
            .await
            .expect("global list skips non-ssh rows");

        // A binary planted next to the current executable wins over the bare
        // PATH fallback once the env override is unset.
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let planted = exe_dir.join(agent_binary_name());
        std::fs::write(&planted, b"#!/bin/sh\n").unwrap();
        let resolved = resolve_agent_binary().unwrap();
        std::fs::remove_file(&planted).unwrap();
        assert_eq!(resolved, planted);
    }
}
