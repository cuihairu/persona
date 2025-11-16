use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::*;
use persona_core::{
    Database, PersonaService,
    models::{CredentialType, SecurityLevel, CredentialData, SshKeyData, Identity as CoreIdentity},
};
use dialoguer::{Input, Password, Confirm};
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
    /// Show agent status (placeholder)
    Status,
    /// Add keys to agent (placeholder)
    AddToAgent {
        /// Optional: identity name to filter (ignored in MVP)
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
    match args.command {
        SshSubcommand::Generate { identity, name, key_type, favorite } => {
            generate_key(&identity, name, &key_type, favorite, config).await
        }
        SshSubcommand::List { identity } => list_keys(&identity, config).await,
        SshSubcommand::Remove { id, yes } => remove_key(id, yes, config).await,
        SshSubcommand::Status => {
            println!("{}", "SSH Agent status (placeholder):".yellow().bold());
            println!("  {}", "Not implemented yet. Use your system ssh-agent temporarily.".dim());
            Ok(())
        }
        SshSubcommand::AddToAgent { identity: _, print_export } => start_agent(config, print_export).await,
        SshSubcommand::AgentStatus => agent_status(config),
        SshSubcommand::StartAgent { print_export } => start_agent(config, print_export).await,
        SshSubcommand::ListAll => list_all_keys(config).await,
        SshSubcommand::Import { identity, name, seed_base64, seed_hex } => import_seed(&identity, name, seed_base64, seed_hex, config).await,
        SshSubcommand::ExportPub { id } => export_pubkey(id, config).await,
        SshSubcommand::StopAgent => stop_agent(),
        SshSubcommand::Run { host, command } => run_with_host(&host, command, config).await,
    }
}

async fn ensure_service(config: &crate::config::CliConfig) -> Result<PersonaService> {
    let db_path = config.get_database_path();
    let db = Database::from_file(&db_path.to_string_lossy()).await
        .context("Failed to open database")?;
    db.migrate().await.context("Failed to run migrations")?;
    let mut service = PersonaService::new(db).await.context("Failed to create PersonaService")?;
    if service.has_users().await? {
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .interact()?;
        match service.authenticate_user(&password).await? {
            persona_core::auth::authentication::AuthResult::Success => {}
            other => anyhow::bail!("Authentication failed: {:?}", other),
        }
    }
    Ok(service)
}

async fn resolve_identity(service: &PersonaService, name: &str) -> Result<CoreIdentity> {
    service.get_identity_by_name(name).await?
        .with_context(|| format!("Identity '{}' not found", name))
}

async fn generate_key(identity_name: &str, label: Option<String>, key_type: &str, favorite: bool, config: &crate::config::CliConfig) -> Result<()> {
    println!("{}", "🔑 Generating SSH key...".cyan().bold());
    if key_type.to_lowercase() != "ed25519" {
        anyhow::bail!("Only ed25519 is supported currently");
    }

    let mut service = ensure_service(config).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // Generate ed25519 keypair
    use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let secret_bytes = signing_key.to_bytes(); // 32-byte seed
    let pub_bytes = verifying_key.to_bytes(); // 32-byte public

    // Encode to OpenSSH public line: base64 of [len:"ssh-ed25519"][b"ssh-ed25519"][len:pub][pub]
    let openssh_pub = encode_ssh_ed25519_public(&pub_bytes, None);
    let private_b64 = base64::encode(secret_bytes);

    let name = label.unwrap_or_else(|| format!("SSH Key ({})", identity.name));
    let mut data = SshKeyData {
        private_key: private_b64,
        public_key: openssh_pub.clone(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };
    let cred = service.create_credential(
        identity.id,
        name.clone(),
        CredentialType::SshKey,
        SecurityLevel::High,
        &CredentialData::SshKey(data.clone()),
    ).await?;

    println!("{} Created SSH key credential:", "✓".green().bold());
    println!("  Name: {}", name.cyan());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Public: {}", openssh_pub);
    println!("  ID: {}", cred.id);
    if favorite {
        println!("  {}", "Mark as favorite: TODO".dim());
    }
    Ok(())
}

async fn list_keys(identity_name: &str, config: &crate::config::CliConfig) -> Result<()> {
    let mut service = ensure_service(config).await?;
    let identity = resolve_identity(&service, identity_name).await?;
    let creds = service.get_credentials_for_identity(&identity.id).await?;
    let mut count = 0usize;
    for cred in creds {
        if matches!(cred.credential_type, CredentialType::SshKey) {
            count += 1;
            println!("{} {}", "#".dim(), count);
            println!("  ID: {}", cred.id);
            println!("  Name: {}", cred.name.cyan());
            println!("  Created: {}", cred.created_at.format("%Y-%m-%d %H:%M:%S"));
            println!("  Favorite: {}", if cred.is_favorite { "yes".green() } else { "no".dim() });
        }
    }
    if count == 0 {
        println!("{}", "No SSH keys for this identity.".yellow());
    }
    Ok(())
}

async fn remove_key(id: Uuid, yes: bool, config: &crate::config::CliConfig) -> Result<()> {
    let mut service = ensure_service(config).await?;
    if !yes {
        if !Confirm::new()
            .with_prompt(format!("Remove SSH key credential {}?", id))
            .default(false)
            .interact()? {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
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
    let b64 = base64::encode(&buf);
    match comment {
        Some(c) if !c.is_empty() => format!("ssh-ed25519 {} {}", b64, c),
        _ => format!("ssh-ed25519 {}", b64),
    }
}

async fn start_agent(config: &crate::config::CliConfig, print_export: bool) -> Result<()> {
    use tokio::process::Command;
    use tokio::io::{AsyncBufReadExt, BufReader};
    println!("{}", "Starting persona-ssh-agent...".cyan().bold());
    let db_path = config.get_database_path();
    let mut cmd = Command::new("persona-ssh-agent");
    cmd.env("PERSONA_DB_PATH", db_path.to_string_lossy().to_string());
    // if vault encrypted, prompt for master password and pass via env
    let mut tmp_service = ensure_service(config).await?; // ensure migrations; may prompt
    // If ensure_service prompted, service is unlocked; but agent needs password via env for future reloads
    // Here we conservatively ask user again (not stored from ensure_service)
    let pass = Password::new()
        .with_prompt("Enter master password for agent (leave empty if not set)")
        .allow_empty_password(true)
        .interact()?;
    if !pass.is_empty() {
        cmd.env("PERSONA_MASTER_PASSWORD", pass);
    }
    // forward stdout to capture SSH_AUTH_SOCK
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());
    let mut child = cmd.spawn().context("Failed to start persona-ssh-agent")?;
    let stdout = child.stdout.take().context("No stdout from agent")?;
    let mut reader = BufReader::new(stdout).lines();
    let mut sock_line = None;
    if let Some(line) = reader.next_line().await? {
        if line.starts_with("SSH_AUTH_SOCK=") {
            sock_line = Some(line);
        } else {
            println!("{}", line);
        }
    }
    if let Some(sock) = sock_line {
        println!("{} {}", "Agent socket:".yellow(), sock.split('=').nth(1).unwrap_or("").cyan());
        if print_export {
            println!();
            println!("{}", "Run the following in your shell:".dim());
            println!("  export {}", sock);
        }
    } else {
        println!("{}", "Could not detect SSH_AUTH_SOCK from agent output.".yellow());
    }

    Ok(())
}

fn agent_status(config: &crate::config::CliConfig) -> Result<()> {
    let state_dir = std::env::var("PERSONA_AGENT_STATE_DIR").ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join(".persona")
        });
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
        if let Ok(count) = query_agent_identities(&sock) {
            println!("{} {}", "Agent keys:".yellow(), count.to_string().cyan());
        }
    } else if sock_file.exists() {
        let sock = std::fs::read_to_string(&sock_file).unwrap_or_default();
        if let Ok(count) = query_agent_identities(sock.trim()) {
            println!("{} {}", "Agent keys:".yellow(), count.to_string().cyan());
        }
    }
    if !running {
        println!("{}", "persona-ssh-agent is not running.".yellow());
    }
    Ok(())
}

fn query_agent_identities(sock_path: &str) -> Result<usize> {
    use std::os::unix::net::UnixStream;
    use std::io::{Write, Read};
    use byteorder::{BigEndian, ByteOrder, WriteBytesExt, ReadBytesExt};
    let mut stream = UnixStream::connect(sock_path)
        .with_context(|| format!("Failed to connect to agent at {}", sock_path))?;
    // Build request: len(4) + type(1)=11
    let mut pkt = vec![0u8; 5];
    BigEndian::write_u32(&mut pkt[0..4], 1);
    pkt[4] = 11u8;
    stream.write_all(&pkt)?;
    // Read response len
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = BigEndian::read_u32(&len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
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

async fn run_with_host(host: &str, command: Vec<String>, _config: &crate::config::CliConfig) -> Result<()> {
    use tokio::process::Command;
    if command.is_empty() {
        anyhow::bail!("Provide a command after --");
    }
    // Write host to state file
    let state_dir = std::env::var("PERSONA_AGENT_STATE_DIR").ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join(".persona")
        });
    std::fs::create_dir_all(&state_dir).ok();
    let host_file = state_dir.join("agent-target-host");
    std::fs::write(&host_file, host).context("Failed to write agent target host")?;
    // Spawn command
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
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

async fn import_seed(identity_name: &str, label: Option<String>, seed_b64: Option<String>, seed_hex: Option<String>, config: &crate::config::CliConfig) -> Result<()> {
    println!("{}", "🔑 Importing SSH seed...".cyan().bold());
    let mut service = ensure_service(config).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    let mut seed = if let Some(b64) = seed_b64 {
        base64::decode(&b64).context("Invalid base64 seed")?
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
        private_key: base64::encode(arr),
        public_key: public_openssh.clone(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    };
    let cred = service.create_credential(
        identity.id,
        name.clone(),
        CredentialType::SshKey,
        SecurityLevel::High,
        &CredentialData::SshKey(ssh_data),
    ).await?;
    println!("{} Imported SSH key:", "✓".green().bold());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Name: {}", name.cyan());
    println!("  Public: {}", public_openssh);
    println!("  ID: {}", cred.id);
    Ok(())
}

async fn export_pubkey(id: uuid::Uuid, config: &crate::config::CliConfig) -> Result<()> {
    let mut service = ensure_service(config).await?;
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
    use std::process::Command;
    let state_dir = std::env::var("PERSONA_AGENT_STATE_DIR").ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join(".persona")
        });
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
    let status = Command::new("kill").arg(pid).status().unwrap_or_else(|_| std::process::ExitStatus::from_raw(0));
    if status.success() {
        println!("{} Stopped persona-ssh-agent (pid {})", "✓".green(), pid);
        // Cleanup sock/pid files
        let _ = std::fs::remove_file(pid_file);
        let sock_file = state_dir.join("ssh-agent.sock");
        let _ = std::fs::remove_file(sock_file);
    } else {
        println!("{}", "Failed to stop agent (kill)".red());
    }
    Ok(())
}
