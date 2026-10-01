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
        /// Key type (ed25519|rsa|ecdsa); rsa is 4096-bit, ecdsa is NIST P-256
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        /// Key comment (written into the key and the public key line)
        #[arg(short, long)]
        comment: Option<String>,
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
    /// Import an OpenSSH private key file (id_ed25519 / id_rsa / id_ecdsa,
    /// passphrase-protected keys are unlocked at import; the stored copy is
    /// sealed by the vault's per-item key)
    ImportFile {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Path to the OpenSSH private key file
        #[arg(short, long)]
        file: String,
        /// Key label (defaults to the file's comment, else the file name)
        #[arg(short, long)]
        name: Option<String>,
        /// Passphrase for encrypted keys (you will be prompted if omitted
        /// and the key needs one)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Print OpenSSH public key for a credential
    ExportPub {
        /// Credential UUID
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Stop persona-ssh-agent
    StopAgent,
    /// Sign a file with a vault SSH key (SSHSIG, `ssh-keygen -Y sign` wire
    /// format) — powers git commit signing via the `persona-ssh-sign` shim
    /// (see main.rs); can also be used directly
    GpgSign {
        /// Operation mode; only "sign" is supported
        #[arg(short = 'Y')]
        mode: String,
        /// Signature namespace (git uses "git"; binds the signature to one protocol)
        #[arg(short = 'n', default_value = "git")]
        namespace: String,
        /// Key spec: credential UUID, an "ssh-ed25519 <b64>" public key line,
        /// or a path to a file containing one. Defaults to the only vault key.
        #[arg(short = 'f')]
        key: Option<String>,
        /// File to sign
        file: String,
        /// Signature output path (defaults to <file>.sig, like ssh-keygen -Y sign)
        #[arg(short = 'o')]
        output: Option<String>,
    },
    /// Manage a vault public key in a host's authorized_keys. Runs the user's
    /// own `ssh` binary (same trust model as `ssh run`); the agent's host
    /// policy applies while the session is open
    Authorize {
        /// Identity owning the key
        #[arg(short, long)]
        identity: String,
        /// Target host (user@host allowed, passed to ssh)
        #[arg(long)]
        host: String,
        /// Credential UUID (optional when the identity holds exactly one SSH key)
        #[arg(long)]
        id: Option<Uuid>,
        /// Remove matching lines from authorized_keys instead of adding
        #[arg(long)]
        remove: bool,
        /// Print matching authorized_keys lines from the host
        #[arg(long, conflicts_with = "remove")]
        list: bool,
        /// Print the ssh invocation and remote script without running it
        #[arg(long)]
        dry_run: bool,
        /// Remote ssh port
        #[arg(long)]
        port: Option<u16>,
        /// Remote authorized_keys path (default: $HOME/.ssh/authorized_keys)
        #[arg(long)]
        remote_path: Option<String>,
    },
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
            comment,
            favorite,
        } => generate_key(&identity, name, &key_type, comment, favorite, config, ui).await,
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
        SshSubcommand::ImportFile {
            identity,
            file,
            name,
            passphrase,
        } => import_file(&identity, &file, name, passphrase, config, ui).await,
        SshSubcommand::ExportPub { id } => export_pubkey(id, config, ui).await,
        SshSubcommand::StopAgent => stop_agent(),
        SshSubcommand::Run { host, command } => run_with_host(&host, command, config).await,
        SshSubcommand::GpgSign {
            mode,
            namespace,
            key,
            file,
            output,
        } => gpg_sign(&mode, &namespace, key, &file, output, config, ui).await,
        SshSubcommand::Authorize {
            identity,
            host,
            id,
            remove,
            list,
            dry_run,
            port,
            remote_path,
        } => {
            authorize(
                &identity,
                &host,
                AuthorizeOptions {
                    id,
                    remove,
                    list,
                    dry_run,
                    port,
                    remote_path,
                },
                config,
                ui,
            )
            .await
        }
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
    comment: Option<String>,
    favorite: bool,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let key_type = key_type.to_lowercase();
    let comment = comment.unwrap_or_default();
    println!(
        "{}",
        format!("🔑 Generating {key_type} SSH keypair...")
            .cyan()
            .bold()
    );

    // 生成先行：未知类型在解锁 workspace 之前就报错。ed25519 走库内
    // 既有约定（BASE64 seed），rsa/ecdsa 走 ssh_generate（明文 PEM，
    // 封存由 per-item key 负责）——与导入通道的双格式约定一致。
    let (ssh_data, public_line, fingerprint) = if key_type == "ed25519" {
        use ed25519_dalek::SigningKey;
        use rand::Rng;

        let mut rng = rand::rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_bytes = signing_key.verifying_key().to_bytes(); // 32-byte public

        // Encode to OpenSSH public line: base64 of [len:"ssh-ed25519"][b"ssh-ed25519"][len:pub][pub]
        let openssh_pub = encode_ssh_ed25519_public(
            &pub_bytes,
            (!comment.is_empty()).then_some(comment.as_str()),
        );
        let fingerprint = ssh_key::PublicKey::from_openssh(&openssh_pub)
            .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
            .unwrap_or_default();
        let data = SshKeyData {
            private_key: BASE64.encode(signing_key.to_bytes()), // 32-byte seed
            public_key: openssh_pub.clone(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        };
        (data, openssh_pub, fingerprint)
    } else {
        let generated =
            persona_core::crypto::ssh_generate::generate_ssh_keypair(&key_type, &comment)?;
        let data = SshKeyData {
            private_key: generated.private_key_pem,
            public_key: generated.public_key.clone(),
            key_type: generated.key_type,
            passphrase: None,
        };
        (data, generated.public_key, generated.fingerprint)
    };

    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // 条目名回退与 import 通道一致：--name > comment > 既有兜底
    let name = label
        .or_else(|| (!comment.is_empty()).then(|| comment.clone()))
        .unwrap_or_else(|| format!("SSH Key ({})", identity.name));

    let mut cred = service
        .create_credential(
            identity.id,
            name.clone(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;

    println!("{} Created SSH key credential:", "✓".green().bold());
    println!("  Name: {}", name.cyan());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Type: {}", key_type.cyan());
    if !fingerprint.is_empty() {
        println!("  Fingerprint: {}", fingerprint.yellow());
    }
    println!("  Public: {}", public_line);
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

/// 等待 daemon 打出 SSH_AUTH_SOCK= 的上限。正常在 spawn 后毫秒级完成；
/// 超窗仍无 socket 行按「daemon 挂起」处理（kill + 报错），绝不让 CLI
/// 永久阻塞——无上限时 daemon 沉默（如 socket 绑定卡住）会拖死调用方。
const AGENT_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 以 `deadline` 为上限等待 future，超时折算成 `TimedOut` 的 io::Error。
async fn with_startup_deadline<T>(
    deadline: std::time::Duration,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "persona-ssh-agent did not report SSH_AUTH_SOCK in time",
        )),
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
    let sock_line = match with_startup_deadline(AGENT_STARTUP_TIMEOUT, async {
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
        Ok(sock_line)
    })
    .await
    {
        Ok(sock_line) => sock_line,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            // `Child::kill().await` reaps the child, and reaping a Windows
            // process that still has pending I/O never completes — awaiting it
            // here would trade the daemon's silence for a fresh permanent hang
            // in the CLI, i.e. exactly the failure the deadline exists to stop.
            // Signal without reaping (`start_kill` returns immediately) and let
            // the caller see the timeout; the agent's own pid file is what
            // `stop-agent` uses for cleanup.
            let _ = child.start_kill();
            anyhow::bail!(
                "persona-ssh-agent did not report SSH_AUTH_SOCK within {}s (is it stuck binding its socket?)",
                AGENT_STARTUP_TIMEOUT.as_secs()
            );
        }
        Err(err) => return Err(err.into()),
    };
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
    // Query the key count from the same agent the Socket line describes —
    // the state file's socket. SSH_AUTH_SOCK is only a fallback for when no
    // state file exists yet: in a desktop session it usually points at the
    // system ssh-agent, and key counts from that mixed two agents into one
    // status report.
    let query_target = if sock_file.exists() {
        std::fs::read_to_string(&sock_file)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        std::env::var("SSH_AUTH_SOCK").unwrap_or_default()
    };
    if !query_target.is_empty() {
        if let Ok(count) = query_agent_identities(&query_target).await {
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

/// 导入私钥文件（`persona ssh import-file --identity … --file ~/.ssh/id_ed25519`）。
/// 格式自动识别（OpenSSH 容器 / PKCS#8 / PKCS#1 / SEC1，见 core 的
/// ssh_import）；入库口径：私钥存解锁后的 OpenSSH PEM（per-item key
/// 封存在 vault 层），公钥行/类型/指纹解析自同一把钥。
async fn import_file(
    identity_name: &str,
    file_path: &str,
    label: Option<String>,
    passphrase: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    println!("{}", "🔑 Importing private key file...".cyan().bold());
    let pem = std::fs::read_to_string(file_path)
        .with_context(|| format!("Cannot read key file {file_path}"))?;

    // 先按给定口令解析；密钥受保护但没给口令时交互补问一次
    let imported = match persona_core::crypto::ssh_import::import_private_key_file(
        &pem,
        passphrase.as_deref(),
    ) {
        Ok(imported) => imported,
        Err(err) if err.to_string().contains("passphrase required") => {
            let pass = ui
                .password("Key passphrase", false, None)
                .context("Passphrase required to unlock this SSH key")?;
            persona_core::crypto::ssh_import::import_private_key_file(&pem, Some(&pass))?
        }
        Err(err) => return Err(err.into()),
    };

    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;

    // 条目名回退：--name > 钥匙 comment > 文件名 > 兜底
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string());
    let name = label
        .or_else(|| (!imported.comment.is_empty()).then(|| imported.comment.clone()))
        .or(file_name)
        .unwrap_or_else(|| "SSH Key (imported)".to_string());

    let ssh_data = SshKeyData {
        private_key: imported.private_key_pem.clone(),
        public_key: imported.public_key.clone(),
        key_type: imported.key_type.clone(),
        passphrase: None,
    };
    let cred = service
        .create_credential(
            identity.id,
            name,
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(ssh_data),
        )
        .await?;

    println!("{} Imported SSH key:", "✓".green().bold());
    println!("  Identity: {}", identity.name.cyan());
    println!("  Name: {}", cred.name.cyan());
    println!("  Type: {}", imported.key_type.cyan());
    println!("  Fingerprint: {}", imported.fingerprint.yellow());
    println!("  Public: {}", imported.public_key);
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

/// 从保险库收集全部可用作签名的 SSH key：(seed, 公钥行, 凭据 id, 身份 id)。
/// 解不开（已锁定/损坏）的凭据跳过——不能拿来签的东西不该中断签名流程，
/// 但如果全军覆没，resolve_signing_key 会以空列表报错。
async fn vault_ssh_keys(service: &PersonaService) -> Result<Vec<([u8; 32], String, Uuid, Uuid)>> {
    let mut keys = Vec::new();
    for identity in service.get_identities().await? {
        let creds = service.get_credentials_for_identity(&identity.id).await?;
        for cred in creds {
            if !matches!(cred.credential_type, CredentialType::SshKey) {
                continue;
            }
            let (seed, public_line) = match service.get_credential_data(&cred.id).await? {
                Some(CredentialData::SshKey(ssh)) => match decode_seed(&ssh) {
                    Ok(seed) => (seed, ssh.public_key),
                    Err(err) => {
                        eprintln!("{} Skipping SSH key {}: {}", "!".yellow(), cred.id, err);
                        continue;
                    }
                },
                _ => continue,
            };
            keys.push((seed, public_line, cred.id, identity.id));
        }
    }
    Ok(keys)
}

/// SshKeyData.private_key 是 base64 的 32 字节 ed25519 seed（与
/// agents/ssh-agent 同一约定）。
fn decode_seed(ssh: &SshKeyData) -> Result<[u8; 32]> {
    let raw = BASE64
        .decode(ssh.private_key.trim().as_bytes())
        .context("SSH key private material is not valid base64")?;
    if raw.len() != 32 {
        anyhow::bail!("SSH key seed must be 32 bytes, got {}", raw.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(seed)
}

/// authorized_keys 行里的 key blob（第二个空白分隔字段）。
fn public_key_blob(line: &str) -> Option<&str> {
    line.split_whitespace().nth(1)
}

/// 解析 `-f` keyspec 到可签名的 seed。四种形态：
/// `persona:ssh:<uuid>` / 裸凭据 UUID（git 的 user.signingkey 推荐）、
/// `ssh-ed25519 <b64>` 公钥行字面量、含公钥行的文件路径；
/// 缺省时要求保险库恰好有一把 SSH key。
async fn resolve_signing_key(
    service: &PersonaService,
    spec: Option<&str>,
) -> Result<([u8; 32], String, Uuid, Uuid)> {
    let mut keys = vault_ssh_keys(service).await?;
    if keys.is_empty() {
        anyhow::bail!("No SSH keys in the vault; run `persona ssh generate` first");
    }
    let spec = match spec {
        None => {
            return if keys.len() == 1 {
                Ok(keys.remove(0))
            } else {
                anyhow::bail!(
                    "{} SSH keys in the vault; pick one with -f <credential-id> \
                     (or set git's user.signingkey)",
                    keys.len()
                );
            };
        }
        Some(spec) => spec.trim(),
    };
    let uuid_text = spec.strip_prefix("persona:ssh:").unwrap_or(spec);
    if let Ok(id) = Uuid::parse_str(uuid_text) {
        return keys
            .into_iter()
            .find(|(_, _, cred_id, _)| *cred_id == id)
            .ok_or_else(|| anyhow::anyhow!("Credential {id} is not an SSH key in this vault"));
    }
    // 公钥行字面量或文件路径（git 允许 user.signingkey 是 .pub 文件）
    let line = match std::fs::read_to_string(spec) {
        Ok(text) => text,
        Err(_) => spec.to_string(),
    };
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("ssh-ed25519") => {}
        _ => anyhow::bail!(
            "Key spec is neither a credential UUID, nor a readable key file, \
             nor an ssh-ed25519 public key line"
        ),
    }
    let blob = tokens.next().context("Public key line has no key blob")?;
    keys.into_iter()
        .find(|(_, public_line, _, _)| public_key_blob(public_line) == Some(blob))
        .ok_or_else(|| {
            anyhow::anyhow!("No vault SSH key matches this public key; import or generate it first")
        })
}

/// `-Y sign`：读文件 → SSHSIG 签名 → 装甲写盘。输出与
/// `ssh-keygen -Y sign -n <namespace>` 逐字节兼容（ed25519 确定性签名），
/// 因此可以直接充当 git `gpg.format=ssh` 的签名器（persona-ssh-sign shim）。
async fn gpg_sign(
    mode: &str,
    namespace: &str,
    key: Option<String>,
    file: &str,
    output: Option<String>,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    if mode != "sign" {
        anyhow::bail!("Only `-Y sign` is supported (got -Y {})", mode);
    }
    let message = std::fs::read(file).with_context(|| format!("Cannot read {file}"))?;
    let service = ensure_service(config, ui).await?;
    let (seed, public_line, cred_id, identity_id) =
        resolve_signing_key(&service, key.as_deref()).await?;
    let blob = persona_core::crypto::sshsig::sign(&seed, namespace, &message);
    // 落盘前自验：签名数学上成立，且内嵌公钥就是选中的那把 vault key
    let embedded = persona_core::crypto::sshsig::verify(&blob, namespace, &message)
        .context("Just-created signature failed self-verification")?;
    if BASE64.encode(&embedded) != public_key_blob(&public_line).unwrap_or_default() {
        anyhow::bail!("Signature embeds an unexpected public key");
    }
    let out_path = output.unwrap_or_else(|| format!("{file}.sig"));
    std::fs::write(&out_path, persona_core::crypto::sshsig::armor(&blob))
        .with_context(|| format!("Cannot write {out_path}"))?;
    println!("{} Signed {} -> {}", "✓".green(), file, out_path);
    println!("  Key: {} ({})", public_line, cred_id);
    // 审计口径：与 agent 的 `ssh_sign` 同一动作名，via/namespace/摘要
    // 落 metadata（best-effort，不阻塞主流程）
    audit_ssh_event(
        &config.get_database_path(),
        "ssh_sign",
        Some(identity_id),
        Some(cred_id),
        &[
            ("via", "gpg-sign".to_string()),
            ("namespace", namespace.to_string()),
            (
                "data_sha256",
                persona_core::crypto::hashing::Sha256Hasher::hash_hex(&message),
            ),
            ("output", out_path),
        ],
    )
    .await;
    Ok(())
}

/// 审计事件（既有口径，与 agents/ssh-agent 相同）：独立短连接落
/// `audit_log` 行；失败只告警不阻塞主流程。
async fn audit_ssh_event(
    db_path: &Path,
    action: &str,
    identity_id: Option<Uuid>,
    credential_id: Option<Uuid>,
    metadata: &[(&str, String)],
) {
    let outcome = (async {
        use persona_core::models::{AuditAction, AuditLog, ResourceType};
        use persona_core::storage::AuditLogRepository;
        use persona_core::Repository;
        let db: persona_core::Database =
            Database::from_file::<std::path::PathBuf>(db_path.to_owned())
                .await
                .into_anyhow()?;
        db.migrate().await?;
        let repo = AuditLogRepository::new(db);
        let mut log = AuditLog::new(
            AuditAction::Custom(action.to_string()),
            ResourceType::Credential,
            true,
        )
        .with_identity_id(identity_id)
        .with_credential_id(credential_id);
        for (key, value) in metadata {
            log = log.with_metadata((*key).to_string(), value.clone());
        }
        repo.create(&log).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    if let Err(err) = outcome {
        eprintln!("{} audit log: {err}", "!".yellow());
    }
}

/// 供远端脚本/argv 组装用的 ssh 二进制（测试与非常规安装可覆盖）。
fn ssh_binary() -> String {
    std::env::var("PERSONA_SSH_BINARY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh".to_string())
}

/// POSIX sh 单引号转义（authorized_keys 内容只出现 base64 与算法名，
/// 但远端路径是调用方给的，一律按不可信处理）。
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// bare 公钥行（去注释/选项）：与写入远端 authorized_keys 的形态一致，
/// 也让 remove 的整行匹配只认我们的写法、不误删其他工具的行。
fn bare_public_line(line: &str) -> String {
    let mut tokens = line.split_whitespace();
    let algo = tokens.next().unwrap_or_default();
    let blob = tokens.next().unwrap_or_default();
    if algo.is_empty() || blob.is_empty() {
        line.trim().to_string()
    } else {
        format!("{algo} {blob}")
    }
}

/// 生成远端 `sh -c` 脚本（POSIX sh）。`path_expr` 已带引用：默认
/// `"$HOME/.ssh/authorized_keys"`（远端展开），自定义路径走单引号字面量。
/// - add：幂等（`grep -qxF` 去重后 `printf >>`，不覆盖已有行）；整行
///   单引号引用——公钥行内含空格，不引号会被 shell 拆词
/// - remove：只有第 2 字段（key blob）等于我们的行才会删——awk 重写到
///   `cat` 回原文件保 inode/权限，不误伤其他工具管理的行；blob 内嵌
///   awk 双引号程序体，只放行 base64 字符集
/// - list：原样 `cat` 远端文件（不含即空）
fn authorized_keys_plan(action: &str, path_expr: &str, key: &str) -> Result<String> {
    match action {
        "list" => Ok(format!("if test -f {path_expr}; then cat {path_expr}; fi")),
        "remove" => {
            if !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
            {
                anyhow::bail!(
                    "Unexpected characters in the key blob; refusing to build the remote script"
                );
            }
            Ok(format!(
                "if test -f {path_expr}; then awk '$2 != \"{key}\"' {path_expr} > \
                 {path_expr}.persona-tmp && cat {path_expr}.persona-tmp > {path_expr} && \
                 rm -f {path_expr}.persona-tmp; fi"
            ))
        }
        _ => {
            let quoted = sh_quote(key);
            Ok(format!(
                "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\" && touch {path_expr} && \
                 chmod 600 {path_expr} && if grep -qxF {quoted} {path_expr}; then :; else \
                 printf '%s\\n' {quoted} >> {path_expr}; fi"
            ))
        }
    }
}

/// 跑一次 ssh（captured stdout/stderr），期间挂 agent-target-host——
/// 与 `ssh run` 同一策略口径（known_hosts/确认/限速由 agent 的 host
/// 策略管）。会话结束无论成败都清 host 文件。
async fn ssh_capture(host: &str, program: &str, args: &[String]) -> Result<std::process::Output> {
    use tokio::process::Command;
    let state_dir = agent_state_dir();
    std::fs::create_dir_all(&state_dir).ok();
    let host_file = state_dir.join("agent-target-host");
    std::fs::write(&host_file, host).context("Failed to write agent target host")?;
    let outcome = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("Failed to run ssh");
    let _ = std::fs::remove_file(&host_file);
    outcome
}

/// authorized_keys 分发的参数集（避免 handler 摊成十几个位置参数）。
struct AuthorizeOptions {
    id: Option<Uuid>,
    remove: bool,
    list: bool,
    dry_run: bool,
    port: Option<u16>,
    remote_path: Option<String>,
}

/// authorized_keys 分发：密钥由 vault 出（私钥不出库），传输/认证交给
/// 用户自己的 `ssh` 二进制（与 `ssh run` 同一信任模型——本仓不做 SSH
/// 客户端协议实现，这是设计边界不是缺失）。
async fn authorize(
    identity_name: &str,
    host: &str,
    opts: AuthorizeOptions,
    config: &crate::config::CliConfig,
    ui: &dyn crate::utils::prompt::PromptUi,
) -> Result<()> {
    let service = ensure_service(config, ui).await?;
    let identity = resolve_identity(&service, identity_name).await?;
    let all = service.get_credentials_for_identity(&identity.id).await?;
    let mut keys: Vec<(String, Uuid)> = Vec::new();
    for cred in all {
        if !matches!(cred.credential_type, CredentialType::SshKey) {
            continue;
        }
        if let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&cred.id).await? {
            keys.push((ssh.public_key, cred.id));
        }
    }
    if keys.is_empty() {
        anyhow::bail!(
            "Identity '{}' has no SSH keys; run `persona ssh generate` first",
            identity.name
        );
    }
    let (public_line, cred_id) = match opts.id {
        Some(wanted) => keys
            .into_iter()
            .find(|(_, cred_id)| *cred_id == wanted)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Credential {wanted} is not an SSH key of identity '{}'",
                    identity.name
                )
            })?,
        None if keys.len() == 1 => keys.remove(0),
        None => anyhow::bail!(
            "{} SSH keys for identity '{}'; pick one with --id",
            keys.len(),
            identity.name
        ),
    };
    let line = bare_public_line(&public_line);
    let blob = match line.split_whitespace().nth(1) {
        Some(blob) if line.split_whitespace().count() == 2 => blob,
        _ => anyhow::bail!("Vault key {} has an unexpected public key format", cred_id),
    };
    let path_expr = match opts.remote_path.as_deref() {
        Some(path) => sh_quote(path),
        None => "\"$HOME/.ssh/authorized_keys\"".to_string(),
    };
    let action = if opts.list {
        "list"
    } else if opts.remove {
        "remove"
    } else {
        "add"
    };
    // remove 的匹配键是 blob（第 2 字段），add/list 用整行
    let key = if action == "remove" {
        blob
    } else {
        line.as_str()
    };
    let script = authorized_keys_plan(action, &path_expr, key)?;

    let mut argv = vec![ssh_binary()];
    if let Some(port) = opts.port {
        argv.push("-p".to_string());
        argv.push(port.to_string());
    }
    argv.push(host.to_string());
    argv.push(script);
    if opts.dry_run {
        let display: Vec<String> = argv
            .iter()
            .map(|piece| {
                if piece.chars().any(char::is_whitespace) {
                    format!("{piece:?}")
                } else {
                    piece.clone()
                }
            })
            .collect();
        println!("{}", display.join(" "));
        return Ok(());
    }

    let output = ssh_capture(host, &argv[0], &argv[1..]).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ssh exited with {}: {}",
            output
                .status
                .code()
                .map(|c| format!("status {c}"))
                .unwrap_or_else(|| "failure".to_string()),
            stderr.trim()
        );
    }
    if action == "list" {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            println!(
                "{} No matching authorized_keys lines on {}.",
                "none".yellow(),
                host
            );
        } else {
            print!("{stdout}");
        }
    } else {
        println!(
            "{} {} → {} (credential {})",
            "✓".green(),
            action,
            host,
            cred_id
        );
    }
    // 审计口径：动作 + 目标主机 + 凭据/身份（best-effort）
    audit_ssh_event(
        &config.get_database_path(),
        "ssh_authorize",
        Some(identity.id),
        Some(cred_id),
        &[
            ("host", host.to_string()),
            ("action", action.to_string()),
            ("ok", output.status.success().to_string()),
        ],
    )
    .await;
    Ok(())
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

    /// `decode_seed` 的两个守卫分支：非法 base64、种子长度不是 32 字节。
    #[test]
    fn decode_seed_rejects_non_base64_and_wrong_length() {
        let key = |private_key: String| SshKeyData {
            private_key,
            public_key: String::new(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        };

        let err = decode_seed(&key("!!! not base64 !!!".to_string())).unwrap_err();
        assert!(
            err.to_string()
                .contains("private material is not valid base64"),
            "{err}"
        );

        let err = decode_seed(&key(BASE64.encode(b"too short"))).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes, got 9"), "{err}");
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

        // Unknown key types are refused before anything is unlocked
        // (rsa/ecdsa 生成已支持，dsa 之类仍是快失败).
        let ui = ScriptedUi::new();
        let err = execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: None,
                key_type: "dsa".to_string(),
                comment: None,
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("dsa must be refused");
        assert!(err.to_string().contains("Unsupported SSH key type: dsa"));
        assert!(ui.exhausted());

        // Generating with an explicit label and favorite flag.
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                name: Some("work-key".to_string()),
                key_type: "ed25519".to_string(),
                comment: None,
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
                comment: None,
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
                comment: None,
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
                comment: None,
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
    // import-file: OpenSSH 私钥文件导入（seed 导入之外的文件通道）
    // ------------------------------------------------------------------

    fn write_key_file(dir: &TempDir, name: &str, pem: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).unwrap();
        path
    }

    fn openssh_pem(algorithm: ssh_key::Algorithm) -> (String, String) {
        let key = ssh_key::private::PrivateKey::random(&mut rand_core::OsRng, algorithm).unwrap();
        (
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            key.public_key().to_openssh().unwrap(),
        )
    }

    #[tokio::test]
    async fn import_file_plain_and_stored_shape() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        let (pem, pub_line) = openssh_pem(ssh_key::Algorithm::Rsa { hash: None });
        let key_path = write_key_file(&dir, "id_rsa", &pem);

        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: key_path.to_string_lossy().to_string(),
                name: Some("rsa-import".to_string()),
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("plain rsa file import works");
        assert!(ui.exhausted());

        // 库内形状：私钥 = 解锁后的 PEM（可再解析、非密文），类型/公钥一致
        let creds = alice_credentials(&config, "master-pin").await;
        let ssh_id = creds
            .iter()
            .find(|(_, t)| matches!(t, CredentialType::SshKey))
            .expect("ssh credential present")
            .0;
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.authenticate_user("master-pin").await.unwrap();
        let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&ssh_id).await.unwrap()
        else {
            panic!("ssh key data readable");
        };
        assert_eq!(ssh.key_type, "rsa");
        assert_eq!(ssh.public_key, pub_line);
        assert!(ssh
            .private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let reparsed = ssh_key::private::PrivateKey::from_openssh(&ssh.private_key).unwrap();
        assert!(!reparsed.key_data().is_encrypted());

        // 名字回退：comment 非空且无 --name 时用 comment；这里给了 --name
        // 走 label——再导一把不带 --name 的 ed25519 验证 comment/file 回退。
        // （这把的公钥行在 set_comment 之后才取，解构出的第一个直接丢弃）
        let (pem, _) = openssh_pem(ssh_key::Algorithm::Ed25519);
        let mut key = ssh_key::private::PrivateKey::from_openssh(&pem).unwrap();
        key.set_comment("cui@laptop");
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
        let pub_line = key.public_key().to_openssh().unwrap();
        let key_path = write_key_file(&dir, "id_ed25519_test", &pem);

        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: key_path.to_string_lossy().to_string(),
                name: None,
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("comment fallback works");
        let creds = alice_credentials(&config, "master-pin").await;
        assert_eq!(
            creds
                .iter()
                .filter(|(_, t)| matches!(t, CredentialType::SshKey))
                .count(),
            2
        );
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.authenticate_user("master-pin").await.unwrap();
        let identity = service
            .get_identity_by_name("alice")
            .await
            .unwrap()
            .unwrap();
        let named = service
            .get_credentials_for_identity(&identity.id)
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.name == "cui@laptop")
            .expect("entry named after the key comment");
        let Some(CredentialData::SshKey(ssh)) =
            service.get_credential_data(&named.id).await.unwrap()
        else {
            panic!("ssh key data readable");
        };
        assert_eq!(ssh.public_key, pub_line);
        assert_eq!(ssh.key_type, "ed25519");
    }

    #[tokio::test]
    async fn import_file_encrypted_passphrase_paths() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        let key = ssh_key::private::PrivateKey::random(
            &mut rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        // encrypt 返回新的加密实例（不改动原值），必须接住再序列化
        let key = key.encrypt(&mut rand_core::OsRng, "hunter2").unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
        let key_path = write_key_file(&dir, "id_encrypted", &pem);
        let file = key_path.to_string_lossy().to_string();

        // 受保护但没给 --passphrase → ScriptedUi 补问口令后解锁成功
        let ui = ScriptedUi::new().password("hunter2").password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: file.clone(),
                name: None,
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("interactive passphrase unlock works");
        assert!(ui.exhausted());

        // --passphrase 直给也通
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: file.clone(),
                name: None,
                passphrase: Some("hunter2".to_string()),
            }),
            &config,
            &ui,
        )
        .await
        .expect("flagged passphrase unlock works");

        // 错误口令 → 明确报错（不静默吞）
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file,
                name: None,
                passphrase: Some("wrong".to_string()),
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("wrong passphrase must fail");
        assert!(err.to_string().contains("incorrect"), "{err}");
    }

    #[tokio::test]
    async fn import_file_rejects_garbage_and_missing_files() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        // 不存在的文件
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: dir.path().join("nope").to_string_lossy().to_string(),
                name: None,
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("missing file must fail");
        assert!(err.to_string().contains("Cannot read key file"));

        // 垃圾内容 / 公钥行当私钥 → 解析层拒绝
        let garbage = write_key_file(&dir, "garbage", "not a key at all");
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: garbage.to_string_lossy().to_string(),
                name: None,
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("garbage file must fail");
        assert!(
            err.to_string().contains("Unrecognized private key file format"),
            "{err}"
        );

        let (_, pub_line) = openssh_pem(ssh_key::Algorithm::Ed25519);
        let pub_file = write_key_file(&dir, "id_ed25519.pub", &pub_line);
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::ImportFile {
                identity: "alice".to_string(),
                file: pub_file.to_string_lossy().to_string(),
                name: None,
                passphrase: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("public key file must fail");
        assert!(
            err.to_string().contains("Unrecognized private key file format"),
            "{err}"
        );
    }

    // ------------------------------------------------------------------
    // generate: 页面内/CLI 生成新密钥对（rsa 走 core 测试，这里不跑 4096 位）
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn generate_stores_keypair_and_applies_name_fallback() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        // 一把带 comment 不带 --name：条目名回退 comment
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                key_type: "ed25519".to_string(),
                comment: Some("gen-test".to_string()),
                name: None,
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect("ed25519 generate works");

        let creds = alice_credentials(&config, "master-pin").await;
        let (ssh_id, _) = creds
            .iter()
            .find(|(_, t)| matches!(t, CredentialType::SshKey))
            .expect("generated ssh credential present")
            .clone();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.authenticate_user("master-pin").await.unwrap();
        let cred = service.get_credential(&ssh_id).await.unwrap().unwrap();
        assert_eq!(cred.name, "gen-test", "名字回退 comment");

        let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&ssh_id).await.unwrap()
        else {
            panic!("ssh key data readable");
        };
        assert_eq!(ssh.key_type, "ed25519");
        assert_eq!(ssh.passphrase, None);
        // ed25519 生成走库内既有约定：BASE64 seed（非 PEM；agent 双格式加载
        // seed 优先），公钥行以重建 verifying key 为独立裁判
        let seed = BASE64.decode(&ssh.private_key).unwrap();
        assert_eq!(seed.len(), 32, "ed25519 私钥 = 32B seed");
        use ed25519_dalek::SigningKey;
        let seed_bytes: [u8; 32] = seed.as_slice().try_into().unwrap();
        let expected_pub = SigningKey::from_bytes(&seed_bytes).verifying_key();
        let parsed_pub = ssh_key::PublicKey::from_openssh(&ssh.public_key).unwrap();
        assert_eq!(
            parsed_pub.key_data().ed25519().unwrap().0,
            *expected_pub.as_bytes(),
            "公钥行与 seed 重建的公钥一致"
        );
        assert!(ssh.public_key.ends_with("gen-test"), "comment 进公钥行");

        // 二把带 --name + ecdsa：label 优先
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                key_type: "ecdsa".to_string(),
                comment: Some("ignored-comment".to_string()),
                name: Some("my-ecdsa".to_string()),
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect("ecdsa generate works");
        let creds = alice_credentials(&config, "master-pin").await;
        let ecdsa_id = creds
            .iter()
            .find(|(id, _)| *id != ssh_id)
            .map(|(id, _)| *id)
            .expect("second credential present");
        let cred = service.get_credential(&ecdsa_id).await.unwrap().unwrap();
        assert_eq!(cred.name, "my-ecdsa", "--name 优先于 comment");
    }

    #[tokio::test]
    async fn generate_rejects_unknown_key_type() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Generate {
                identity: "alice".to_string(),
                key_type: "dsa".to_string(),
                comment: None,
                name: None,
                favorite: false,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("unknown type must fail");
        assert!(
            err.to_string().contains("Unsupported SSH key type: dsa"),
            "{err}"
        );
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

        // A reachable agent answers the identity query — via the state file's
        // socket even while SSH_AUTH_SOCK points elsewhere (e.g. the system
        // agent): one status report must describe one agent.
        let listener = UnixListener::bind(dir.path().join("query.sock")).unwrap();
        let server = tokio::spawn(serve_one_identity_query(listener, 3));
        let stray_listener = UnixListener::bind(dir.path().join("stray.sock")).unwrap();
        let _env_sock = EnvVarGuard::set(
            "SSH_AUTH_SOCK",
            dir.path().join("stray.sock").to_string_lossy().to_string(),
        );
        std::fs::write(
            dir.path().join("ssh-agent.sock"),
            dir.path().join("query.sock").to_string_lossy().to_string(),
        )
        .unwrap();
        agent_status(&config)
            .await
            .expect("status with a live agent works");
        server.await.unwrap();
        // The env-pointed agent was never consulted.
        let stray_hit = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            stray_listener.accept(),
        )
        .await;
        assert!(
            stray_hit.is_err(),
            "SSH_AUTH_SOCK must not be queried while a state file exists"
        );
        drop(stray_listener);

        // With no state file, the SSH_AUTH_SOCK socket is the fallback source.
        std::fs::remove_file(dir.path().join("ssh-agent.sock")).unwrap();
        let fallback_listener = UnixListener::bind(dir.path().join("fallback.sock")).unwrap();
        let _env_sock_fallback = EnvVarGuard::set(
            "SSH_AUTH_SOCK",
            dir.path()
                .join("fallback.sock")
                .to_string_lossy()
                .to_string(),
        );
        let fallback_server = tokio::spawn(serve_one_identity_query(fallback_listener, 1));
        agent_status(&config)
            .await
            .expect("status falls back to the env socket");
        fallback_server.await.unwrap();
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

    #[test]
    fn find_agent_binary_near_walks_exe_dir_then_deps_then_parent() {
        // The candidate order is the whole point of PATH-independent
        // resolution: cargo drops the agent beside the persona binary, `deps`
        // covers alternate layouts, and the parent covers target-rooted
        // installs. Pure filesystem walk — no process, no daemon — so every
        // platform (Windows included) covers the fallback order.
        let root = TempDir::new().unwrap();
        let exe_dir = root.path().join("debug");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let exe = exe_dir.join("persona");
        let parent_planted = root.path().join("agent");

        // Nothing planted anywhere: no hit rather than a wrong guess.
        assert!(find_agent_binary_near(&exe, "agent").is_none());

        // Parent dir alone.
        std::fs::write(&parent_planted, b"").unwrap();
        assert_eq!(
            find_agent_binary_near(&exe, "agent"),
            Some(parent_planted.clone())
        );
        std::fs::remove_file(&parent_planted).unwrap();

        // `deps` outranks the parent dir.
        let deps_planted = exe_dir.join("deps").join("agent");
        std::fs::create_dir_all(exe_dir.join("deps")).unwrap();
        std::fs::write(&deps_planted, b"").unwrap();
        std::fs::write(&parent_planted, b"").unwrap();
        assert_eq!(
            find_agent_binary_near(&exe, "agent"),
            Some(deps_planted.clone())
        );

        // And the exe dir outranks `deps` — the layout cargo actually produces.
        let exe_planted = exe_dir.join("agent");
        std::fs::write(&exe_planted, b"").unwrap();
        assert_eq!(find_agent_binary_near(&exe, "agent"), Some(exe_planted));
    }

    #[tokio::test]
    async fn startup_deadline_converts_silence_to_timeout_error() {
        // A daemon that stays silent must surface as a TimedOut error once
        // the deadline lapses, not hang the caller forever.
        let err = with_startup_deadline(
            std::time::Duration::from_millis(50),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .expect_err("a silent agent must surface as a timeout");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn startup_deadline_passes_through_completed_result() {
        let value = with_startup_deadline(std::time::Duration::from_secs(30), async { Ok(7) })
            .await
            .expect("completed futures pass through untouched");
        assert_eq!(value, 7);
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
                comment: None,
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

    // ------------------------------------------------------------------
    // gpg-sign: SSHSIG signing for git commits.
    // ------------------------------------------------------------------

    /// 真 ssh-keygen 参照向量（与 core/src/crypto/sshsig.rs 同一份：ed25519
    /// 确定性签名 ⇒ 我们输出正确 ⇔ 与 `ssh-keygen -Y sign` 逐字节一致）。
    const REF_SEED: [u8; 32] = [
        0x59, 0xd9, 0x98, 0xd6, 0xdb, 0x19, 0xcc, 0x8f, 0x7f, 0xe2, 0x45, 0xfa, 0x8a, 0x04, 0xe6,
        0x10, 0xd8, 0x84, 0x5d, 0xff, 0x80, 0xdb, 0xec, 0x8d, 0xfc, 0x88, 0x15, 0xe1, 0x8e, 0xa0,
        0x83, 0x8d,
    ];
    const REF_PUBLIC_LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaLEB5wGG3c9s7atvxL3FnUPZ+Gwqp/YOsLfQqzJeNg";
    const REF_MESSAGE: &[u8] = b"hello persona\nsecond line\n";
    const REF_ARMOR: &str = concat!(
        "-----BEGIN SSH SIGNATURE-----\n",
        "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJosQHnAYbdz2ztq2/EvcWdQ9n4\n",
        "bCqn9g6wt9CrMl42AAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\n",
        "AAAAQJt/PJ1nuI6ToAzsanR3MLYqM2qiVC5IWESIGbXh6o4hiHoB8ng7N1/2nUDiqAq55b\n",
        "nM36bAlsZrid+A5TX5agU=\n",
        "-----END SSH SIGNATURE-----\n",
    );

    /// 把参照 seed 导入 alice 名下，返回新凭据 id。
    async fn import_reference_key(config: &CliConfig, identity: &str) -> Uuid {
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Import {
                identity: identity.to_string(),
                name: Some("signing-key".to_string()),
                seed_base64: Some(BASE64.encode(REF_SEED)),
                seed_hex: None,
            }),
            config,
            &ui,
        )
        .await
        .expect("reference seed imports");
        alice_credentials(config, "master-pin")
            .await
            .into_iter()
            .find(|(_, t)| matches!(t, CredentialType::SshKey))
            .map(|(id, _)| id)
            .expect("imported ssh key is in the vault")
    }

    async fn gpg_sign_via_dispatch(
        config: &CliConfig,
        key: Option<String>,
        file: &std::path::Path,
        output: Option<String>,
    ) -> anyhow::Result<()> {
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::GpgSign {
                mode: "sign".to_string(),
                namespace: "git".to_string(),
                key,
                file: file.to_string_lossy().into_owned(),
                output,
            }),
            config,
            &ui,
        )
        .await
    }

    #[tokio::test]
    async fn gpg_sign_output_is_byte_identical_to_ssh_keygen() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        let msg = dir.path().join("commit-msg");
        std::fs::write(&msg, REF_MESSAGE).unwrap();

        // 默认 -f（保险库唯一 key）+ 默认输出 <file>.sig —— 与 git 调用形状一致
        let cred = import_reference_key(&config, "alice").await;
        gpg_sign_via_dispatch(&config, None, &msg, None)
            .await
            .expect("signing with the only vault key works");
        let sig = std::fs::read(dir.path().join("commit-msg.sig")).unwrap();
        assert_eq!(
            String::from_utf8(sig).unwrap(),
            REF_ARMOR,
            "must match ssh-keygen -Y sign byte-for-byte"
        );

        // keyspec = 凭据 UUID → 同样逐字节
        gpg_sign_via_dispatch(
            &config,
            Some(cred.to_string()),
            &msg,
            Some(
                dir.path()
                    .join("by-uuid.sig")
                    .to_string_lossy()
                    .into_owned(),
            ),
        )
        .await
        .expect("signing by credential uuid works");

        // keyspec = 公钥行字面量 / .pub 文件路径
        let pub_file = dir.path().join("ref.pub");
        std::fs::write(&pub_file, format!("{REF_PUBLIC_LINE} comment\n")).unwrap();
        for spec in [
            REF_PUBLIC_LINE.to_string(),
            format!("persona:ssh:{cred}"),
            pub_file.to_string_lossy().into_owned(),
        ] {
            gpg_sign_via_dispatch(
                &config,
                Some(spec),
                &msg,
                Some(
                    dir.path()
                        .join("by-line.sig")
                        .to_string_lossy()
                        .into_owned(),
                ),
            )
            .await
            .expect("keyspec resolves to the reference key");
        }
        // 非默认 namespace 的产物应当能被 core 的 verify 验过
        let ns_msg = dir.path().join("ns-file");
        std::fs::write(&ns_msg, b"payload").unwrap();
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::GpgSign {
                mode: "sign".to_string(),
                namespace: "file".to_string(),
                key: Some(cred.to_string()),
                file: ns_msg.to_string_lossy().into_owned(),
                output: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("non-git namespace signs");
        let blob = persona_core::crypto::sshsig::disarmor(
            &std::fs::read_to_string(dir.path().join("ns-file.sig")).unwrap(),
        )
        .unwrap();
        persona_core::crypto::sshsig::verify(&blob, "file", b"payload")
            .expect("namespace-bound signature verifies");
    }

    #[tokio::test]
    async fn gpg_sign_rejects_bad_mode_keyspec_and_inputs() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;
        import_reference_key(&config, "alice").await;
        let msg = dir.path().join("commit-msg");
        std::fs::write(&msg, REF_MESSAGE).unwrap();

        // -Y 只支持 sign（git 不会传别的，但保持与 ssh-keygen 的差异明确）
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::GpgSign {
                mode: "verify".to_string(),
                namespace: "git".to_string(),
                key: None,
                file: msg.to_string_lossy().into_owned(),
                output: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("non-sign mode must fail");
        assert!(err.to_string().contains("Only `-Y sign`"));

        // 待签文件不存在
        let err = gpg_sign_via_dispatch(&config, None, &dir.path().join("missing"), None)
            .await
            .expect_err("missing file must fail");
        assert!(err.to_string().contains("Cannot read"));

        // 保险库里有两把 key 且未给 -f
        import_reference_key(&config, "bob").await;
        let err = gpg_sign_via_dispatch(&config, None, &msg, None)
            .await
            .expect_err("ambiguous vault must fail");
        assert!(err.to_string().contains("pick one with -f"), "{err}");

        // 未知的凭据 UUID
        let err = gpg_sign_via_dispatch(&config, Some(Uuid::new_v4().to_string()), &msg, None)
            .await
            .expect_err("unknown uuid must fail");
        assert!(err.to_string().contains("not an SSH key"), "{err}");

        // 非 ssh-ed25519 的公钥行
        let err = gpg_sign_via_dispatch(
            &config,
            Some("ssh-rsa AAAAB3NzaC1yc2E".to_string()),
            &msg,
            None,
        )
        .await
        .expect_err("rsa keyspec must fail");
        assert!(err
            .to_string()
            .contains("neither a credential UUID, nor a readable key file"));

        // 匹配不到任何 vault key 的 ed25519 公钥行
        let err = gpg_sign_via_dispatch(
            &config,
            Some(format!("ssh-ed25519 {}", BASE64.encode([3u8; 51]))),
            &msg,
            None,
        )
        .await
        .expect_err("foreign key must fail");
        assert!(
            err.to_string().contains("No vault SSH key matches"),
            "{err}"
        );

        // 空保险库（所有 identity 的 key 全删）且未给 -f
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.authenticate_user("master-pin").await.unwrap();
        for identity in service.get_identities().await.unwrap() {
            for cred in service
                .get_credentials_for_identity(&identity.id)
                .await
                .unwrap()
            {
                if matches!(cred.credential_type, CredentialType::SshKey) {
                    service.delete_credential(&cred.id).await.unwrap();
                }
            }
        }
        let err = gpg_sign_via_dispatch(&config, None, &msg, None)
            .await
            .expect_err("empty vault must fail");
        assert!(
            err.to_string().contains("No SSH keys in the vault"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn gpg_sign_writes_an_ssh_sign_audit_row() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;
        let cred = import_reference_key(&config, "alice").await;
        let msg = dir.path().join("commit-msg");
        std::fs::write(&msg, REF_MESSAGE).unwrap();

        gpg_sign_via_dispatch(&config, Some(cred.to_string()), &msg, None)
            .await
            .expect("signing works");

        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = persona_core::storage::AuditLogRepository::new(db);
        // 审计是 inline await 的，直接查即可
        let rows = repo
            .find_by_action(&persona_core::models::AuditAction::Custom(
                "ssh_sign".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "one ssh_sign row expected");
        let row = &rows[0];
        assert_eq!(row.credential_id, Some(cred));
        assert_eq!(
            row.metadata.get("via").map(String::as_str),
            Some("gpg-sign")
        );
        assert_eq!(
            row.metadata.get("namespace").map(String::as_str),
            Some("git")
        );
        assert_eq!(
            row.metadata.get("data_sha256").map(String::as_str),
            Some(persona_core::crypto::hashing::Sha256Hasher::hash_hex(REF_MESSAGE).as_str())
        );
    }

    #[test]
    fn authorize_plan_builders_bare_lines_and_quoting() {
        let path = "\"$HOME/.ssh/authorized_keys\"";
        let line = "ssh-ed25519 AAAA";
        let add = authorized_keys_plan("add", path, line).unwrap();
        assert!(add.contains("mkdir -p \"$HOME/.ssh\""));
        assert!(add.contains("chmod 700 \"$HOME/.ssh\""));
        assert!(add.contains("chmod 600 \"$HOME/.ssh/authorized_keys\""));
        assert!(
            add.contains("if grep -qxF 'ssh-ed25519 AAAA'"),
            "idempotent add via grep -qxF: {add}"
        );
        assert!(add.contains("printf '%s\\n' 'ssh-ed25519 AAAA' >>"));

        let remove = authorized_keys_plan("remove", path, "BBBB").unwrap();
        assert!(remove.contains("awk '$2 != \"BBBB\"'"));
        assert!(remove.contains(".persona-tmp"), "tmp rewrite, not mv");

        // blob 会内嵌 awk 双引号程序体——非 base64 字符集必须拒绝
        assert!(authorized_keys_plan("remove", path, "BB;BB").is_err());

        let list = authorized_keys_plan("list", path, "BBBB").unwrap();
        assert!(list.contains("cat \"$HOME/.ssh/authorized_keys\""));
        assert!(list.contains("test -f"));

        // 自定义路径按不可信内容单引号转义
        let custom = sh_quote("/srv/keys/a b'c");
        assert_eq!(custom, "'/srv/keys/a b'\\''c'");
        let add_custom = authorized_keys_plan("add", &custom, line).unwrap();
        assert!(add_custom.contains("touch '/srv/keys/a b'\\''c'"));

        // bare 行：去注释/选项，只留 algo + blob；畸形输入原样兜底
        assert_eq!(
            bare_public_line("ssh-ed25519 AAAA some comment"),
            "ssh-ed25519 AAAA"
        );
        assert_eq!(bare_public_line("ssh-ed25519 AAAA"), "ssh-ed25519 AAAA");
        assert_eq!(bare_public_line("garbage"), "garbage");
    }

    /// 假 ssh：把「最后一个参数」（远端脚本）放到沙箱 HOME 里执行——测试
    /// 跑的就是 `authorized_keys_plan` 生成的脚本本身。
    #[cfg(unix)]
    fn plant_fake_ssh(dir: &TempDir, home: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let stub = dir.path().join("fake-ssh");
        let script = format!(
            "#!/bin/sh\nfor last in \"$@\"; do :; done\nHOME='{}' exec sh -c \"$last\"\n",
            home.display()
        );
        std::fs::write(&stub, &script).unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        stub
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authorize_round_trip_through_fake_ssh() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;
        let cred = import_reference_key(&config, "alice").await;
        let remote_home = TempDir::new().unwrap();
        let stub = plant_fake_ssh(&dir, remote_home.path());
        let _state = sandbox_agent_state_dir(&dir);
        let _ssh = EnvVarGuard::set("PERSONA_SSH_BINARY", &stub);

        async fn run_authorize(
            config: &CliConfig,
            ui: &ScriptedUi,
            remove: bool,
            list: bool,
            dry_run: bool,
            id: Option<Uuid>,
        ) -> anyhow::Result<()> {
            execute_with(
                ssh_args(SshSubcommand::Authorize {
                    identity: "alice".to_string(),
                    host: "server.example".to_string(),
                    id,
                    remove,
                    list,
                    dry_run,
                    port: None,
                    remote_path: None,
                }),
                config,
                ui,
            )
            .await
        }

        let akey = remote_home.path().join(".ssh/authorized_keys");

        // add → 行写入且与参照公钥完全一致（整形换行）
        let ui = ScriptedUi::new().password("master-pin");
        run_authorize(&config, &ui, false, false, false, None)
            .await
            .expect("add works");
        assert_eq!(
            std::fs::read_to_string(&akey).unwrap().trim(),
            REF_PUBLIC_LINE
        );

        // 幂等：再 add 一次仍是同一行、没有重复
        let ui = ScriptedUi::new().password("master-pin");
        run_authorize(&config, &ui, false, false, false, None)
            .await
            .expect("re-add works");
        assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

        // list 只读不写
        let ui = ScriptedUi::new().password("master-pin");
        run_authorize(&config, &ui, false, true, false, None)
            .await
            .expect("list works");
        assert_eq!(std::fs::read_to_string(&akey).unwrap().lines().count(), 1);

        // remove → 行被删；再 remove 幂等（test -f + awk 空重写）
        let ui = ScriptedUi::new().password("master-pin");
        run_authorize(&config, &ui, true, false, false, Some(cred))
            .await
            .expect("remove works");
        assert!(std::fs::read_to_string(&akey).unwrap().trim().is_empty());
        let ui = ScriptedUi::new().password("master-pin");
        run_authorize(&config, &ui, true, false, false, None)
            .await
            .expect("re-remove works");

        // 审计行（handler 内 inline await，无需轮询）
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = persona_core::storage::AuditLogRepository::new(db);
        let rows = repo
            .find_by_action(&persona_core::models::AuditAction::Custom(
                "ssh_authorize".to_string(),
            ))
            .await
            .unwrap();
        // add ×2 + list + remove ×2 共 5 行
        assert!(
            rows.len() >= 5,
            "every authorize action audited: {}",
            rows.len()
        );
        for row in &rows {
            assert_eq!(row.credential_id, Some(cred));
            assert_eq!(
                row.metadata.get("host").map(String::as_str),
                Some("server.example")
            );
        }
    }

    #[tokio::test]
    async fn authorize_rejections_and_dry_run() {
        let _env = lock_process_env();
        let _pw = EnvVarGuard::remove("PERSONA_MASTER_PASSWORD");

        let dir = TempDir::new().unwrap();
        let config = unlocked_workspace(&dir, "master-pin").await;

        async fn run_authorize(
            config: &CliConfig,
            ui: &ScriptedUi,
            identity: &str,
            id: Option<Uuid>,
        ) -> anyhow::Result<()> {
            execute_with(
                ssh_args(SshSubcommand::Authorize {
                    identity: identity.to_string(),
                    host: "server.example".to_string(),
                    id,
                    remove: false,
                    list: false,
                    dry_run: false,
                    port: None,
                    remote_path: None,
                }),
                config,
                ui,
            )
            .await
        }

        // 身份名下没有任何 SSH key
        let ui = ScriptedUi::new().password("master-pin");
        let err = run_authorize(&config, &ui, "bob", None)
            .await
            .expect_err("keyless identity must fail");
        assert!(err.to_string().contains("has no SSH keys"), "{err}");

        // 两把 key 且未给 --id
        let key_a = import_reference_key(&config, "alice").await;
        import_reference_key(&config, "alice").await;
        let ui = ScriptedUi::new().password("master-pin");
        let err = run_authorize(&config, &ui, "alice", None)
            .await
            .expect_err("ambiguous identity must fail");
        assert!(err.to_string().contains("pick one with --id"), "{err}");

        // 未知 --id
        let ui = ScriptedUi::new().password("master-pin");
        let err = run_authorize(&config, &ui, "alice", Some(Uuid::new_v4()))
            .await
            .expect_err("unknown id must fail");
        assert!(
            err.to_string().contains("is not an SSH key of identity"),
            "{err}"
        );

        // dry-run：ssh 二进制指向不存在也不报错（不 spawn），真实跑才报
        let _ssh = EnvVarGuard::set("PERSONA_SSH_BINARY", dir.path().join("no-such-ssh"));
        let ui = ScriptedUi::new().password("master-pin");
        execute_with(
            ssh_args(SshSubcommand::Authorize {
                identity: "alice".to_string(),
                host: "server.example".to_string(),
                id: Some(key_a),
                remove: false,
                list: false,
                dry_run: true,
                port: None,
                remote_path: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect("dry-run must not spawn");
        let ui = ScriptedUi::new().password("master-pin");
        let err = execute_with(
            ssh_args(SshSubcommand::Authorize {
                identity: "alice".to_string(),
                host: "server.example".to_string(),
                id: Some(key_a),
                remove: false,
                list: false,
                dry_run: false,
                port: None,
                remote_path: None,
            }),
            &config,
            &ui,
        )
        .await
        .expect_err("missing ssh binary must fail");
        assert!(err.to_string().contains("Failed to run ssh"), "{err}");
    }
}
