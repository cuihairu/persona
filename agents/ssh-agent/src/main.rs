//! Persona SSH Agent daemon
//! - Cross-platform agent (UNIX sockets on Unix, Named Pipes on Windows)
//! - Implements SSH Agent protocol subset:
//!   - request_identities
//!   - sign_request (ed25519)
//! - Loads SSH keys (ed25519) from Persona vault (CredentialType::SshKey)
//! - Unlocks using master password from env PERSONA_MASTER_PASSWORD (if required)
//! - Advanced policy enforcement: per-host, per-key, time-based restrictions
//!
//! NOTE: This is an early MVP; enhanced policies/approvals in progress.

mod policy;
mod transport;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use persona_core::{
    BiometricPlatform, BiometricPrompt, BiometricProvider, RedactedLoggerBuilder, Repository,
};
use policy::{PolicyEnforcer, SignatureDecision};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, Level};
use transport::{default_agent_path, AgentListener, AgentStream};

#[tokio::main]
async fn main() -> Result<()> {
    RedactedLoggerBuilder::new(Level::INFO)
        .include_target(false)
        .init()?;

    let socket_path = default_agent_path();
    let db_path = std::env::var("PERSONA_DB_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        });

    // Create listener using cross-platform abstraction
    let mut listener = AgentListener::bind(&socket_path)
        .await
        .with_context(|| format!("Failed to bind socket {}", socket_path.display()))?;
    info!("persona-ssh-agent listening at {}", socket_path.display());
    println!("SSH_AUTH_SOCK={}", socket_path.display());

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
    let _ = std::fs::write(&sock_file, socket_path.display().to_string());
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

async fn handle_connection(agent: &mut Agent, mut stream: AgentStream) -> Result<()> {
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let pkt_len = BigEndian::read_u32(&len_buf) as usize;
        let mut pkt = vec![0u8; pkt_len];
        stream.read_exact(&mut pkt).await?;
        if pkt.is_empty() {
            continue;
        }
        let msg_type = pkt[0];
        match msg_type {
            11 => {
                // SSH_AGENTC_REQUEST_IDENTITIES
                let resp = agent.identities_answer()?;
                stream.write_all(&resp).await?;
            }
            13 => {
                // SSH_AGENTC_SIGN_REQUEST
                let resp = agent.sign_response(&pkt[1..])?;
                stream.write_all(&resp).await?;
            }
            other => {
                warn!("Unsupported message type: {}", other);
                // send failure (5)
                let mut out = vec![0u8; 5];
                BigEndian::write_u32(&mut out[0..4], 1);
                out[4] = 5u8;
                stream.write_all(&out).await?;
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct AgentKey {
    pub public_blob: Vec<u8>, // OpenSSH key blob
    pub comment: String,
    pub secret_seed: [u8; 32], // ed25519 seed
    pub identity_id: uuid::Uuid,
    pub credential_id: uuid::Uuid,
}

struct Agent {
    keys: Vec<AgentKey>,
    policy: std::sync::Arc<tokio::sync::Mutex<PolicyEnforcer>>,
    biometric_provider: Arc<dyn BiometricProvider>,
}

impl Agent {
    fn new() -> Self {
        let enforcer = PolicyEnforcer::from_env();
        // Use mock provider by default; desktop/mobile apps can inject real implementation
        let biometric_provider: Arc<dyn BiometricProvider> =
            Arc::new(persona_core::MockBiometricProvider::default());

        Self {
            keys: Vec::new(),
            policy: std::sync::Arc::new(tokio::sync::Mutex::new(enforcer)),
            biometric_provider,
        }
    }
    fn clone_shallow(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            policy: self.policy.clone(),
            biometric_provider: self.biometric_provider.clone(),
        }
    }

    async fn load_keys_from_persona(&mut self, db_path: &PathBuf) -> persona_core::Result<()> {
        use persona_core::models::{CredentialData, CredentialType};
        use persona_core::{Database, PersonaService};

        let db = Database::from_file(db_path).await?;
        db.migrate().await?;
        let mut service = PersonaService::new(db.clone()).await?;
        let mut unlocked = true;
        if service.has_users().await? {
            if let Ok(pass) = std::env::var("PERSONA_MASTER_PASSWORD") {
                match service.authenticate_user(&pass).await? {
                    persona_core::auth::authentication::AuthResult::Success => {}
                    _ => {
                        unlocked = false;
                    }
                }
            } else {
                unlocked = false;
            }
        }
        if !unlocked {
            warn!("Vault is locked and PERSONA_MASTER_PASSWORD not set; no keys loaded");
            return Ok(());
        }
        let identities = service.get_identities().await?;
        for id in identities {
            let creds = service.get_credentials_for_identity(&id.id).await?;
            for cred in creds {
                if let CredentialType::SshKey = cred.credential_type {
                    if let Some(CredentialData::SshKey(ssh)) =
                        service.get_credential_data(&cred.id).await?
                    {
                        // ssh.private_key is base64 seed; ssh.public_key is OpenSSH text
                        let seed_bytes = match BASE64.decode(&ssh.private_key) {
                            Ok(b) if b.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                arr
                            }
                            _ => {
                                warn!("Invalid SSH seed size for credential {}", cred.id);
                                continue;
                            }
                        };
                        // Build public blob from OpenSSH public text
                        let public_blob =
                            if let Some(blob) = parse_openssh_pub_to_blob(&ssh.public_key) {
                                blob
                            } else {
                                warn!("Invalid OpenSSH public key for credential {}", cred.id);
                                continue;
                            };
                        self.keys.push(AgentKey {
                            public_blob,
                            comment: cred.name.clone(),
                            secret_seed: seed_bytes,
                            identity_id: id.id,
                            credential_id: cred.id,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn identities_answer(&self) -> Result<Vec<u8>> {
        use byteorder::{BigEndian, WriteBytesExt};
        // packet: len(4) type(1)=12 count(u32) repeated [string key_blob, string comment]
        let mut payload = Vec::new();
        payload.push(12u8);
        payload.write_u32::<BigEndian>(self.keys.len() as u32)?;
        for k in &self.keys {
            write_ssh_string(&mut payload, &k.public_blob)?;
            write_ssh_string(&mut payload, k.comment.as_bytes())?;
        }
        Ok(wrap_packet(payload))
    }

    fn sign_response(&self, mut payload: &[u8]) -> Result<Vec<u8>> {
        use byteorder::{BigEndian, ReadBytesExt};
        // sign_request payload: string key_blob, string data, flags(u32)
        let key_blob = read_ssh_string(&mut payload)?;
        let data_to_sign = read_ssh_string(&mut payload)?;
        let _flags = payload.read_u32::<BigEndian>().unwrap_or(0);
        // Find key
        let key = self
            .keys
            .iter()
            .find(|k| k.public_blob == key_blob)
            .ok_or_else(|| anyhow::anyhow!("Key not found"))?;

        // Get target hostname
        let hostname = current_target_host();

        // Policy enforcement using PolicyEnforcer
        let mut policy_enforcer = self.policy.blocking_lock();
        match policy_enforcer.check_signature(&key.credential_id, hostname.as_deref())? {
            SignatureDecision::Denied { reason } => {
                tracing::warn!("Signature denied: {}", reason);
                return Ok(failure_packet());
            }
            SignatureDecision::RequireBiometric { reason } => {
                drop(policy_enforcer); // Release lock before biometric check

                // Check if biometric is available
                if !self.biometric_provider.is_available(detect_platform()) {
                    tracing::warn!(
                        "Biometric required but not available, falling back to confirmation"
                    );
                    let prompt = format!(
                        "Biometric unavailable. Allow SSH signature for '{}'? [y/N] ",
                        hostname.as_deref().unwrap_or("unknown host")
                    );
                    if !prompt_confirm_blocking(&prompt)? {
                        tracing::warn!("Signature denied by user (reason: {})", reason);
                        return Ok(failure_packet());
                    }
                } else {
                    // Perform biometric authentication
                    let prompt = BiometricPrompt {
                        user_id: key.identity_id,
                        reason: format!(
                            "SSH signature requested for {}",
                            hostname.as_deref().unwrap_or("unknown host")
                        ),
                        platform: detect_platform(),
                    };

                    match self.biometric_provider.authenticate(&prompt) {
                        Ok(result) if result.verified => {
                            tracing::info!("Biometric authentication successful");
                        }
                        Ok(_) => {
                            tracing::warn!("Biometric authentication failed");
                            return Ok(failure_packet());
                        }
                        Err(e) => {
                            tracing::error!("Biometric authentication error: {}", e);
                            return Ok(failure_packet());
                        }
                    }
                }

                policy_enforcer = self.policy.blocking_lock();
            }
            SignatureDecision::RequireConfirm { reason } => {
                drop(policy_enforcer); // Release lock before prompt

                let prompt = if let Some(ref host) = hostname {
                    format!("Allow SSH signature for host '{}'? [y/N] ", host)
                } else {
                    "Allow SSH signature? [y/N] ".to_string()
                };

                if !prompt_confirm_blocking(&prompt)? {
                    tracing::warn!("Signature denied by user (reason: {})", reason);
                    return Ok(failure_packet());
                }

                policy_enforcer = self.policy.blocking_lock();
            }
            SignatureDecision::Allowed => {
                // Proceed with signing
            }
        }

        // Record the signature for tracking
        policy_enforcer.record_signature(&key.credential_id, hostname.as_deref());
        drop(policy_enforcer); // Release lock before signing

        // ed25519 sign
        use ed25519_dalek::{Signature, Signer, SigningKey};
        let signing = SigningKey::from_bytes(&key.secret_seed);
        let sig: Signature = signing.sign(&data_to_sign);
        // Audit sign operation (best-effort, include SHA256 of signed data)
        if let Err(e) = audit_sign_with_digest(&key.identity_id, &key.credential_id, &data_to_sign)
        {
            tracing::warn!("audit sign failed: {}", e);
        }
        // Build signature blob: string algo, string signature (raw) for ed25519
        let mut sig_blob = Vec::new();
        write_ssh_string(&mut sig_blob, b"ssh-ed25519")?;
        write_ssh_string(&mut sig_blob, sig.to_bytes().as_slice())?;
        // response: type(14) string sig_blob
        let mut out = Vec::new();
        out.push(14u8);
        write_ssh_string(&mut out, &sig_blob)?;
        Ok(wrap_packet(out))
    }
}

fn audit_sign_with_digest(
    identity_id: &uuid::Uuid,
    credential_id: &uuid::Uuid,
    data: &[u8],
) -> Result<()> {
    use persona_core::models::{AuditAction, AuditLog, ResourceType};
    use persona_core::storage::AuditLogRepository;
    // Compute SHA256 of data
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let data_sha256 = hex::encode(digest.as_ref());
    // Determine DB path
    let db_path = std::env::var("PERSONA_DB_PATH")
        .ok()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("PERSONA_DB_PATH not set"))?;
    let rt = tokio::runtime::Handle::try_current().map_err(|_| anyhow!("No runtime"))?;
    rt.block_on(async move {
        let db = persona_core::storage::Database::from_file(&db_path)
            .await
            .map_err(|e| anyhow!(e))?;
        db.migrate().await.map_err(|e| anyhow!(e))?;
        let repo = AuditLogRepository::new(db);
        let log = AuditLog::new(
            AuditAction::Custom("ssh_sign".to_string()),
            ResourceType::Credential,
            true,
        )
        .with_identity_id(Some(*identity_id))
        .with_credential_id(Some(*credential_id))
        .with_metadata("data_sha256".to_string(), data_sha256);
        let _ = repo.create(&log).await;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn wrap_packet(payload: Vec<u8>) -> Vec<u8> {
    use byteorder::{BigEndian, ByteOrder};
    let len = payload.len() as u32;
    let mut out = vec![0u8; 4];
    BigEndian::write_u32(&mut out[0..4], len);
    out.extend_from_slice(&payload);
    out
}

fn write_ssh_string(buf: &mut Vec<u8>, s: &[u8]) -> Result<()> {
    use byteorder::{BigEndian, WriteBytesExt};
    buf.write_u32::<BigEndian>(s.len() as u32)?;
    buf.extend_from_slice(s);
    Ok(())
}

fn read_ssh_string(buf: &mut &[u8]) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, ReadBytesExt};
    let len = buf.read_u32::<BigEndian>()? as usize;
    if buf.len() < len {
        anyhow::bail!("ssh string length out of bounds");
    }
    let (s, rest) = buf.split_at(len);
    *buf = rest;
    Ok(s.to_vec())
}

fn parse_openssh_pub_to_blob(s: &str) -> Option<Vec<u8>> {
    // "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI.... [comment]"
    let mut parts = s.split_whitespace();
    let algo = parts.next()?;
    if algo != "ssh-ed25519" {
        return None;
    }
    let b64 = parts.next()?;
    let decoded = BASE64.decode(b64).ok()?;
    Some(decoded)
}

fn failure_packet() -> Vec<u8> {
    use byteorder::{BigEndian, ByteOrder};
    let mut out = vec![0u8; 5];
    BigEndian::write_u32(&mut out[0..4], 1);
    out[4] = 5u8;
    out
}

fn prompt_confirm_blocking(prompt: &str) -> Result<bool> {
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

fn current_target_host() -> Option<String> {
    std::env::var("PERSONA_AGENT_TARGET_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn is_host_in_known_hosts(host: &str) -> bool {
    let custom = std::env::var("PERSONA_KNOWN_HOSTS_FILE").ok();
    let paths = custom
        .into_iter()
        .map(PathBuf::from)
        .chain(dirs::home_dir().map(|p| p.join(".ssh").join("known_hosts")));
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                if let Some(first) = line.split_whitespace().next() {
                    if first.split(',').any(|entry| entry == host) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn detect_platform() -> Option<BiometricPlatform> {
    #[cfg(target_os = "macos")]
    {
        // Try to detect Touch ID vs Face ID
        // In a real implementation, you'd check hardware capabilities
        Some(BiometricPlatform::TouchId)
    }

    #[cfg(target_os = "windows")]
    {
        Some(BiometricPlatform::WindowsHello)
    }

    #[cfg(target_os = "linux")]
    {
        Some(BiometricPlatform::LinuxSecretService)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}
