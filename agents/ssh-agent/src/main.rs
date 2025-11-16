//! Persona SSH Agent daemon (MVP)
//! - UNIX domain socket agent implementing a minimal subset of the SSH Agent protocol:
//!   - request_identities
//!   - sign_request (ed25519)
//! - Loads SSH keys (ed25519) from Persona vault (CredentialType::SshKey)
//! - Unlocks using master password from env PERSONA_MASTER_PASSWORD (if required)
//! NOTE: This is an early MVP; no policies/approvals yet.

use anyhow::{Context, Result};
use tracing::{info, warn, error, Level};
use std::path::PathBuf;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let socket_path = std::env::var("SSH_AUTH_SOCK").ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push(format!("persona-ssh-agent-{}.sock", std::process::id()));
            p
        });
    let db_path = std::env::var("PERSONA_DB_PATH").ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        });

    // Remove existing socket if present
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind socket {}", socket_path.display()))?;
    info!("persona-ssh-agent listening at {}", socket_path.display());
    println!("SSH_AUTH_SOCK={}", socket_path.display());

    // Write state files
    let state_dir = std::env::var("PERSONA_AGENT_STATE_DIR").ok()
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
    agent.load_keys_from_persona(&db_path).await?;
    info!("Loaded {} SSH keys from Persona", agent.keys.len());

    loop {
        let (stream, addr) = listener.accept().await?;
        let mut agent_clone = agent.clone_shallow();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut agent_clone, stream).await {
                warn!("Connection error: {}", e);
            }
        });
    }
}

#[cfg(not(unix))]
fn main() -> Result<()> {
    eprintln!("persona-ssh-agent: UNIX domain sockets are not supported on this platform yet.");
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(agent: &mut Agent, mut stream: tokio::net::UnixStream) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use byteorder::{BigEndian, ByteOrder};
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let pkt_len = BigEndian::read_u32(&len_buf) as usize;
        let mut pkt = vec![0u8; pkt_len];
        stream.read_exact(&mut pkt).await?;
        if pkt.is_empty() { continue; }
        let msg_type = pkt[0];
        match msg_type {
            11 => { // SSH_AGENTC_REQUEST_IDENTITIES
                let resp = agent.identities_answer()?;
                stream.write_all(&resp).await?;
            }
            13 => { // SSH_AGENTC_SIGN_REQUEST
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

#[derive(Default, Clone)]
struct AgentPolicy {
    require_confirm: bool,
    min_interval_ms: u64,
    last_sign: Option<std::time::Instant>,
}

#[derive(Default)]
struct Agent {
    keys: Vec<AgentKey>,
    policy: std::sync::Arc<tokio::sync::Mutex<AgentPolicy>>,
}

impl Agent {
    fn new() -> Self {
        let require_confirm = std::env::var("PERSONA_AGENT_REQUIRE_CONFIRM")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);
        let min_interval_ms = std::env::var("PERSONA_AGENT_MIN_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Self {
            keys: Vec::new(),
            policy: std::sync::Arc::new(tokio::sync::Mutex::new(AgentPolicy {
                require_confirm,
                min_interval_ms,
                last_sign: None,
            })),
        }
    }
    fn clone_shallow(&self) -> Self { Self { keys: self.keys.clone(), policy: self.policy.clone() } }

    async fn load_keys_from_persona(&mut self, db_path: &PathBuf) -> Result<()> {
        use persona_core::{Database, PersonaService};
        use persona_core::models::{CredentialType, CredentialData};
        use dialoguer::Password;

        let db = Database::from_file(&db_path.to_string_lossy()).await?;
        db.migrate().await?;
        let mut service = PersonaService::new(db.clone()).await?;
        let mut unlocked = true;
        if service.has_users().await? {
            if let Ok(pass) = std::env::var("PERSONA_MASTER_PASSWORD") {
                match service.authenticate_user(&pass).await? {
                    persona_core::auth::authentication::AuthResult::Success => {}
                    _ => { unlocked = false; }
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
                    if let Some(CredentialData::SshKey(ssh)) = service.get_credential_data(&cred.id).await? {
                        // ssh.private_key is base64 seed; ssh.public_key is OpenSSH text
                        let seed_bytes = match base64::decode(&ssh.private_key) {
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
                        let public_blob = if let Some(blob) = parse_openssh_pub_to_blob(&ssh.public_key) {
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
        use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
        // sign_request payload: string key_blob, string data, flags(u32)
        let key_blob = read_ssh_string(&mut payload)?;
        let data_to_sign = read_ssh_string(&mut payload)?;
        let _flags = payload.read_u32::<BigEndian>().unwrap_or(0);
        // Find key
        let key = self.keys.iter().find(|k| k.public_blob == key_blob)
            .ok_or_else(|| anyhow::anyhow!("Key not found"))?;
        // Policy: rate limiting and optional confirmation
        {
            use std::time::{Duration, Instant};
            let mut pol = self.policy.blocking_lock();
            if pol.min_interval_ms > 0 {
                if let Some(last) = pol.last_sign {
                    if last.elapsed() < Duration::from_millis(pol.min_interval_ms) {
                        tracing::warn!("Denied sign: rate-limit {}ms", pol.min_interval_ms);
                        return Ok(failure_packet());
                    }
                }
            }
            if pol.require_confirm {
                if !prompt_confirm_blocking("Allow SSH signature? [y/N] ")? {
                    tracing::warn!("Denied sign: user rejected");
                    return Ok(failure_packet());
                }
            }
            pol.last_sign = Some(Instant::now());
        }
        // Known hosts enforcement (optional)
        if std::env::var("PERSONA_AGENT_ENFORCE_KNOWN_HOSTS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let host = current_target_host();
            let mut allow = false;
            if let Some(ref h) = host {
                if is_host_in_known_hosts(h) {
                    allow = true;
                } else {
                    let confirm_on_unknown = std::env::var("PERSONA_AGENT_CONFIRM_ON_UNKNOWN")
                        .map(|v| v == "1" || v.to_lowercase() == "true")
                        .unwrap_or(false);
                    if confirm_on_unknown {
                        if prompt_confirm_blocking(&format!("Host '{}' not in known_hosts. Allow signature? [y/N] ", h))? {
                            allow = true;
                        }
                    }
                }
            }
            if !allow {
                tracing::warn!("Denied sign: known_hosts policy (host {:?})", host);
                return Ok(failure_packet());
            }
        }
        // ed25519 sign
        use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey};
        let signing = SigningKey::from_bytes(&key.secret_seed);
        let sig: Signature = signing.sign(&data_to_sign);
        // Audit sign operation (best-effort, include SHA256 of signed data)
        if let Err(e) = audit_sign_with_digest(&key.identity_id, &key.credential_id, &data_to_sign) {
            tracing::warn!("audit sign failed: {}", e);
        }
        // Build signature blob: string algo, string signature (raw) for ed25519
        let mut sig_blob = Vec::new();
        write_ssh_string(&mut sig_blob, b"ssh-ed25519")?;
        write_ssh_string(&mut sig_blob, sig.as_ref())?;
        // response: type(14) string sig_blob
        let mut out = Vec::new();
        out.push(14u8);
        write_ssh_string(&mut out, &sig_blob)?;
        Ok(wrap_packet(out))
    }
}

fn audit_sign_with_digest(identity_id: &uuid::Uuid, credential_id: &uuid::Uuid, data: &[u8]) -> Result<()> {
    use persona_core::storage::AuditLogRepository;
    use persona_core::models::{AuditLog, AuditAction, ResourceType};
    // Compute SHA256 of data
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let data_sha256 = hex::encode(digest.as_ref());
    // Determine DB path
    let db_path = std::env::var("PERSONA_DB_PATH").ok()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("PERSONA_DB_PATH not set"))?;
    let rt = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("No runtime"))?;
    rt.block_on(async move {
        let db = persona_core::storage::Database::from_file(&db_path.to_string_lossy()).await?;
        db.migrate().await?;
        let repo = AuditLogRepository::new(db);
        let log = AuditLog::new(AuditAction::Custom("ssh_sign".to_string()), ResourceType::Credential, true)
            .with_identity_id(Some(*identity_id))
            .with_credential_id(Some(*credential_id))
            .with_metadata("data_sha256".to_string(), data_sha256);
        let _ = repo.create(&log).await;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn wrap_packet(mut payload: Vec<u8>) -> Vec<u8> {
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

fn read_ssh_string<'a>(buf: &mut &'a [u8]) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, ReadBytesExt};
    let len = buf.read_u32::<BigEndian>()? as usize;
    if buf.len() < len { anyhow::bail!("ssh string length out of bounds"); }
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
    let decoded = base64::decode(b64).ok()?;
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
    use std::io::{Write, Read};
    // Prefer /dev/tty for interactive consent
    if let Ok(mut tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
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
