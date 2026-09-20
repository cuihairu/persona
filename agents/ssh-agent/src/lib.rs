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

pub mod approval;
pub mod policy;
pub mod transport;

mod daemon;

pub use approval::{
    fingerprint_for_blob, ApprovalHandler, ApprovalRequest, DenyAllApprovalHandler,
    TtyApprovalHandler,
};
pub use daemon::{run_agent, run_agent_with_approval, run_agent_with_hooks};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use persona_core::{
    BiometricPlatform, BiometricPrompt, BiometricProvider, PersonaError, Repository,
};
use policy::{PolicyEnforcer, SignatureDecision};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use transport::AgentStream;

pub async fn handle_connection(agent: &mut Agent, mut stream: AgentStream) -> Result<()> {
    use byteorder::{BigEndian, ByteOrder};
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
                let resp = agent.sign_response(&pkt[1..]).await?;
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
pub struct AgentKey {
    pub public_blob: Vec<u8>, // OpenSSH key blob
    pub comment: String,
    pub secret_seed: [u8; 32], // ed25519 seed
    pub identity_id: uuid::Uuid,
    pub credential_id: uuid::Uuid,
}

pub struct Agent {
    keys: Vec<AgentKey>,
    policy: Arc<Mutex<PolicyEnforcer>>,
    biometric_provider: Arc<dyn BiometricProvider>,
    approval_handler: Arc<dyn ApprovalHandler>,
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    pub fn new() -> Self {
        let enforcer = PolicyEnforcer::from_env();
        // Fail-closed by default: the mock is unavailable and fails, so a
        // `require_biometric` policy denies signatures until the host injects
        // a real provider (`with_biometric_provider`). The previous default
        // (available + always verified) silently waved biometric-gated
        // signatures through.
        let biometric_provider: Arc<dyn BiometricProvider> =
            Arc::new(persona_core::MockBiometricProvider {
                available: false,
                force_fail: true,
                platform: persona_core::BiometricPlatform::Unknown,
            });

        Self {
            keys: Vec::new(),
            policy: Arc::new(Mutex::new(enforcer)),
            biometric_provider,
            approval_handler: Arc::new(approval::TtyApprovalHandler),
        }
    }

    /// Replace the approval handler (desktop/mobile apps inject their own UI).
    pub fn with_approval_handler(mut self, handler: Arc<dyn ApprovalHandler>) -> Self {
        self.approval_handler = handler;
        self
    }

    /// Replace the biometric provider (hosts inject the OS-backed provider;
    /// without this the default provider denies every biometric gate).
    pub fn with_biometric_provider(mut self, provider: Arc<dyn BiometricProvider>) -> Self {
        self.biometric_provider = provider;
        self
    }

    pub fn clone_shallow(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            policy: self.policy.clone(),
            biometric_provider: self.biometric_provider.clone(),
            approval_handler: self.approval_handler.clone(),
        }
    }

    pub async fn load_keys_from_persona(&mut self, db_path: &PathBuf) -> persona_core::Result<()> {
        if self.load_test_key_from_env()? {
            info!("Loaded SSH key from test environment override");
            return Ok(());
        }
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

    fn load_test_key_from_env(&mut self) -> persona_core::Result<bool> {
        let seed_b64 = match std::env::var("PERSONA_AGENT_TEST_KEY_SEED") {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let decoded = BASE64.decode(seed_b64.trim()).map_err(|e| {
            anyhow!(PersonaError::InvalidInput(format!(
                "Invalid test key seed: {e}"
            )))
        })?;
        if decoded.len() != 32 {
            return Err(anyhow!(PersonaError::InvalidInput(
                "Test key seed must be 32 bytes".to_string(),
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decoded);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pub_bytes = signing.verifying_key().to_bytes();
        let mut public_blob = Vec::new();
        write_ssh_string(&mut public_blob, b"ssh-ed25519")
            .map_err(|e| anyhow!(PersonaError::CryptographicError(e.to_string())))?;
        write_ssh_string(&mut public_blob, &pub_bytes)
            .map_err(|e| anyhow!(PersonaError::CryptographicError(e.to_string())))?;
        let comment = std::env::var("PERSONA_AGENT_TEST_KEY_COMMENT")
            .unwrap_or_else(|_| "Test Key".to_string());
        self.keys.push(AgentKey {
            public_blob,
            comment,
            secret_seed: seed,
            identity_id: uuid::Uuid::new_v4(),
            credential_id: uuid::Uuid::new_v4(),
        });
        Ok(true)
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

    async fn sign_response(&self, mut payload: &[u8]) -> Result<Vec<u8>> {
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

        // Policy enforcement using PolicyEnforcer.
        // The guard is scoped so it never spans an await (MutexGuard is !Send).
        let decision = {
            let mut policy_enforcer = self
                .policy
                .lock()
                .map_err(|_| anyhow!("Policy lock poisoned"))?;
            policy_enforcer.check_signature(&key.credential_id, hostname.as_deref())?
        };
        match decision {
            SignatureDecision::Denied { reason } => {
                tracing::warn!("Signature denied: {}", reason);
                return Ok(failure_packet());
            }
            SignatureDecision::RequireBiometric { reason } => {
                // Check if biometric is available
                if !self.biometric_provider.is_available(detect_platform()) {
                    tracing::warn!(
                        "Biometric required but not available, falling back to confirmation"
                    );
                    let prompt = format!(
                        "Biometric unavailable. Allow SSH signature for '{}'? [y/N] ",
                        hostname.as_deref().unwrap_or("unknown host")
                    );
                    let request = ApprovalRequest {
                        key_id: key.credential_id.to_string(),
                        fingerprint: approval::fingerprint_for_blob(&key.public_blob),
                        operation: "sign".to_string(),
                        peer: hostname.clone(),
                        reason: reason.clone(),
                        prompt,
                    };
                    if !self.approval_handler.confirm(&request).await? {
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
            }
            SignatureDecision::RequireConfirm { reason } => {
                let prompt = if let Some(ref host) = hostname {
                    format!("Allow SSH signature for host '{}'? [y/N] ", host)
                } else {
                    "Allow SSH signature? [y/N] ".to_string()
                };

                let request = ApprovalRequest {
                    key_id: key.credential_id.to_string(),
                    fingerprint: approval::fingerprint_for_blob(&key.public_blob),
                    operation: "sign".to_string(),
                    peer: hostname.clone(),
                    reason: reason.clone(),
                    prompt,
                };
                if !self.approval_handler.confirm(&request).await? {
                    tracing::warn!("Signature denied by user (reason: {})", reason);
                    return Ok(failure_packet());
                }
            }
            SignatureDecision::Allowed => {
                // Proceed with signing
            }
        }

        // Record the signature for tracking
        {
            let mut policy_enforcer = self
                .policy
                .lock()
                .map_err(|_| anyhow!("Policy lock poisoned"))?;
            policy_enforcer.record_signature(&key.credential_id, hostname.as_deref());
        }

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
    let db_path = resolve_persona_db_path();

    // Best-effort background audit: never block the agent request handler, and avoid
    // nested `block_on` when running inside an existing Tokio runtime (tests included).
    let identity_id = *identity_id;
    let credential_id = *credential_id;
    let fut = async move {
        let db = persona_core::storage::Database::from_file(&db_path).await?;
        db.migrate().await?;
        let repo = AuditLogRepository::new(db);
        let log = AuditLog::new(
            AuditAction::Custom("ssh_sign".to_string()),
            ResourceType::Credential,
            true,
        )
        .with_identity_id(Some(identity_id))
        .with_credential_id(Some(credential_id))
        .with_metadata("data_sha256".to_string(), data_sha256);
        let _ = repo.create(&log).await;
        Ok::<(), anyhow::Error>(())
    };

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = fut.await;
        });
        return Ok(());
    }

    // Fallback for synchronous contexts.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _ = rt.block_on(fut);
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

fn current_target_host() -> Option<String> {
    fn parse_connection_var(var: &str) -> Option<String> {
        std::env::var(var)
            .ok()
            .and_then(|value| value.split_whitespace().next().map(|s| s.to_string()))
    }

    fn parse_host_from_command(command: &str) -> Option<String> {
        let mut fallback = None;
        for raw_token in command.split_whitespace() {
            let token = raw_token.trim_matches(|c| c == '"' || c == '\'');
            if token.is_empty()
                || token.starts_with('-')
                || token.eq_ignore_ascii_case("ssh")
                || token.eq_ignore_ascii_case("ssh.exe")
                || token.starts_with('$')
            {
                continue;
            }

            let candidate = if let Some(idx) = token.rfind('@') {
                token[idx + 1..].to_string()
            } else if token.contains('/') || token.contains('=') {
                continue;
            } else {
                token.to_string()
            };

            let is_hostname = candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
            if !is_hostname {
                continue;
            }
            if candidate.contains('.') || candidate.contains(':') {
                return Some(candidate);
            }
            if fallback.is_none() {
                fallback = Some(candidate);
            }
        }
        fallback
    }

    if let Ok(value) = std::env::var("PERSONA_AGENT_TARGET_HOST") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    for var in ["PERSONA_AGENT_TARGET_HOST_HINT", "PERSONA_AGENT_SSH_DEST"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    for var in ["SSH_CONNECTION", "SSH_CLIENT"] {
        if let Some(host) = parse_connection_var(var) {
            if !host.is_empty() {
                return Some(host);
            }
        }
    }

    for var in [
        "PERSONA_AGENT_SSH_COMMAND",
        "SSH_ORIGINAL_COMMAND",
        "GIT_SSH_COMMAND",
    ] {
        if let Ok(cmd) = std::env::var(var) {
            if let Some(host) = parse_host_from_command(&cmd) {
                return Some(host);
            }
        }
    }

    None
}

pub(crate) fn is_host_in_known_hosts(host: &str) -> bool {
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

fn resolve_persona_db_path() -> PathBuf {
    std::env::var("PERSONA_DB_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".persona")
                .join("identities.db")
        })
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

#[cfg(test)]
#[allow(clippy::await_holding_lock)] // env_lock must be held across .await for env var isolation in parallel tests
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        // Recover from a poisoned lock so one failing test does not cascade.
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn make_test_agent(keys: Vec<AgentKey>) -> Agent {
        let policy = policy::SigningPolicy::default();
        let enforcer = PolicyEnforcer::new(policy);
        let biometric_provider: Arc<dyn BiometricProvider> =
            Arc::new(persona_core::MockBiometricProvider::default());

        Agent {
            keys,
            policy: Arc::new(Mutex::new(enforcer)),
            biometric_provider,
            approval_handler: Arc::new(approval::DenyAllApprovalHandler),
        }
    }

    fn make_ed25519_key(comment: &str) -> (AgentKey, ed25519_dalek::VerifyingKey) {
        let seed = [9u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        let pub_bytes = verifying.to_bytes();

        let mut public_blob = Vec::new();
        write_ssh_string(&mut public_blob, b"ssh-ed25519").unwrap();
        write_ssh_string(&mut public_blob, &pub_bytes).unwrap();

        (
            AgentKey {
                public_blob,
                comment: comment.to_string(),
                secret_seed: seed,
                identity_id: uuid::Uuid::new_v4(),
                credential_id: uuid::Uuid::new_v4(),
            },
            verifying,
        )
    }

    #[test]
    fn wrap_packet_prepends_big_endian_length() {
        let out = wrap_packet(vec![1u8, 2, 3]);
        assert_eq!(out, vec![0, 0, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn ssh_string_roundtrip() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"hello").unwrap();
        write_ssh_string(&mut buf, b"world").unwrap();

        let mut slice: &[u8] = &buf;
        let a = read_ssh_string(&mut slice).unwrap();
        let b = read_ssh_string(&mut slice).unwrap();
        assert_eq!(a, b"hello");
        assert_eq!(b, b"world");
        assert!(slice.is_empty());
    }

    #[test]
    fn ssh_string_out_of_bounds_errors() {
        let mut buf = Vec::new();
        // length=10, but only 1 byte of payload
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.push(1u8);
        let mut slice: &[u8] = &buf;
        assert!(read_ssh_string(&mut slice).is_err());
    }

    #[test]
    fn parse_openssh_pub_to_blob_accepts_ed25519() {
        let decoded = vec![1u8, 2, 3, 4, 5];
        let encoded = BASE64.encode(&decoded);
        let line = format!("ssh-ed25519 {} comment", encoded);
        assert_eq!(parse_openssh_pub_to_blob(&line), Some(decoded));
    }

    #[test]
    fn parse_openssh_pub_to_blob_rejects_other_algorithms() {
        let line = "ssh-rsa AAAA comment";
        assert_eq!(parse_openssh_pub_to_blob(line), None);
    }

    #[test]
    fn current_target_host_prefers_explicit_vars() {
        let _guard = env_lock();

        std::env::remove_var("PERSONA_AGENT_TARGET_HOST_HINT");
        std::env::remove_var("PERSONA_AGENT_SSH_DEST");
        std::env::remove_var("SSH_CONNECTION");
        std::env::remove_var("SSH_CLIENT");
        std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");
        std::env::remove_var("SSH_ORIGINAL_COMMAND");
        std::env::remove_var("GIT_SSH_COMMAND");

        std::env::set_var("PERSONA_AGENT_TARGET_HOST", "github.com");
        assert_eq!(current_target_host().as_deref(), Some("github.com"));

        std::env::set_var("PERSONA_AGENT_TARGET_HOST", "");
        std::env::set_var("PERSONA_AGENT_TARGET_HOST_HINT", "gitlab.com");
        assert_eq!(current_target_host().as_deref(), Some("gitlab.com"));

        std::env::remove_var("PERSONA_AGENT_TARGET_HOST");
        std::env::remove_var("PERSONA_AGENT_TARGET_HOST_HINT");
        std::env::set_var("SSH_CONNECTION", "1.2.3.4 123 5.6.7.8 22");
        assert_eq!(current_target_host().as_deref(), Some("1.2.3.4"));

        std::env::remove_var("SSH_CONNECTION");
        std::env::set_var("GIT_SSH_COMMAND", "ssh -T git@github.com");
        assert_eq!(current_target_host().as_deref(), Some("github.com"));
    }

    #[test]
    fn is_host_in_known_hosts_uses_custom_file() {
        let _guard = env_lock();

        let dir = tempfile::tempdir().unwrap();
        let known_hosts_path = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts_path,
            "\
# comment
github.com ssh-ed25519 AAAA
gitlab.com,192.0.2.1 ssh-rsa AAAA
",
        )
        .unwrap();

        std::env::set_var("PERSONA_KNOWN_HOSTS_FILE", &known_hosts_path);

        assert!(is_host_in_known_hosts("github.com"));
        assert!(is_host_in_known_hosts("gitlab.com"));
        assert!(!is_host_in_known_hosts("example.com"));
    }

    #[test]
    fn identities_answer_encodes_count_and_comments() {
        let (k1, _) = make_ed25519_key("Key One");
        let (k2, _) = make_ed25519_key("Key Two");
        let agent = make_test_agent(vec![k1.clone(), k2.clone()]);

        let pkt = agent.identities_answer().unwrap();
        assert!(pkt.len() >= 4 + 1 + 4);
        let len = u32::from_be_bytes(pkt[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, pkt.len() - 4);
        assert_eq!(pkt[4], 12u8);
        let count = u32::from_be_bytes(pkt[5..9].try_into().unwrap());
        assert_eq!(count, 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn handle_connection_request_identities_roundtrip() {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::transport::AgentListener;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("persona-agent-e2e.sock");

        let mut listener = AgentListener::bind(&sock_path).await.unwrap();
        let (k, _) = make_ed25519_key("Key One");
        let mut agent = make_test_agent(vec![k]);

        let mut server_task = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            handle_connection(&mut agent, stream).await.unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut req = vec![0u8; 5];
        BigEndian::write_u32(&mut req[0..4], 1);
        req[4] = 11u8;
        client.write_all(&req).await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = BigEndian::read_u32(&len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 12u8);

        drop(client);
        // server exits when stream closes
        match tokio::time::timeout(std::time::Duration::from_secs(1), &mut server_task).await {
            Ok(res) => res.unwrap(),
            Err(_) => {
                server_task.abort();
                let _ = server_task.await;
            }
        }
    }

    #[tokio::test]
    async fn sign_response_produces_verifiable_signature() {
        let _guard = env_lock();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        std::env::set_var("PERSONA_DB_PATH", &db_path);

        let (key, verifying) = make_ed25519_key("Key One");
        let agent = make_test_agent(vec![key.clone()]);

        let data = b"data-to-sign";
        let mut payload = Vec::new();
        write_ssh_string(&mut payload, &key.public_blob).unwrap();
        write_ssh_string(&mut payload, data).unwrap();
        payload.extend_from_slice(&0u32.to_be_bytes()); // flags

        let pkt = agent.sign_response(&payload).await.unwrap();
        let len = u32::from_be_bytes(pkt[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, pkt.len() - 4);
        assert_eq!(pkt[4], 14u8);

        let mut slice: &[u8] = &pkt[5..];
        let sig_blob = read_ssh_string(&mut slice).unwrap();
        assert!(slice.is_empty());

        let mut sig_slice: &[u8] = &sig_blob;
        let algo = read_ssh_string(&mut sig_slice).unwrap();
        let sig_bytes = read_ssh_string(&mut sig_slice).unwrap();
        assert!(sig_slice.is_empty());
        assert_eq!(algo, b"ssh-ed25519");

        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        verifying.verify_strict(data, &sig).unwrap();
    }

    // ------------------------------------------------------------------
    // Agent construction / env-based key loading
    // ------------------------------------------------------------------

    #[test]
    fn agent_default_and_clone_shallow_share_policy() {
        let agent = Agent::default();
        assert!(agent.keys.is_empty());

        let (k, _) = make_ed25519_key("shared");
        let with_key = Agent {
            keys: vec![k],
            ..Agent::default()
        };
        let clone = with_key.clone_shallow();
        assert_eq!(clone.keys.len(), 1);
        assert_eq!(clone.keys[0].comment, "shared");
        assert!(Arc::ptr_eq(&with_key.policy, &clone.policy));
        assert!(Arc::ptr_eq(
            &with_key.biometric_provider,
            &clone.biometric_provider
        ));
    }

    #[test]
    fn default_agent_biometric_is_deny() {
        // The default provider must be unavailable and fail, so a
        // `require_biometric` policy denies instead of silently passing.
        let agent = Agent::default();
        assert!(!agent.biometric_provider.is_available(detect_platform()));
        let prompt = BiometricPrompt {
            user_id: uuid::Uuid::new_v4(),
            reason: "default-deny probe".to_string(),
            platform: detect_platform(),
        };
        assert!(agent.biometric_provider.authenticate(&prompt).is_err());
    }

    #[test]
    fn with_biometric_provider_overrides_default() {
        let provider = stub_biometric(true, StubOutcome::Succeed(true));
        let agent = Agent::default().with_biometric_provider(provider);
        assert!(agent.biometric_provider.is_available(detect_platform()));
        let prompt = BiometricPrompt {
            user_id: uuid::Uuid::new_v4(),
            reason: "override probe".to_string(),
            platform: detect_platform(),
        };
        assert!(
            agent
                .biometric_provider
                .authenticate(&prompt)
                .unwrap()
                .verified
        );
    }

    fn clear_test_key_env() {
        std::env::remove_var("PERSONA_AGENT_TEST_KEY_SEED");
        std::env::remove_var("PERSONA_AGENT_TEST_KEY_COMMENT");
    }

    #[test]
    fn load_test_key_from_env_covers_all_paths() {
        let _guard = env_lock();
        clear_test_key_env();
        let mut agent = Agent::default();

        // No env var -> no key, no error.
        assert!(!agent.load_test_key_from_env().unwrap());
        assert!(agent.keys.is_empty());

        // Malformed base64 -> error.
        std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", "!!!not base64!!!");
        assert!(agent.load_test_key_from_env().is_err());

        // Wrong size payload -> error.
        std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(b"short"));
        assert!(agent.load_test_key_from_env().is_err());

        // Valid 32-byte seed -> key loaded with optional comment override.
        let seed = [7u8; 32];
        std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));
        assert!(agent.load_test_key_from_env().unwrap());
        assert_eq!(agent.keys.len(), 1);
        assert_eq!(agent.keys[0].comment, "Test Key");
        assert_eq!(agent.keys[0].secret_seed, seed);

        std::env::set_var("PERSONA_AGENT_TEST_KEY_COMMENT", "custom comment");
        assert!(agent.load_test_key_from_env().unwrap());
        assert_eq!(agent.keys.len(), 2);
        assert_eq!(agent.keys[1].comment, "custom comment");

        clear_test_key_env();
    }

    #[tokio::test]
    async fn load_keys_from_persona_test_env_override_short_circuits() {
        let _guard = env_lock();
        clear_test_key_env();
        let seed = [11u8; 32];
        std::env::set_var("PERSONA_AGENT_TEST_KEY_SEED", BASE64.encode(seed));

        let mut agent = Agent::default();
        let bogus_path = PathBuf::from("/nonexistent/dir/identities.db");
        agent.load_keys_from_persona(&bogus_path).await.unwrap();
        assert_eq!(agent.keys.len(), 1);
        assert_eq!(agent.keys[0].secret_seed, seed);

        clear_test_key_env();
    }

    #[tokio::test]
    async fn load_keys_from_persona_missing_db_parent_errors() {
        let _guard = env_lock();
        clear_test_key_env();

        let dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist -> Database::from_file cannot create it.
        let db_path = dir.path().join("no-such-dir").join("identities.db");
        let mut agent = Agent::default();
        assert!(agent.load_keys_from_persona(&db_path).await.is_err());
    }

    fn openssh_pub_line(seed: [u8; 32]) -> (String, Vec<u8>) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pub_bytes = signing.verifying_key().to_bytes();
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, b"ssh-ed25519").unwrap();
        write_ssh_string(&mut blob, &pub_bytes).unwrap();
        (
            format!("ssh-ed25519 {} test@host", BASE64.encode(&blob)),
            blob,
        )
    }

    fn ssh_credential_data(seed: [u8; 32], pub_line: &str) -> persona_core::models::CredentialData {
        use persona_core::models::{CredentialData, SshKeyData};
        CredentialData::SshKey(SshKeyData {
            private_key: BASE64.encode(seed),
            public_key: pub_line.to_string(),
            key_type: "ed25519".to_string(),
            passphrase: None,
        })
    }

    #[tokio::test]
    async fn load_keys_from_persona_loads_valid_ssh_credential() {
        let _guard = env_lock();
        clear_test_key_env();
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let mut service = persona_core::PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity(
                "agent-test".to_string(),
                persona_core::models::IdentityType::Personal,
            )
            .await
            .unwrap();

        let seed = [21u8; 32];
        let (pub_line, pub_blob) = openssh_pub_line(seed);
        let cred = service
            .create_credential(
                identity.id,
                "my ssh key".to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &ssh_credential_data(seed, &pub_line),
            )
            .await
            .unwrap();

        let mut agent = Agent::default();
        agent.load_keys_from_persona(&db_path).await.unwrap();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert_eq!(agent.keys.len(), 1);
        let loaded = &agent.keys[0];
        assert_eq!(loaded.comment, "my ssh key");
        assert_eq!(loaded.secret_seed, seed);
        assert_eq!(loaded.public_blob, pub_blob);
        assert_eq!(loaded.identity_id, identity.id);
        assert_eq!(loaded.credential_id, cred.id);
    }

    #[tokio::test]
    async fn load_keys_from_persona_skips_invalid_seed_and_pubkey() {
        let _guard = env_lock();
        clear_test_key_env();
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let mut service = persona_core::PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity(
                "agent-test".to_string(),
                persona_core::models::IdentityType::Personal,
            )
            .await
            .unwrap();

        // Bad seed size (not 32 bytes) and malformed public key text.
        let bad_seed =
            persona_core::models::CredentialData::SshKey(persona_core::models::SshKeyData {
                private_key: BASE64.encode(b"too short"),
                public_key: "ssh-ed25519 AAAA".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            });
        service
            .create_credential(
                identity.id,
                "bad seed".to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &bad_seed,
            )
            .await
            .unwrap();

        let (_, good_blob) = openssh_pub_line([31u8; 32]);
        let bad_pub =
            persona_core::models::CredentialData::SshKey(persona_core::models::SshKeyData {
                private_key: BASE64.encode([32u8; 32]),
                public_key: "not-a-valid-key-line".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            });
        service
            .create_credential(
                identity.id,
                "bad pubkey".to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &bad_pub,
            )
            .await
            .unwrap();

        // A valid one to prove loading still works after skips.
        let seed = [41u8; 32];
        let (pub_line, _) = openssh_pub_line(seed);
        service
            .create_credential(
                identity.id,
                "good".to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &ssh_credential_data(seed, &pub_line),
            )
            .await
            .unwrap();

        let mut agent = Agent::default();
        agent.load_keys_from_persona(&db_path).await.unwrap();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert_eq!(agent.keys.len(), 1, "only the valid credential loads");
        assert_eq!(agent.keys[0].secret_seed, seed);
        let _ = good_blob;
    }

    #[tokio::test]
    async fn load_keys_from_persona_locked_vault_loads_nothing() {
        let _guard = env_lock();
        clear_test_key_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let mut service = persona_core::PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();

        // Vault has users but no PERSONA_MASTER_PASSWORD: fail closed, no keys.
        let mut agent = Agent::default();
        agent.load_keys_from_persona(&db_path).await.unwrap();
        assert!(agent.keys.is_empty());

        // Wrong password also loads nothing.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "wrong-pin");
        let mut agent = Agent::default();
        agent.load_keys_from_persona(&db_path).await.unwrap();
        assert!(agent.keys.is_empty());
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
    }

    // ------------------------------------------------------------------
    // sign_response policy branches
    // ------------------------------------------------------------------

    fn agent_with_policy(
        keys: Vec<AgentKey>,
        policy: policy::SigningPolicy,
        biometric_provider: Arc<dyn BiometricProvider>,
    ) -> Agent {
        Agent {
            keys,
            policy: Arc::new(Mutex::new(PolicyEnforcer::new(policy))),
            biometric_provider,
            approval_handler: Arc::new(approval::DenyAllApprovalHandler),
        }
    }

    enum StubOutcome {
        Succeed(bool),
        Fail(String),
    }

    fn stub_biometric(available: bool, outcome: StubOutcome) -> Arc<dyn BiometricProvider> {
        struct Stub {
            available: bool,
            outcome: StubOutcome,
        }
        impl BiometricProvider for Stub {
            fn is_available(&self, _hint: Option<BiometricPlatform>) -> bool {
                self.available
            }
            fn authenticate(
                &self,
                prompt: &BiometricPrompt,
            ) -> Result<persona_core::BiometricAuthResult> {
                let verified = match &self.outcome {
                    StubOutcome::Succeed(v) => *v,
                    StubOutcome::Fail(msg) => {
                        return Err(
                            persona_core::PersonaError::AuthenticationFailed(msg.clone()).into(),
                        );
                    }
                };
                Ok(persona_core::BiometricAuthResult {
                    user_id: prompt.user_id,
                    verified,
                    platform: prompt
                        .platform
                        .unwrap_or(BiometricPlatform::LinuxSecretService),
                })
            }
        }
        Arc::new(Stub { available, outcome })
    }

    fn sign_payload_for(key: &AgentKey, data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_ssh_string(&mut payload, &key.public_blob).unwrap();
        write_ssh_string(&mut payload, data).unwrap();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload
    }

    #[tokio::test]
    async fn sign_response_unknown_key_errors() {
        let agent = make_test_agent(vec![]);
        let (_, _) = make_ed25519_key("unused");
        // Blob for a key the agent does not hold.
        let seed = [3u8; 32];
        let (pub_line, blob) = openssh_pub_line(seed);
        let _ = pub_line;
        let payload = {
            let mut p = Vec::new();
            write_ssh_string(&mut p, &blob).unwrap();
            write_ssh_string(&mut p, b"data").unwrap();
            p.extend_from_slice(&0u32.to_be_bytes());
            p
        };
        let err = agent.sign_response(&payload).await.unwrap_err();
        assert!(err.to_string().contains("Key not found"));
    }

    #[tokio::test]
    async fn sign_response_denied_by_deny_all_policy() {
        let _guard = env_lock();
        std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

        let mut policy = policy::SigningPolicy::default();
        policy.global.deny_all = true;
        let (key, _) = make_ed25519_key("denied");
        let agent = agent_with_policy(
            vec![key.clone()],
            policy,
            stub_biometric(true, StubOutcome::Succeed(true)),
        );

        let pkt = agent
            .sign_response(&sign_payload_for(&key, b"data"))
            .await
            .unwrap();
        assert_eq!(pkt[4], 5u8, "failure packet");
    }

    #[tokio::test]
    async fn sign_response_biometric_branches() {
        let _guard = env_lock();
        std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

        for (name, outcome, expect_success) in [
            ("verified", StubOutcome::Succeed(true), true),
            ("rejected", StubOutcome::Succeed(false), false),
            (
                "error",
                StubOutcome::Fail("sensor unavailable".to_string()),
                false,
            ),
        ] {
            let mut policy = policy::SigningPolicy::default();
            let (key, verifying) = make_ed25519_key("biometric");
            policy.key_policies.insert(
                key.credential_id.to_string(),
                policy::KeyPolicy {
                    require_biometric: true,
                    ..Default::default()
                },
            );
            let agent = agent_with_policy(vec![key.clone()], policy, stub_biometric(true, outcome));

            let pkt = agent
                .sign_response(&sign_payload_for(&key, b"payload"))
                .await
                .unwrap();
            if expect_success {
                assert_eq!(pkt[4], 14u8, "{}: signature response", name);
                let mut slice: &[u8] = &pkt[5..];
                let sig_blob = read_ssh_string(&mut slice).unwrap();
                let mut s: &[u8] = &sig_blob;
                let _algo = read_ssh_string(&mut s).unwrap();
                let sig_bytes = read_ssh_string(&mut s).unwrap();
                let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
                verifying.verify_strict(b"payload", &sig).unwrap();
            } else {
                assert_eq!(pkt[4], 5u8, "{}: failure packet", name);
            }
        }
    }

    // ------------------------------------------------------------------
    // handle_connection protocol branches
    // ------------------------------------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn handle_connection_replies_failure_for_unsupported_type() {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("unsupported.sock");
        let mut listener = crate::transport::AgentListener::bind(&sock_path)
            .await
            .unwrap();
        let mut agent = make_test_agent(vec![]);

        let server = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            handle_connection(&mut agent, stream).await
        });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        // Empty payload is skipped entirely.
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        // Unsupported type (9) gets a failure packet (5).
        let mut req = vec![0u8; 5];
        BigEndian::write_u32(&mut req[0..4], 1);
        req[4] = 9u8;
        client.write_all(&req).await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let mut resp = vec![0u8; BigEndian::read_u32(&len_buf) as usize];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 5u8);

        // Truncated packet body (declared 16, sent 2) -> connection errors out.
        client.write_all(&16u32.to_be_bytes()).await.unwrap();
        client.write_all(b"xy").await.unwrap();
        drop(client);

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
        let handler = result.expect("server should finish").unwrap();
        assert!(handler.is_err(), "truncated body must surface an error");
    }

    // ------------------------------------------------------------------
    // Host detection fallbacks / db path / parsing edges
    // ------------------------------------------------------------------

    #[test]
    fn current_target_host_command_and_connection_fallbacks() {
        let _guard = env_lock();
        for var in [
            "PERSONA_AGENT_TARGET_HOST",
            "PERSONA_AGENT_TARGET_HOST_HINT",
            "PERSONA_AGENT_SSH_DEST",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "PERSONA_AGENT_SSH_COMMAND",
            "SSH_ORIGINAL_COMMAND",
            "GIT_SSH_COMMAND",
        ] {
            std::env::remove_var(var);
        }

        // SSH_CLIENT second-priority connection var.
        std::env::set_var("SSH_CLIENT", "10.0.0.9 2222 10.0.0.1 22");
        assert_eq!(current_target_host().as_deref(), Some("10.0.0.9"));
        std::env::remove_var("SSH_CLIENT");

        // PERSONA_AGENT_SSH_COMMAND parsed for a bare (dotless) hostname.
        std::env::set_var("PERSONA_AGENT_SSH_COMMAND", "ssh admin@intranet");
        assert_eq!(current_target_host().as_deref(), Some("intranet"));
        std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");

        // SSH_ORIGINAL_COMMAND wins over GIT_SSH_COMMAND and filters flags/paths.
        std::env::set_var(
            "SSH_ORIGINAL_COMMAND",
            "ssh -p 2222 deploy@host.example.com",
        );
        std::env::set_var("GIT_SSH_COMMAND", "ssh git@other.example.com");
        assert_eq!(current_target_host().as_deref(), Some("host.example.com"));
        std::env::remove_var("SSH_ORIGINAL_COMMAND");
        std::env::remove_var("GIT_SSH_COMMAND");

        // Only path-like / flag tokens -> None.
        std::env::set_var("GIT_SSH_COMMAND", "ssh /usr/bin/git-cleanup");
        assert_eq!(current_target_host(), None);
        std::env::remove_var("GIT_SSH_COMMAND");

        // A quoted $variable is filtered; nothing else qualifies -> None.
        std::env::set_var("PERSONA_AGENT_SSH_COMMAND", "ssh \"$TARGET\"");
        assert_eq!(current_target_host(), None);
        std::env::remove_var("PERSONA_AGENT_SSH_COMMAND");
    }

    #[test]
    fn resolve_persona_db_path_prefers_env_override() {
        let _guard = env_lock();

        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom.db");
        std::env::set_var("PERSONA_DB_PATH", &custom);
        assert_eq!(resolve_persona_db_path(), custom);

        std::env::remove_var("PERSONA_DB_PATH");
        let fallback = resolve_persona_db_path();
        assert!(fallback.ends_with(".persona/identities.db"));
    }

    #[test]
    fn parse_openssh_pub_to_blob_rejects_malformed_lines() {
        assert_eq!(parse_openssh_pub_to_blob(""), None);
        assert_eq!(parse_openssh_pub_to_blob("ssh-ed25519 !!!not-b64!!!"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_sign_with_digest_writes_log_inside_runtime() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        std::env::set_var("PERSONA_DB_PATH", &db_path);

        // audit_logs has FKs to identities/credentials: seed real rows first.
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let identity_repo = persona_core::storage::IdentityRepository::new(db.clone());
        let identity = persona_core::models::Identity::new(
            "audit-owner".to_string(),
            persona_core::models::IdentityType::Personal,
        );
        identity_repo.create(&identity).await.unwrap();
        // credential_id also carries an FK to credentials: seed that row too.
        use persona_core::models::{Credential, CredentialType, SecurityLevel};
        let mut cred = Credential::new(
            identity.id,
            "audit-key".to_string(),
            CredentialType::SshKey,
            SecurityLevel::High,
            vec![7u8; 32],
            None,
        );
        cred.encrypted_data = vec![7u8; 32];
        let credential_repo = persona_core::storage::CredentialRepository::new(db.clone());
        credential_repo.create(&cred).await.unwrap();
        let credential = cred.id;
        drop(db);

        audit_sign_with_digest(&identity.id, &credential, b"signed-bytes").unwrap();

        // The audit write is spawned in the background; poll briefly for it.
        let mut found = false;
        let mut last_err = String::new();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            match persona_core::Database::from_file(&db_path).await {
                Ok(db) => match db.migrate().await {
                    Ok(()) => {
                        let repo = persona_core::storage::AuditLogRepository::new(db.clone());
                        match repo
                            .find_by_action(&persona_core::models::AuditAction::Custom(
                                "ssh_sign".to_string(),
                            ))
                            .await
                        {
                            Ok(logs) if !logs.is_empty() => {
                                found = true;
                                break;
                            }
                            Ok(_) => {}
                            Err(e) => last_err = format!("find: {e}"),
                        }
                    }
                    Err(e) => last_err = format!("migrate: {e}"),
                },
                Err(e) => last_err = format!("open: {e}"),
            }
        }
        std::env::remove_var("PERSONA_DB_PATH");
        assert!(
            found,
            "ssh_sign audit entry should be persisted; last_err={last_err}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn handle_connection_sign_request_roundtrip() {
        use byteorder::{BigEndian, ByteOrder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        std::env::set_var("PERSONA_DB_PATH", &db_path);
        std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

        let sock_path = dir.path().join("sign.sock");
        let mut listener = crate::transport::AgentListener::bind(&sock_path)
            .await
            .unwrap();
        let (k, verifying) = make_ed25519_key("signer");
        let mut agent = make_test_agent(vec![k.clone()]);

        let server = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            handle_connection(&mut agent, stream).await
        });

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let payload = sign_payload_for(&k, b"frame-payload");
        let mut req = Vec::new();
        req.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        req.push(13u8); // SSH_AGENTC_SIGN_REQUEST
        req.extend_from_slice(&payload);
        client.write_all(&req).await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let mut resp = vec![0u8; BigEndian::read_u32(&len_buf) as usize];
        client.read_exact(&mut resp).await.unwrap();
        std::env::remove_var("PERSONA_DB_PATH");
        drop(client);

        assert_eq!(resp[0], 14u8, "signature answer");
        let mut slice: &[u8] = &resp[1..];
        let sig_blob = read_ssh_string(&mut slice).unwrap();
        let mut s: &[u8] = &sig_blob;
        let algo = read_ssh_string(&mut s).unwrap();
        let sig_bytes = read_ssh_string(&mut s).unwrap();
        assert_eq!(algo, b"ssh-ed25519");
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        verifying.verify_strict(b"frame-payload", &sig).unwrap();

        let handler = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server should finish")
            .unwrap();
        handler.unwrap();
    }

    #[test]
    fn audit_sign_with_digest_sync_fallback_builds_runtime() {
        // Outside any tokio runtime this exercises the synchronous fallback
        // path that spins up its own current-thread runtime.
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit-sync.db");
        std::env::set_var("PERSONA_DB_PATH", &db_path);

        // Seed the FK rows synchronously.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let identity_id = rt.block_on(async {
            let db = persona_core::Database::from_file(&db_path).await.unwrap();
            db.migrate().await.unwrap();
            let identity_repo = persona_core::storage::IdentityRepository::new(db.clone());
            let identity = persona_core::models::Identity::new(
                "sync-audit".to_string(),
                persona_core::models::IdentityType::Personal,
            );
            identity_repo.create(&identity).await.unwrap();
            use persona_core::models::{Credential, CredentialType, SecurityLevel};
            let mut cred = Credential::new(
                identity.id,
                "sync-key".to_string(),
                CredentialType::SshKey,
                SecurityLevel::High,
                vec![9u8; 32],
                None,
            );
            cred.encrypted_data = vec![9u8; 32];
            let credential_repo = persona_core::storage::CredentialRepository::new(db.clone());
            credential_repo.create(&cred).await.unwrap();
            (identity.id, cred.id)
        });

        let result = std::thread::spawn(move || {
            audit_sign_with_digest(&identity_id.0, &identity_id.1, b"sync-payload")
        })
        .join()
        .unwrap();
        result.unwrap();
        std::env::remove_var("PERSONA_DB_PATH");
    }

    // ------------------------------------------------------------------
    // Approval fallback / host resolution / locked-vault loading
    // ------------------------------------------------------------------

    /// Approval handler with a fixed decision that records every prompt.
    struct RecordingApproval {
        allow: bool,
        prompts: StdMutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl approval::ApprovalHandler for RecordingApproval {
        async fn confirm(&self, request: &approval::ApprovalRequest) -> anyhow::Result<bool> {
            self.prompts.lock().unwrap().push(request.prompt.clone());
            Ok(self.allow)
        }
    }

    fn biometric_policy_for(key: &AgentKey) -> policy::SigningPolicy {
        let mut policy = policy::SigningPolicy::default();
        policy.key_policies.insert(
            key.credential_id.to_string(),
            policy::KeyPolicy {
                require_biometric: true,
                ..Default::default()
            },
        );
        policy
    }

    fn agent_with(
        key: AgentKey,
        policy: policy::SigningPolicy,
        approval: Arc<dyn approval::ApprovalHandler>,
        biometric: Arc<dyn BiometricProvider>,
    ) -> Agent {
        Agent {
            keys: vec![key],
            policy: Arc::new(Mutex::new(PolicyEnforcer::new(policy))),
            biometric_provider: biometric,
            approval_handler: approval,
        }
    }

    /// Parse a signature response and return the raw signature bytes.
    fn extract_signature(pkt: &[u8]) -> Vec<u8> {
        assert_eq!(pkt[4], 14u8, "signature response");
        let mut slice: &[u8] = &pkt[5..];
        let sig_blob = read_ssh_string(&mut slice).unwrap();
        let mut s: &[u8] = &sig_blob;
        let algo = read_ssh_string(&mut s).unwrap();
        assert_eq!(algo, b"ssh-ed25519");
        read_ssh_string(&mut s).unwrap()
    }

    #[tokio::test]
    async fn sign_response_biometric_unavailable_falls_back_to_approval() {
        let _guard = env_lock();
        std::env::remove_var("PERSONA_AGENT_TARGET_HOST");

        // Approval allows: the signature still succeeds through the fallback.
        let (key, verifying) = make_ed25519_key("biometric-fallback");
        let allow = Arc::new(RecordingApproval {
            allow: true,
            prompts: StdMutex::new(Vec::new()),
        });
        let agent = agent_with(
            key.clone(),
            biometric_policy_for(&key),
            allow.clone(),
            stub_biometric(false, StubOutcome::Succeed(true)),
        );
        let pkt = agent
            .sign_response(&sign_payload_for(&key, b"fallback-allow"))
            .await
            .unwrap();
        let sig = extract_signature(&pkt);
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        verifying.verify_strict(b"fallback-allow", &sig).unwrap();
        let prompts = allow.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains("Biometric unavailable"));

        // Approval denies: the request is refused without a signature.
        let deny = Arc::new(RecordingApproval {
            allow: false,
            prompts: StdMutex::new(Vec::new()),
        });
        let agent = agent_with(
            key.clone(),
            biometric_policy_for(&key),
            deny.clone(),
            stub_biometric(false, StubOutcome::Succeed(true)),
        );
        let pkt = agent
            .sign_response(&sign_payload_for(&key, b"fallback-deny"))
            .await
            .unwrap();
        assert_eq!(pkt[4], 5u8, "denied fallback must fail");
        assert_eq!(deny.prompts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sign_response_require_confirm_without_hostname_prompts_generically() {
        let _guard = env_lock();
        for var in [
            "PERSONA_AGENT_TARGET_HOST",
            "PERSONA_AGENT_TARGET_HOST_HINT",
            "PERSONA_AGENT_SSH_DEST",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "PERSONA_AGENT_SSH_COMMAND",
            "SSH_ORIGINAL_COMMAND",
            "GIT_SSH_COMMAND",
        ] {
            std::env::remove_var(var);
        }

        let mut policy = policy::SigningPolicy::default();
        policy.global.require_confirm = true;
        let (key, _) = make_ed25519_key("confirm-no-host");
        let allow = Arc::new(RecordingApproval {
            allow: true,
            prompts: StdMutex::new(Vec::new()),
        });
        let agent = agent_with(
            key.clone(),
            policy,
            allow.clone(),
            stub_biometric(true, StubOutcome::Succeed(true)),
        );
        let pkt = agent
            .sign_response(&sign_payload_for(&key, b"no-host"))
            .await
            .unwrap();
        assert_eq!(pkt[4], 14u8);
        // Without any host hint the prompt is the generic form.
        let prompts = allow.prompts.lock().unwrap();
        assert_eq!(prompts[0], "Allow SSH signature? [y/N] ");
    }

    #[test]
    fn current_target_host_skips_invalid_tokens_and_blank_hints() {
        let _guard = env_lock();
        for var in [
            "PERSONA_AGENT_TARGET_HOST",
            "PERSONA_AGENT_TARGET_HOST_HINT",
            "PERSONA_AGENT_SSH_DEST",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "PERSONA_AGENT_SSH_COMMAND",
            "SSH_ORIGINAL_COMMAND",
            "GIT_SSH_COMMAND",
        ] {
            std::env::remove_var(var);
        }

        // A token that is not a hostname (illegal characters) is skipped and
        // no fallback host remains.
        std::env::set_var("GIT_SSH_COMMAND", "ssh user@bad!host.example");
        assert_eq!(current_target_host(), None);
        std::env::remove_var("GIT_SSH_COMMAND");

        // Blank hint/dest values are skipped and SSH_CONNECTION wins.
        std::env::set_var("PERSONA_AGENT_TARGET_HOST_HINT", "   ");
        std::env::set_var("PERSONA_AGENT_SSH_DEST", "");
        std::env::set_var("SSH_CONNECTION", "9.9.9.9 1 2");
        assert_eq!(current_target_host().as_deref(), Some("9.9.9.9"));
    }

    #[tokio::test]
    async fn load_keys_from_persona_locked_vault_and_mismatched_type() {
        let _guard = env_lock();
        clear_test_key_env();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("identities.db");
        let db = persona_core::Database::from_file(&db_path).await.unwrap();
        db.migrate().await.unwrap();
        let mut service = persona_core::PersonaService::new(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let identity = service
            .create_identity(
                "locked-vault".to_string(),
                persona_core::models::IdentityType::Personal,
            )
            .await
            .unwrap();

        // A vault with users but no PERSONA_MASTER_PASSWORD loads nothing.
        let mut agent = Agent::default();
        agent.load_keys_from_persona(&db_path).await.unwrap();
        assert!(agent.keys.is_empty());

        // An unlocked vault with a credential typed SshKey whose payload is
        // not SSH key material is skipped as well.
        std::env::set_var("PERSONA_MASTER_PASSWORD", "master-pin");
        let mismatched = persona_core::models::CredentialData::Password(
            persona_core::models::PasswordCredentialData {
                password: "not-an-ssh-key".to_string(),
                email: None,
                security_questions: vec![],
            },
        );
        service
            .create_credential(
                identity.id,
                "mismatched".to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &mismatched,
            )
            .await
            .unwrap();

        agent.load_keys_from_persona(&db_path).await.unwrap();
        std::env::remove_var("PERSONA_MASTER_PASSWORD");
        assert!(agent.keys.is_empty());
    }
}
