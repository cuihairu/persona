use super::*;

pub struct Agent {
    pub(crate) keys: Vec<AgentKey>,
    pub(crate) policy: Arc<Mutex<PolicyEnforcer>>,
    pub(crate) biometric_provider: Arc<dyn BiometricProvider>,
    pub(crate) approval_handler: Arc<dyn ApprovalHandler>,
    /// Host-injected vault password (preferred over the
    /// `PERSONA_MASTER_PASSWORD` env var). Consumed by
    /// [`Self::load_keys_from_persona`] so it does not outlive key loading.
    pub(crate) master_password: Option<String>,
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
            master_password: None,
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

    /// Inject the vault unlock password directly (preferred over the
    /// `PERSONA_MASTER_PASSWORD` env var, which lingers for the whole
    /// process lifetime once written).
    pub fn with_master_password(mut self, password: Option<String>) -> Self {
        self.master_password = password;
        self
    }

    /// Inject the require-confirm policy directly (preferred over the
    /// `PERSONA_AGENT_REQUIRE_CONFIRM` env var).
    pub fn with_require_confirm(self, value: bool) -> Self {
        if let Ok(mut policy_enforcer) = self.policy.lock() {
            policy_enforcer.set_require_confirm(value);
        }
        self
    }

    pub fn clone_shallow(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            policy: self.policy.clone(),
            biometric_provider: self.biometric_provider.clone(),
            approval_handler: self.approval_handler.clone(),
            // per-connection clones never need the password (keys are
            // already loaded at that point)
            master_password: None,
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
            // Host-injected password first (taken so it never outlives key
            // loading); env var stays the CLI fallback.
            let pass = self
                .master_password
                .take()
                .or_else(|| std::env::var("PERSONA_MASTER_PASSWORD").ok());
            match pass {
                Some(pass) => match service.authenticate_user(&pass).await? {
                    persona_core::auth::authentication::AuthResult::Success => {}
                    _ => {
                        unlocked = false;
                    }
                },
                None => {
                    unlocked = false;
                }
            }
        }
        if !unlocked {
            warn!("Vault is locked and no master password provided; no keys loaded");
            return Ok(());
        }
        let identities = service.get_identities().await?;
        // 身份过滤器（PERSONA_AGENT_IDENTITY，`persona ssh add-to-agent
        // --identity`）：设置后只加载该分身的 SSH 密钥。名字未知时不加载
        // 任何密钥（fail-closed，绝不回落全量加载——过滤器失配必须显式
        // 失败，而不是静默扩大注入面）。
        let identity_filter = std::env::var("PERSONA_AGENT_IDENTITY")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        if let Some(filter) = &identity_filter {
            if !identities.iter().any(|i| i.name == *filter) {
                warn!("SSH key filter: identity '{filter}' not found; no keys loaded");
                return Ok(());
            }
        }
        for id in identities {
            if let Some(filter) = &identity_filter {
                if id.name != *filter {
                    continue;
                }
            }
            let creds = service.get_credentials_for_identity(&id.id).await?;
            for cred in creds {
                if let CredentialType::SshKey = cred.credential_type {
                    if let Some(CredentialData::SshKey(ssh)) =
                        service.get_credential_data(&cred.id).await?
                    {
                        match agent_key_from_ssh_data(&ssh, &cred, &id.id) {
                            Ok(key) => self.keys.push(key),
                            Err(e) => {
                                warn!("Skipping SSH credential {}: {e}", cred.id);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn load_test_key_from_env(&mut self) -> persona_core::Result<bool> {
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
            signing_key: SigningKeyMaterial::Ed25519 { seed },
            identity_id: uuid::Uuid::new_v4(),
            credential_id: uuid::Uuid::new_v4(),
        });
        Ok(true)
    }

    pub(super) fn identities_answer(&self) -> Result<Vec<u8>> {
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

    pub(super) async fn sign_response(&self, mut payload: &[u8]) -> Result<Vec<u8>> {
        use byteorder::{BigEndian, ReadBytesExt};
        // sign_request payload: string key_blob, string data, flags(u32)
        let key_blob = read_ssh_string(&mut payload)?;
        let data_to_sign = read_ssh_string(&mut payload)?;
        // RFC 8332 flags: SSH_AGENT_RSA_SHA2_256 = 2, SSH_AGENT_RSA_SHA2_512 = 4
        let flags = payload.read_u32::<BigEndian>().unwrap_or(0);
        // Find key
        let key = self
            .keys
            .iter()
            .find(|k| k.public_blob == key_blob)
            .ok_or_else(|| anyhow::anyhow!("Key not found"))?;

        // Get target hostname
        let hostname = current_target_host();

        // 统一授权入口（架构校正批1）：agent 密钥的唯一动作是签名且只对
        // 自己的密钥——越权请求在此拒绝；主机规则/频率/确认计数等条件
        // 策略仍由下方 PolicyEnforcer 把守（机制层）。
        let entry = persona_core::authz::authorize(
            &persona_core::authz::AuthzPrincipal::AgentKey {
                credential_id: key.credential_id,
                identity_id: key.identity_id,
            },
            &persona_core::authz::AuthzResource::SshKey {
                credential_id: key.credential_id,
            },
            persona_core::authz::AuthzAction::Sign,
            &persona_core::authz::AuthzContext::AGENT,
        );
        if !entry.is_allowed() {
            warn!("Signature rejected at unified authz entry: {:?}", entry);
            return Ok(failure_packet());
        }

        // Policy enforcement using PolicyEnforcer: check + record happen
        // atomically under one lock (check/record split let concurrent
        // requests all pass the rate limits before any was booked). The
        // record is optimistic — the approval/biometric gates below may
        // still refuse, in which case we roll it back.
        // The guard is scoped so it never spans an await (MutexGuard is !Send).
        let decision = {
            let mut policy_enforcer = self
                .policy
                .lock()
                .map_err(|_| anyhow!("Policy lock poisoned"))?;
            policy_enforcer.check_and_record_signature(&key.credential_id, hostname.as_deref())?
        };
        // 裁决统一词汇落审计/日志：与 core/Connect/CLI 同一表达。
        info!("Signature policy decision: {:?}", decision.to_authz());

        // Roll back the optimistic policy record taken above. Used on every
        // gate-refusal path below (user denies confirmation, biometric
        // fails) so a refused signature does not consume rate-limit budget.
        macro_rules! refused {
            () => {{
                if let Ok(mut policy_enforcer) = self.policy.lock() {
                    policy_enforcer.rollback_signature(&key.credential_id, hostname.as_deref());
                }
            }};
        }

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
                        refused!();
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
                            refused!();
                            return Ok(failure_packet());
                        }
                        Err(e) => {
                            tracing::error!("Biometric authentication error: {}", e);
                            refused!();
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
                    refused!();
                    return Ok(failure_packet());
                }
            }
            SignatureDecision::Allowed => {
                // Proceed with signing
            }
        }

        // Per-algorithm signing; sig_blob carries the wire algorithm name
        let sig_blob = build_signature_blob(key, &data_to_sign, flags)?;
        // Audit sign operation (best-effort, include SHA256 of signed data)
        if let Err(e) = audit_sign_with_digest(&key.identity_id, &key.credential_id, &data_to_sign)
        {
            tracing::warn!("audit sign failed: {}", e);
        }
        // response: type(14) string sig_blob
        let mut out = Vec::new();
        out.push(14u8);
        write_ssh_string(&mut out, &sig_blob)?;
        Ok(wrap_packet(out))
    }
}

pub(super) fn audit_sign_with_digest(
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
