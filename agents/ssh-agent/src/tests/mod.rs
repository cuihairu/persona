use super::*;
use std::path::Path;
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
            signing_key: SigningKeyMaterial::Ed25519 { seed },
            identity_id: uuid::Uuid::new_v4(),
            credential_id: uuid::Uuid::new_v4(),
        },
        verifying,
    )
}

/// 从 AgentKey 里取 ed25519 seed（测试断言用）。
fn key_seed(key: &AgentKey) -> [u8; 32] {
    match &key.signing_key {
        SigningKeyMaterial::Ed25519 { seed } => *seed,
        other => panic!("expected ed25519 key, got {}", other.algorithm_name()),
    }
}
fn clear_test_key_env() {
    std::env::remove_var("PERSONA_AGENT_TEST_KEY_SEED");
    std::env::remove_var("PERSONA_AGENT_TEST_KEY_COMMENT");
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
/// 测试夹具：建一个身份并挂一枚 SSH 密钥，返回身份 id。
async fn seed_identity_ssh_key(
    service: &mut persona_core::PersonaService,
    name: &str,
    seed: [u8; 32],
) -> uuid::Uuid {
    let identity = service
        .create_identity(
            name.to_string(),
            persona_core::models::IdentityType::Personal,
        )
        .await
        .unwrap();
    let (pub_line, _) = openssh_pub_line(seed);
    service
        .create_credential(
            identity.id,
            format!("{name} ssh key"),
            persona_core::models::CredentialType::SshKey,
            persona_core::models::SecurityLevel::High,
            &ssh_credential_data(seed, &pub_line),
        )
        .await
        .unwrap();
    identity.id
}
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
// ------------------------------------------------------------------

fn pem_credential_data(
    private: &str,
    public: &str,
    key_type: &str,
) -> persona_core::models::CredentialData {
    persona_core::models::CredentialData::SshKey(persona_core::models::SshKeyData {
        private_key: private.to_string(),
        public_key: public.to_string(),
        key_type: key_type.to_string(),
        passphrase: None,
    })
}

async fn seed_vault_with_ssh_credentials(
    db_path: &Path,
    entries: Vec<(&str, persona_core::models::CredentialData)>,
) {
    let db = persona_core::Database::from_file(&db_path.to_path_buf())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let mut service = persona_core::PersonaService::new(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let identity = service
        .create_identity(
            "agent-pem".to_string(),
            persona_core::models::IdentityType::Personal,
        )
        .await
        .unwrap();
    for (name, data) in entries {
        service
            .create_credential(
                identity.id,
                name.to_string(),
                persona_core::models::CredentialType::SshKey,
                persona_core::models::SecurityLevel::High,
                &data,
            )
            .await
            .unwrap();
    }
}

/// 从签名响应里解出 (算法名, 裸签名字节)。
fn parse_signature_blob(pkt: &[u8]) -> (String, Vec<u8>) {
    assert_eq!(pkt[4], 14u8, "signature response");
    let mut slice: &[u8] = &pkt[5..];
    let sig_blob = read_ssh_string(&mut slice).unwrap();
    let mut s: &[u8] = &sig_blob;
    let algo = String::from_utf8(read_ssh_string(&mut s).unwrap()).unwrap();
    (algo, read_ssh_string(&mut s).unwrap())
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

mod audit;
mod context;
mod core;
mod keys;
mod pem;
mod protocol;
mod sign;
