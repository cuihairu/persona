use super::*;

/// 签名私钥材料。ed25519 走库内既有约定（`SshKeyData.private_key` =
/// BASE64(32B seed)）；导入的 OpenSSH 私钥（rsa / ecdsa / ed25519 PEM）
/// 在加载时解出原始组件，签名时按算法分派。
#[derive(Clone)]
pub enum SigningKeyMaterial {
    /// ed25519 seed（既有约定与导入的 PEM 统一归一到这里）。
    Ed25519 { seed: [u8; 32] },
    /// RSA（PKCS#1 v1.5，rsa-sha2-256/512 按 RFC 8332 客户端 flags 分派）。
    Rsa(Arc<rsa::RsaPrivateKey>),
    /// ECDSA NIST P-256（ecdsa-sha2-nistp256，确定性 RFC 6979 签名）。
    EcdsaP256(p256::ecdsa::SigningKey),
}

#[derive(Clone)]
pub struct AgentKey {
    pub public_blob: Vec<u8>, // OpenSSH key blob
    pub comment: String,
    pub signing_key: SigningKeyMaterial,
    pub identity_id: uuid::Uuid,
    pub credential_id: uuid::Uuid,
}

/// OpenSSH 公钥单行（`ssh-ed25519 AAAA… [comment]` 等）→ 线格式 blob。
/// ssh-key 解析器对三种算法统一处理，顺带校验行格式（畸形行返回 None）。
pub(super) fn parse_public_line_to_blob(s: &str) -> Option<Vec<u8>> {
    let public = ssh_key::PublicKey::from_openssh(s.trim()).ok()?;
    public.to_bytes().ok()
}

/// 库内 SshKey 条目 → AgentKey。私钥双格式：既有约定 BASE64(32B seed)
/// 优先；其余（导入的 OpenSSH PEM，含 rsa/ecdsa）走 PEM 解析。
/// 公钥行与私钥算法不一致时以解析出的私钥为准重建公钥 blob，避免
/// 库内字段被改坏后 agent 通告错误公钥。
pub(super) fn agent_key_from_ssh_data(
    ssh: &persona_core::models::SshKeyData,
    cred: &persona_core::models::Credential,
    identity_id: &uuid::Uuid,
) -> Result<AgentKey> {
    let signing_key =
        parse_signing_key(&ssh.private_key).map_err(|e| anyhow!("credential {}: {e}", cred.id))?;

    // 公钥 blob：优先用库内公钥行；与私钥算法不符/行畸形时从私钥重建
    let public_blob = match parse_public_line_to_blob(&ssh.public_key) {
        Some(blob) => blob,
        None => public_blob_from_signing_key(&signing_key)?,
    };
    if public_key_algorithm(&public_blob).as_deref() != Some(signing_key.algorithm_name()) {
        warn!(
            "credential {}: public key algorithm mismatch, rebuilding from private key",
            cred.id
        );
        return public_blob_from_signing_key(&signing_key).map(|blob| AgentKey {
            public_blob: blob,
            comment: cred.name.clone(),
            signing_key,
            identity_id: *identity_id,
            credential_id: cred.id,
        });
    }

    Ok(AgentKey {
        public_blob,
        comment: cred.name.clone(),
        signing_key,
        identity_id: *identity_id,
        credential_id: cred.id,
    })
}

impl SigningKeyMaterial {
    /// SSH 线格式算法名（签名 blob 与公钥 blob 共用）。
    pub(super) fn algorithm_name(&self) -> &'static str {
        match self {
            SigningKeyMaterial::Ed25519 { .. } => "ssh-ed25519",
            SigningKeyMaterial::Rsa(_) => "ssh-rsa",
            SigningKeyMaterial::EcdsaP256(_) => "ecdsa-sha2-nistp256",
        }
    }
}

/// 私钥文本（BASE64 seed 或 OpenSSH PEM）→ 签名材料。
pub(super) fn parse_signing_key(private_key: &str) -> Result<SigningKeyMaterial> {
    use ssh_key::private::{KeypairData, PrivateKey};

    // 既有约定：BASE64(32B ed25519 seed)。带 '-' 的 PEM 头不可能过 base64 解码。
    if let Ok(bytes) = BASE64.decode(private_key.trim()) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(SigningKeyMaterial::Ed25519 { seed });
        }
    }

    let key = PrivateKey::from_openssh(private_key.trim())
        .map_err(|e| anyhow!("private key is neither a 32-byte seed nor an OpenSSH PEM: {e}"))?;
    if key.key_data().is_encrypted() {
        return Err(anyhow!(
            "private key is still passphrase-encrypted; re-import with the passphrase"
        ));
    }
    match key.key_data() {
        KeypairData::Ed25519(kp) => Ok(SigningKeyMaterial::Ed25519 {
            seed: kp.private.to_bytes(),
        }),
        KeypairData::Rsa(kp) => {
            let mpint_to_biguint = |m: &ssh_key::Mpint| -> Result<rsa::BigUint> {
                m.as_positive_bytes()
                    .map(rsa::BigUint::from_bytes_be)
                    .ok_or_else(|| anyhow!("negative RSA component is not valid"))
            };
            let n = mpint_to_biguint(kp.public().n())?;
            let e = mpint_to_biguint(kp.public().e())?;
            let d = mpint_to_biguint(kp.private().d())?;
            let p = mpint_to_biguint(kp.private().p())?;
            let q = mpint_to_biguint(kp.private().q())?;
            let mut private = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])?;
            private.precompute()?;
            Ok(SigningKeyMaterial::Rsa(Arc::new(private)))
        }
        KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 { private, .. }) => {
            let secret = p256::SecretKey::from_slice(private.as_slice())
                .map_err(|e| anyhow!("invalid P-256 private scalar: {e}"))?;
            Ok(SigningKeyMaterial::EcdsaP256(secret.into()))
        }
        _ => Err(anyhow!(
            "unsupported SSH key algorithm: {}",
            key.algorithm()
        )),
    }
}

fn public_blob_from_signing_key(signing_key: &SigningKeyMaterial) -> Result<Vec<u8>> {
    match signing_key {
        SigningKeyMaterial::Ed25519 { seed } => {
            use ed25519_dalek::SigningKey;
            let pub_bytes = SigningKey::from_bytes(seed).verifying_key().to_bytes();
            let mut blob = Vec::new();
            write_ssh_string(&mut blob, b"ssh-ed25519")?;
            write_ssh_string(&mut blob, &pub_bytes)?;
            Ok(blob)
        }
        SigningKeyMaterial::Rsa(private) => {
            use rsa::traits::PublicKeyParts;
            let public = private.to_public_key();
            let mut blob = Vec::new();
            write_ssh_string(&mut blob, b"ssh-rsa")?;
            write_mpint(&mut blob, &public.n().to_bytes_be());
            write_mpint(&mut blob, &public.e().to_bytes_be());
            Ok(blob)
        }
        SigningKeyMaterial::EcdsaP256(signing) => {
            let verifying = signing.verifying_key();
            let mut blob = Vec::new();
            write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256")?;
            write_ssh_string(&mut blob, b"nistp256")?;
            // 非压缩 SEC1 点（65B，0x04 || X || Y），SSH 线格式约定
            write_ssh_string(&mut blob, verifying.to_sec1_point(false).as_bytes())?;
            Ok(blob)
        }
    }
}

/// 公钥 blob 的算法名（第一个 ssh string）。
pub(super) fn public_key_algorithm(blob: &[u8]) -> Option<String> {
    let mut slice: &[u8] = blob;
    let algo = read_ssh_string(&mut slice).ok()?;
    String::from_utf8(algo).ok()
}

/// 按算法分派签名并组线格式签名 blob：
/// string algorithm, string signature。
/// - ed25519：raw 64B R||S
/// - RSA（RFC 8332）：客户端 flags 要 sha2-256 用之，其余（含 sha2-512
///   flag）用 sha2-512；SHA-1 的 `ssh-rsa` 签名不再产出（OpenSSH ≥8.8
///   已默认禁用，且 SHA-1 签名是弱化路径）
/// - ECDSA P-256：mpint r || mpint s
pub(super) fn build_signature_blob(key: &AgentKey, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;

    let (algo, signature): (&str, Vec<u8>) = match &key.signing_key {
        SigningKeyMaterial::Ed25519 { seed } => {
            use ed25519_dalek::{Signer, SigningKey};
            let sig = SigningKey::from_bytes(seed).sign(data);
            ("ssh-ed25519", sig.to_bytes().to_vec())
        }
        SigningKeyMaterial::Rsa(private) => {
            if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                rsa_sign::<rsa::sha2::Sha256>(private, "rsa-sha2-256", data)?
            } else {
                rsa_sign::<rsa::sha2::Sha512>(private, "rsa-sha2-512", data)?
            }
        }
        SigningKeyMaterial::EcdsaP256(signing) => {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = signing.sign(data);
            let mut signature = Vec::new();
            write_mpint(&mut signature, sig.r().to_bytes().as_slice());
            write_mpint(&mut signature, sig.s().to_bytes().as_slice());
            ("ecdsa-sha2-nistp256", signature)
        }
    };

    let mut sig_blob = Vec::new();
    write_ssh_string(&mut sig_blob, algo.as_bytes())?;
    write_ssh_string(&mut sig_blob, &signature)?;
    Ok(sig_blob)
}

/// PKCS#1 v1.5 签名（确定性，无 RNG），返回裸签名字节。
fn rsa_sign<D>(
    private: &rsa::RsaPrivateKey,
    algo: &'static str,
    data: &[u8],
) -> Result<(&'static str, Vec<u8>)>
where
    D: rsa::sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    let signing = SigningKey::<D>::new(private.clone());
    let sig = signing.sign(data);
    Ok((algo, sig.to_vec()))
}

/// RFC 4251 mpint：去前导零、高位为 1 时补 0x00、零编码为空串。
fn write_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[first..];
    let pad = usize::from(stripped.first().is_some_and(|b| b & 0x80 != 0));
    buf.extend_from_slice(&((stripped.len() + pad) as u32).to_be_bytes());
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf.extend_from_slice(stripped);
}
