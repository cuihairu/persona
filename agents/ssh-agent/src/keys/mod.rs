use super::*;

/// Private key material used for signing. ed25519 follows the library's
/// existing convention (`SshKeyData.private_key` = BASE64(32B seed));
/// imported OpenSSH private keys (rsa / ecdsa / ed25519 PEM) have their
/// raw components resolved at load time, and signing dispatches by algorithm.
#[derive(Clone)]
pub enum SigningKeyMaterial {
    /// ed25519 seed (the existing convention and imported PEMs both
    /// normalize into this form).
    Ed25519 { seed: [u8; 32] },
    /// RSA (PKCS#1 v1.5; rsa-sha2-256/512 selected by the RFC 8332 client
    /// flags).
    Rsa(Arc<rsa::PrivateKey>),
    /// ECDSA NIST P-256 (ecdsa-sha2-nistp256, deterministic RFC 6979
    /// signatures).
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

/// Single-line OpenSSH public key (`ssh-ed25519 AAAA… [comment]` etc.) ->
/// wire-format blob. The ssh-key parser handles all three algorithms
/// uniformly and validates the line format in passing (malformed lines
/// return None).
pub(super) fn parse_public_line_to_blob(s: &str) -> Option<Vec<u8>> {
    let public = ssh_key::PublicKey::from_openssh(s.trim()).ok()?;
    public.to_bytes().ok()
}

/// In-library SshKey entry -> AgentKey. Private keys come in two formats:
/// the existing BASE64(32B seed) convention takes priority; anything else
/// (imported OpenSSH PEM, including rsa/ecdsa) goes through PEM parsing.
/// When the public key line disagrees with the private key's algorithm, the
/// public blob is rebuilt from the parsed private key, so a corrupted
/// in-library field cannot make the agent announce a wrong public key.
pub(super) fn agent_key_from_ssh_data(
    ssh: &persona_core::models::SshKeyData,
    cred: &persona_core::models::Credential,
    identity_id: &uuid::Uuid,
) -> Result<AgentKey> {
    let signing_key =
        parse_signing_key(&ssh.private_key).map_err(|e| anyhow!("credential {}: {e}", cred.id))?;

    // Public blob: prefer the in-library public key line; rebuild it from
    // the private key when the algorithm mismatches or the line is malformed
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
    /// SSH wire-format algorithm name (shared by signature blobs and public
    /// key blobs).
    pub(super) fn algorithm_name(&self) -> &'static str {
        match self {
            SigningKeyMaterial::Ed25519 { .. } => "ssh-ed25519",
            SigningKeyMaterial::Rsa(_) => "ssh-rsa",
            SigningKeyMaterial::EcdsaP256(_) => "ecdsa-sha2-nistp256",
        }
    }
}

/// Private key text (BASE64 seed or OpenSSH PEM) -> signing material.
pub(super) fn parse_signing_key(private_key: &str) -> Result<SigningKeyMaterial> {
    use ssh_key::private::{KeypairData, PrivateKey};

    // Existing convention: BASE64(32B ed25519 seed). A PEM header containing
    // '-' can never survive base64 decoding.
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
            let mpint_to_uint = |m: &ssh_key::Mpint| -> Result<rsa::BoxedUint> {
                let bytes = m
                    .as_positive_bytes()
                    .ok_or_else(|| anyhow!("negative RSA component is not valid"))?;
                Ok(rsa::BoxedUint::from_be_slice_vartime(bytes))
            };
            let n = mpint_to_uint(kp.public().n())?;
            let e = mpint_to_uint(kp.public().e())?;
            let d = mpint_to_uint(kp.private().d())?;
            let p = mpint_to_uint(kp.private().p())?;
            let q = mpint_to_uint(kp.private().q())?;
            // rsa 0.10's from_components validates and precomputes internally.
            let private = rsa::PrivateKey::from_components(n, e, d, vec![p, q])?;
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
            write_mpint(&mut blob, &public.n().to_be_bytes());
            write_mpint(&mut blob, &public.e().to_be_bytes());
            Ok(blob)
        }
        SigningKeyMaterial::EcdsaP256(signing) => {
            let verifying = signing.verifying_key();
            let mut blob = Vec::new();
            write_ssh_string(&mut blob, b"ecdsa-sha2-nistp256")?;
            write_ssh_string(&mut blob, b"nistp256")?;
            // Uncompressed SEC1 point (65B, 0x04 || X || Y), the SSH
            // wire-format convention
            write_ssh_string(&mut blob, verifying.to_sec1_point(false).as_bytes())?;
            Ok(blob)
        }
    }
}

/// Algorithm name of a public key blob (the first ssh string).
pub(super) fn public_key_algorithm(blob: &[u8]) -> Option<String> {
    let mut slice: &[u8] = blob;
    let algo = read_ssh_string(&mut slice).ok()?;
    String::from_utf8(algo).ok()
}

/// Dispatch signing by algorithm and assemble a wire-format signature blob:
/// string algorithm, string signature.
/// - ed25519: raw 64B R||S
/// - RSA (RFC 8332): use sha2-256 when the client flags ask for it, sha2-512
///   otherwise (including the sha2-512 flag); SHA-1 `ssh-rsa` signatures are
///   no longer produced (OpenSSH >= 8.8 disables them by default, and SHA-1
///   signatures are a weakened path)
/// - ECDSA P-256: mpint r || mpint s
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

/// PKCS#1 v1.5 signature (deterministic, no RNG), returns the raw signature
/// bytes.
fn rsa_sign<D>(
    private: &rsa::PrivateKey,
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

/// RFC 4251 mpint: strip leading zeros, pad a 0x00 when the high bit is 1,
/// and encode zero as an empty string.
fn write_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[first..];
    let pad = usize::from(stripped.first().is_some_and(|b| b & 0x80 != 0));
    buf.extend_from_slice(&((stripped.len() + pad) as u32).to_be_bytes());
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf.extend_from_slice(stripped);
}
