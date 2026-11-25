//! Generate SSH keypairs in-app: ed25519 / rsa-4096 / ecdsa-p256.
//!
//! The output is isomorphic to what import produces — the plaintext OpenSSH PEM
//! private key goes into the vault, with per-item key sealing left to the vault
//! layer; the field conventions (type name, algorithm name, fingerprint) reuse
//! ssh_import's mappings so both entry points yield identically shaped records.

use crate::{PersonaError, PersonaResult};
use ssh_key::private::{KeypairData, PrivateKey, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve};

/// Result of an in-app / CLI generation; fields match
/// [`super::ssh_import::ImportedSshKey`].
#[derive(Debug, Clone)]
pub struct GeneratedSshKey {
    /// In-app type name: `ed25519` / `rsa` / `ecdsa`.
    pub key_type: String,
    /// SSH wire-format algorithm name: `ssh-ed25519` / `ssh-rsa` /
    /// `ecdsa-sha2-nistp256`.
    pub ssh_algorithm: String,
    /// One-line OpenSSH public key (with comment, paste-ready for
    /// authorized_keys).
    pub public_key: String,
    /// SHA256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// Unencrypted OpenSSH PEM private key.
    pub private_key_pem: String,
    /// The comment written into the key.
    pub comment: String,
}

/// RSA is fixed at 4096 bits (the in-app stance; open it up if other sizes are
/// ever needed).
const RSA_BIT_SIZE: usize = 4096;

/// Generate a new keypair of the given type. `key_type`: `ed25519` (default) /
/// `rsa` / `ecdsa`.
pub fn generate_ssh_keypair(key_type: &str, comment: &str) -> PersonaResult<GeneratedSshKey> {
    let algorithm = match key_type {
        "ed25519" => Algorithm::Ed25519,
        "rsa" => Algorithm::Rsa { hash: None },
        "ecdsa" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        other => {
            return Err(PersonaError::InvalidInput(format!(
                "Unsupported SSH key type: {other}"
            )))
        }
    };

    // ssh-key does not route RSA through the unified PrivateKey::random path
    // (prime generation needs the rsa crate), so build KeypairData separately;
    // the comment is written afterwards in all cases.
    let mut key = if matches!(algorithm, Algorithm::Rsa { .. }) {
        let keypair =
            RsaKeypair::random(&mut rand_core::UnwrapErr(rand::rngs::SysRng), RSA_BIT_SIZE)
                .map_err(|e| PersonaError::CryptographicError(format!("RSA keygen failed: {e}")))?;
        PrivateKey::new(KeypairData::Rsa(keypair), comment)
            .map_err(|e| PersonaError::CryptographicError(format!("RSA keygen failed: {e}")))?
    } else {
        PrivateKey::random(&mut rand_core::UnwrapErr(rand::rngs::SysRng), algorithm)
            .map_err(|e| PersonaError::CryptographicError(format!("Keygen failed: {e}")))?
    };
    key.set_comment(comment);

    let (key_type, ssh_algorithm) = super::ssh_import::classify(key.algorithm())?;
    Ok(GeneratedSshKey {
        key_type: key_type.to_string(),
        ssh_algorithm: ssh_algorithm.to_string(),
        public_key: super::ssh_import::encode_public_line(&key)?,
        fingerprint: super::ssh_import::fingerprint_of(&key),
        private_key_pem: super::ssh_import::encode_private_pem(&key)?,
        comment: key.comment().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate-then-reparse round-trip consistency: each key type verifies
    /// type / algorithm / public-key line / fingerprint, with the reparsed
    /// public key as the independent judge of the fingerprint (the generation
    /// side does not grade its own homework).
    fn assert_roundtrip(generated: &GeneratedSshKey, expected_type: &str, expected_algo: &str) {
        assert_eq!(generated.key_type, expected_type);
        assert_eq!(generated.ssh_algorithm, expected_algo);
        assert!(generated
            .public_key
            .starts_with(&format!("{expected_algo} AAAA")));
        assert!(generated.fingerprint.starts_with("SHA256:"));
        assert!(generated
            .private_key_pem
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

        let reparsed = PrivateKey::from_openssh(&generated.private_key_pem).unwrap();
        assert!(!reparsed.key_data().is_encrypted());
        assert_eq!(reparsed.comment().as_str_lossy(), generated.comment);
        assert_eq!(
            reparsed
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            generated.fingerprint,
            "指纹必须与重解析公钥一致"
        );
        assert_eq!(
            reparsed.public_key().to_openssh().unwrap(),
            generated.public_key,
            "公钥行必须与重解析公钥一致"
        );
    }

    #[test]
    fn generates_ed25519_with_comment() {
        let generated = generate_ssh_keypair("ed25519", "cui@laptop").unwrap();
        assert_roundtrip(&generated, "ed25519", "ssh-ed25519");
        assert_eq!(generated.comment, "cui@laptop");
        // The comment lands in the public-key line (visible when pasted into
        // authorized_keys)
        assert!(generated.public_key.ends_with("cui@laptop"));
    }

    #[test]
    fn generates_rsa_4096() {
        let generated = generate_ssh_keypair("rsa", "rsa-test").unwrap();
        assert_roundtrip(&generated, "rsa", "ssh-rsa");
        // The modulus is exactly 4096 bits (512 bytes, with the top bit guaranteed
        // set by the generator)
        let n = reparsed_n_bytes(&generated);
        assert_eq!(n.len(), 512, "RSA modulus must be 4096-bit");
    }

    #[test]
    fn generates_ecdsa_p256() {
        let generated = generate_ssh_keypair("ecdsa", "ecdsa-test").unwrap();
        assert_roundtrip(&generated, "ecdsa", "ecdsa-sha2-nistp256");
    }

    #[test]
    fn rejects_unknown_key_type() {
        let err = generate_ssh_keypair("dsa", "x").unwrap_err();
        assert!(err.to_string().contains("Unsupported SSH key type: dsa"));
    }

    fn reparsed_n_bytes(generated: &GeneratedSshKey) -> Vec<u8> {
        let reparsed = PrivateKey::from_openssh(&generated.private_key_pem).unwrap();
        reparsed
            .key_data()
            .rsa()
            .unwrap()
            .public()
            .n()
            .as_positive_bytes()
            .unwrap()
            .to_vec()
    }
}
