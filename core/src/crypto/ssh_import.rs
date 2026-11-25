//! OpenSSH private key file import (`id_ed25519` / `id_rsa` / `id_ecdsa`).
//!
//! openssh-key-v1 container parsing, the bcrypt-pbkdf KDF, and aes*-ctr/cbc
//! decryption are delegated to the audited `ssh-key` crate; this module only
//! enforces the product conventions:
//!
//! - The passphrase unlocks at import time (`SshKeyData.passphrase` is set to
//!   `None` in the store) — once the private key is stored, the vault's
//!   per-item key seals it, and keeping the passphrase next to the ciphertext
//!   adds no security whatsoever, only an extra failure point in the agent's
//!   load chain;
//! - `private_key` stores the **unlocked OpenSSH PEM** (coexisting with the
//!   existing BASE64 seed convention for ed25519; see the dual-format loading
//!   in `agents/ssh-agent`);
//! - The fingerprint and public key line are echoed back in the import
//!   confirmation UI, and the key lands in the vault only after the user
//!   checks the fingerprint.

use crate::{PersonaError, PersonaResult};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding};

/// Import result: what storage needs (`private_key_pem`) plus what the
/// confirmation UI needs (fingerprint / type).
#[derive(Debug, Clone)]
pub struct ImportedSshKey {
    /// The vault's `SshKeyData.key_type` convention: `ed25519` / `rsa` / `ecdsa`.
    pub key_type: String,
    /// SSH wire-format algorithm name: `ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-nistp256`.
    pub ssh_algorithm: String,
    /// Single-line OpenSSH public key (`ssh-ed25519 AAAA… comment`), ready to paste into authorized_keys.
    pub public_key: String,
    /// SHA256 fingerprint (`SHA256:…`) for manual verification at import confirmation.
    pub fingerprint: String,
    /// The unlocked private key (plaintext OpenSSH PEM); storage seals it under the per-item key.
    pub private_key_pem: String,
    /// The comment from the original file (usable as the entry's default name).
    pub comment: String,
}

/// Pre-import preview: needs no passphrase (the OpenSSH container's public-key
/// half is plaintext, so even a protected key can show its fingerprint first
/// for human verification, before deciding whether to type the passphrase).
#[derive(Debug, Clone)]
pub struct SshKeyInspection {
    /// The vault's `SshKeyData.key_type` convention.
    pub key_type: String,
    /// SSH wire-format algorithm name.
    pub ssh_algorithm: String,
    /// Single-line OpenSSH public key.
    pub public_key: String,
    /// SHA256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// The comment from the original file.
    pub comment: String,
    /// Whether the key is passphrase-protected (a passphrase is needed at import).
    pub encrypted: bool,
}

/// Map ssh-key's algorithm classification onto the vault's conventions;
/// unsupported algorithms are uniformly rejected here.
pub(crate) fn classify(algorithm: Algorithm) -> PersonaResult<(&'static str, &'static str)> {
    Ok(match algorithm {
        Algorithm::Ed25519 => ("ed25519", "ssh-ed25519"),
        // 0.6.7's Rsa carries a hash field (for rsa-sha2-* certificate scenarios); the bare algorithm is plain rsa
        Algorithm::Rsa { .. } => ("rsa", "ssh-rsa"),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => ("ecdsa", "ecdsa-sha2-nistp256"),
        other => {
            return Err(PersonaError::InvalidInput(format!(
                "Unsupported SSH key algorithm: {other}"
            )))
        }
    })
}

/// Parse private key file content and return the fields needed for import —
/// format auto-detection across: the OpenSSH container (with bcrypt
/// passphrase unlocking), PKCS#8 (including PBES2 encryption), PKCS#1 RSA,
/// and SEC1 EC (P-256 only). PuTTY PPK and the like are explicitly unsupported.
///
/// `passphrase`: required when the key is passphrase-protected; a wrong
/// passphrase returns a clear error (no silent retry). For unprotected keys
/// either `None`/`Some(_)` is fine (a `Some` is ignored).
pub fn import_private_key_file(
    content: &str,
    passphrase: Option<&str>,
) -> PersonaResult<ImportedSshKey> {
    if let Some(note) = super::ssh_import_pem::unsupported_format_note(content) {
        return Err(PersonaError::InvalidInput(note));
    }
    let trimmed = content.trim_start();
    let key = if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        decode_openssh(content, passphrase)?
    } else if let Some(kind) = super::ssh_import_pem::sniff_pem(content) {
        super::ssh_import_pem::decode(kind, content, passphrase)?
    } else {
        return Err(unrecognized_format_error(content));
    };
    finish_import(key)
}

/// Unknown-format error: names the PEM header actually seen (so a user who
/// grabbed the wrong file can tell at a glance — public keys / certificates /
/// ssh.com formats each have their typical header), then lists every expected
/// format. The label comes from the user's own input, so echoing it back leaks
/// nothing; truncation guards against a malformed overlong line blowing up the message.
fn unrecognized_format_error(content: &str) -> PersonaError {
    const SUPPORTED: &str = "supported PEM headers: \"BEGIN OPENSSH PRIVATE KEY\", \
         \"BEGIN PRIVATE KEY\" (PKCS#8), \"BEGIN ENCRYPTED PRIVATE KEY\" (encrypted PKCS#8), \
         \"BEGIN RSA PRIVATE KEY\" (PKCS#1), \"BEGIN EC PRIVATE KEY\" (SEC1 EC); \
         algorithms: Ed25519, RSA, ECDSA P-256";

    let label = content
        .lines()
        .map(str::trim_start)
        .find_map(|l| l.strip_prefix("-----BEGIN "))
        .map(|rest| rest.split("-----").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut truncated: String = l.chars().take(64).collect();
            if l.chars().count() > 64 {
                truncated.push('…');
            }
            format!("-----BEGIN {truncated}-----")
        });

    match label {
        Some(header) => PersonaError::InvalidInput(format!(
            "Unrecognized private key file format: PEM header \"{header}\" is not supported \
             ({SUPPORTED})"
        )),
        None => PersonaError::InvalidInput(format!(
            "Unrecognized private key file format: not a PEM private key file ({SUPPORTED})"
        )),
    }
}

/// Pre-import preview (format auto-detection): can report fingerprint / type /
/// encrypted-ness without unlocking. The OpenSSH container works as usual (the
/// public-key half is plaintext); an encrypted PKCS#8 PEM has no plaintext
/// public-key half, so without a passphrase it errors out asking for one.
pub fn inspect_private_key_file(content: &str) -> PersonaResult<SshKeyInspection> {
    if let Some(note) = super::ssh_import_pem::unsupported_format_note(content) {
        return Err(PersonaError::InvalidInput(note));
    }
    let trimmed = content.trim_start();
    if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return inspect_openssh_private_key(content);
    }
    let key = match super::ssh_import_pem::sniff_pem(content) {
        Some(kind) => super::ssh_import_pem::decode(kind, content, None)?,
        None => return Err(unrecognized_format_error(content)),
    };
    let (key_type, ssh_algorithm) = classify(key.algorithm())?;

    Ok(SshKeyInspection {
        key_type: key_type.to_string(),
        ssh_algorithm: ssh_algorithm.to_string(),
        public_key: encode_public_line(&key)?,
        fingerprint: fingerprint_of(&key),
        comment: key.comment().to_string(),
        // A PEM that reached a successful preview is already plaintext (an encrypted one without a passphrase was rejected earlier)
        encrypted: false,
    })
}

/// Parse OpenSSH private key file content and return the fields needed for import.
///
/// `passphrase`: required when the key is passphrase-protected; a wrong
/// passphrase returns a clear error (no silent retry). For unprotected keys
/// either `None`/`Some(_)` is fine (a `Some` is ignored).
/// Unsupported algorithms (e.g. sk-* hardware keys) and malformed content
/// likewise return a clear error.
pub fn import_openssh_private_key(
    pem: &str,
    passphrase: Option<&str>,
) -> PersonaResult<ImportedSshKey> {
    let key = decode_openssh(pem, passphrase)?;
    finish_import(key)
}

/// OpenSSH container decoding + passphrase unlocking (shared between `import_openssh_private_key` and format dispatch).
fn decode_openssh(
    pem: &str,
    passphrase: Option<&str>,
) -> PersonaResult<ssh_key::private::PrivateKey> {
    let key = ssh_key::private::PrivateKey::from_openssh(pem.trim())
        .map_err(|e| PersonaError::InvalidInput(format!("Not a valid OpenSSH private key: {e}")))?;

    if key.key_data().is_encrypted() {
        let pass = passphrase.ok_or_else(|| {
            PersonaError::InvalidInput(
                "SSH key is passphrase-protected: passphrase required".to_string(),
            )
        })?;
        key.decrypt(pass)
            .map_err(|_| PersonaError::InvalidInput("SSH key passphrase is incorrect".to_string()))
    } else {
        Ok(key)
    }
}

/// Decode result → import payload (classify / public key line / fingerprint / storage PEM; shared by both entry points).
fn finish_import(key: ssh_key::private::PrivateKey) -> PersonaResult<ImportedSshKey> {
    let (key_type, ssh_algorithm) = classify(key.algorithm())?;
    let public_key = encode_public_line(&key)?;
    let fingerprint = fingerprint_of(&key);
    let private_key_pem = encode_private_pem(&key)?;

    Ok(ImportedSshKey {
        key_type: key_type.to_string(),
        ssh_algorithm: ssh_algorithm.to_string(),
        public_key,
        fingerprint,
        private_key_pem,
        comment: key.comment().to_string(),
    })
}

/// Pre-import preview: reports fingerprint / type / encrypted-ness without unlocking.
pub fn inspect_openssh_private_key(pem: &str) -> PersonaResult<SshKeyInspection> {
    let key = ssh_key::private::PrivateKey::from_openssh(pem.trim())
        .map_err(|e| PersonaError::InvalidInput(format!("Not a valid OpenSSH private key: {e}")))?;
    let encrypted = key.key_data().is_encrypted();
    let (key_type, ssh_algorithm) = classify(key.algorithm())?;

    Ok(SshKeyInspection {
        key_type: key_type.to_string(),
        ssh_algorithm: ssh_algorithm.to_string(),
        public_key: encode_public_line(&key)?,
        fingerprint: fingerprint_of(&key),
        comment: key.comment().to_string(),
        encrypted,
    })
}

pub(crate) fn encode_public_line(key: &ssh_key::private::PrivateKey) -> PersonaResult<String> {
    key.public_key().to_openssh().map_err(|e| {
        PersonaError::CryptographicError(format!("Failed to encode SSH public key: {e}"))
    })
}

/// Public key single line (`ssh-ed25519 AAAA… comment`) → (wire-format
/// algorithm name, SHA256 fingerprint, bit-size / curve label). For list /
/// detail display and fingerprint verification; a parse failure returns None
/// (the caller shows an empty column rather than erroring).
///
/// Label conventions: Ed25519 → `256`, RSA → decimal modulus bit size,
/// ECDSA → the `P-256`-style curve name, DSA → prime bit length; SK hardware
/// keys follow their inner algorithm, while certificate / opaque containers
/// are not applicable and yield None.
pub fn describe_public_key_line(line: &str) -> Option<(String, String, Option<String>)> {
    let pk = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
    Some((
        pk.algorithm().to_string(),
        pk.fingerprint(HashAlg::Sha256).to_string(),
        key_size_label(pk.key_data()),
    ))
}

/// Bit-size / curve label (display-only convention, used in no validation).
fn key_size_label(key_data: &ssh_key::public::KeyData) -> Option<String> {
    match key_data {
        ssh_key::public::KeyData::Ed25519(_) | ssh_key::public::KeyData::SkEd25519(_) => {
            Some("256".to_string())
        }
        ssh_key::public::KeyData::Rsa(rsa) => Some(rsa.key_size().to_string()),
        ssh_key::public::KeyData::Ecdsa(ecdsa) => Some(
            match ecdsa.curve() {
                EcdsaCurve::NistP256 => "P-256",
                EcdsaCurve::NistP384 => "P-384",
                EcdsaCurve::NistP521 => "P-521",
            }
            .to_string(),
        ),
        ssh_key::public::KeyData::SkEcdsaSha2NistP256(_) => Some("P-256".to_string()),
        ssh_key::public::KeyData::Dsa(dsa) => Some(mpint_bits(dsa.p()).to_string()),
        // Certificate / opaque containers: the algorithm name is still displayable, the bit size is not applicable
        _ => None,
    }
}

/// Bit length of a positive-integer Mpint (`as_positive_bytes` strips the sign-zero bytes, so the first byte is necessarily nonzero).
fn mpint_bits(n: &ssh_key::Mpint) -> u32 {
    let Some(bytes) = n.as_positive_bytes() else {
        return 0;
    };
    (bytes.len() as u32 - 1) * 8 + (8 - bytes[0].leading_zeros())
}

pub(crate) fn fingerprint_of(key: &ssh_key::private::PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

pub(crate) fn encode_private_pem(key: &ssh_key::private::PrivateKey) -> PersonaResult<String> {
    key.to_openssh(LineEnding::LF)
        .map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to encode SSH private key: {e}"))
        })
        .map(|pem| pem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::private::PrivateKey;
    use ssh_key::Algorithm;

    /// Bootstraps the three kinds of test keys: ssh-key itself acts as both
    /// generator and parser, and the assertions follow this module's product
    /// conventions (unlocking, field integrity, fingerprint format).
    fn generate_pem(algorithm: Algorithm) -> String {
        let key =
            PrivateKey::random(&mut rand_core::UnwrapErr(rand::rngs::SysRng), algorithm).unwrap();
        key.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    fn generate_encrypted_pem(algorithm: Algorithm, passphrase: &str) -> String {
        let key =
            PrivateKey::random(&mut rand_core::UnwrapErr(rand::rngs::SysRng), algorithm).unwrap();
        key.encrypt(&mut rand_core::UnwrapErr(rand::rngs::SysRng), passphrase)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn imports_plain_ed25519() {
        let pem = generate_pem(Algorithm::Ed25519);
        let imported = import_openssh_private_key(&pem, None).unwrap();
        assert_eq!(imported.key_type, "ed25519");
        assert_eq!(imported.ssh_algorithm, "ssh-ed25519");
        assert!(imported.public_key.starts_with("ssh-ed25519 AAAA"));
        assert!(imported.fingerprint.starts_with("SHA256:"));
        // The unlocked PEM must re-parse cleanly (round-trip consistency) and no longer be an encrypted container
        let reparsed = PrivateKey::from_openssh(&imported.private_key_pem).unwrap();
        assert!(!reparsed.key_data().is_encrypted());
    }

    #[test]
    fn imports_plain_rsa() {
        let pem = generate_pem(Algorithm::Rsa { hash: None });
        let imported = import_openssh_private_key(&pem, None).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert_eq!(imported.ssh_algorithm, "ssh-rsa");
        assert!(imported.public_key.starts_with("ssh-rsa AAAA"));
        assert!(imported.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn imports_plain_ecdsa_p256() {
        let pem = generate_pem(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        });
        let imported = import_openssh_private_key(&pem, None).unwrap();
        assert_eq!(imported.key_type, "ecdsa");
        assert_eq!(imported.ssh_algorithm, "ecdsa-sha2-nistp256");
        assert!(imported.public_key.starts_with("ecdsa-sha2-nistp256 AAAA"));
    }

    #[test]
    fn encrypted_key_without_passphrase_is_rejected() {
        let pem = generate_encrypted_pem(Algorithm::Ed25519, "hunter2");
        let err = import_openssh_private_key(&pem, None).unwrap_err();
        assert!(err.to_string().contains("passphrase required"), "{err}");
    }

    #[test]
    fn encrypted_key_wrong_passphrase_is_rejected() {
        let pem = generate_encrypted_pem(Algorithm::Ed25519, "hunter2");
        let err = import_openssh_private_key(&pem, Some("wrong")).unwrap_err();
        assert!(err.to_string().contains("incorrect"), "{err}");
    }

    #[test]
    fn encrypted_key_unlocks_with_passphrase() {
        let pem = generate_encrypted_pem(Algorithm::Rsa { hash: None }, "hunter2");
        let imported = import_openssh_private_key(&pem, Some("hunter2")).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert!(imported.fingerprint.starts_with("SHA256:"));
        let reparsed = PrivateKey::from_openssh(&imported.private_key_pem).unwrap();
        assert!(!reparsed.key_data().is_encrypted());
    }

    #[test]
    fn comment_is_preserved() {
        let mut key = PrivateKey::random(
            &mut rand_core::UnwrapErr(rand::rngs::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        key.set_comment("cui@laptop");
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        let imported = import_openssh_private_key(&pem, None).unwrap();
        assert_eq!(imported.comment, "cui@laptop");
        assert!(imported.public_key.ends_with("cui@laptop"));
    }

    #[test]
    fn garbage_input_is_rejected() {
        let err = import_openssh_private_key("not a key at all", None).unwrap_err();
        assert!(
            err.to_string().contains("Not a valid OpenSSH private key"),
            "{err}"
        );
    }

    #[test]
    fn public_pem_is_rejected() {
        // A public key is not a private-key container and must be rejected at the parse layer (a clear message for users who grabbed the wrong file)
        let key = PrivateKey::random(
            &mut rand_core::UnwrapErr(rand::rngs::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        let pub_line = key.public_key().to_openssh().unwrap();
        assert!(import_openssh_private_key(&pub_line, None).is_err());
    }

    #[test]
    fn fingerprint_matches_ssh_key_crate() {
        let pem = generate_pem(Algorithm::Ed25519);
        let key = PrivateKey::from_openssh(&pem).unwrap();
        let expected = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let imported = import_openssh_private_key(&pem, None).unwrap();
        assert_eq!(imported.fingerprint, expected);
        assert_eq!(imported.public_key, key.public_key().to_openssh().unwrap());
    }

    #[test]
    fn inspect_works_without_unlocking_encrypted_key() {
        // The OpenSSH container's public-key half is plaintext: a protected key
        // can show its fingerprint without a passphrase, and the user verifies
        // the fingerprint first before deciding whether to enter the passphrase
        let pem = generate_encrypted_pem(Algorithm::Ed25519, "hunter2");
        let inspection = inspect_openssh_private_key(&pem).unwrap();
        assert!(inspection.encrypted);
        assert_eq!(inspection.key_type, "ed25519");
        assert!(inspection.fingerprint.starts_with("SHA256:"));
        assert!(inspection.public_key.starts_with("ssh-ed25519 AAAA"));

        // The unlocked fingerprint matches the preview (same key)
        let imported = import_openssh_private_key(&pem, Some("hunter2")).unwrap();
        assert_eq!(imported.fingerprint, inspection.fingerprint);
        assert_eq!(imported.public_key, inspection.public_key);
    }

    #[test]
    fn inspect_plain_key_reports_not_encrypted() {
        let pem = generate_pem(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        });
        let inspection = inspect_openssh_private_key(&pem).unwrap();
        assert!(!inspection.encrypted);
        assert_eq!(inspection.key_type, "ecdsa");
        assert_eq!(inspection.ssh_algorithm, "ecdsa-sha2-nistp256");
    }

    #[test]
    fn inspect_rejects_garbage() {
        assert!(inspect_openssh_private_key("garbage").is_err());
    }

    #[test]
    fn unrecognized_format_error_names_the_header() {
        // The most common wrong-file grab: a certificate / public key rather than a private key — the error names the header actually seen
        let err = import_private_key_file(
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("\"-----BEGIN CERTIFICATE-----\""), "{msg}");
        assert!(msg.contains("is not supported"), "{msg}");
        // The expected-format roster is still listed
        assert!(msg.contains("BEGIN OPENSSH PRIVATE KEY"), "{msg}");
        assert!(msg.contains("BEGIN EC PRIVATE KEY"), "{msg}");

        // OpenSSL legacy DSA (a strict PEM header with an unsupported algorithm) is likewise named
        let err = import_private_key_file(
            "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----",
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("\"-----BEGIN DSA PRIVATE KEY-----\""),
            "{err}"
        );

        // A file with no PEM header at all: plainly not a PEM private key file (PPK gets its dedicated hint intercepted earlier)
        let err = inspect_private_key_file("random binary bytes").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a PEM private key file"), "{msg}");
        assert!(msg.contains("BEGIN RSA PRIVATE KEY"), "{msg}");
    }

    #[test]
    fn describe_public_key_reports_size_and_curve() {
        // Ed25519: fixed bit length 256
        let ed = PrivateKey::from_openssh(generate_pem(Algorithm::Ed25519)).unwrap();
        let (algo, fp, size) =
            describe_public_key_line(&ed.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ssh-ed25519");
        assert_eq!(fp, ed.public_key().fingerprint(HashAlg::Sha256).to_string());
        assert_eq!(size.as_deref(), Some("256"));

        // RSA: modulus bit size (cross-validated against the private key's own key_size)
        let rsa = PrivateKey::from_openssh(generate_pem(Algorithm::Rsa { hash: None })).unwrap();
        let expected_bits = match rsa.key_data() {
            ssh_key::private::KeypairData::Rsa(rsa) => rsa.key_size().to_string(),
            other => panic!("expected rsa keypair, got {other:?}"),
        };
        let (algo, _, size) =
            describe_public_key_line(&rsa.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ssh-rsa");
        assert_eq!(size.as_deref(), Some(expected_bits.as_str()));

        // ECDSA: curve label
        let ecdsa = PrivateKey::from_openssh(generate_pem(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }))
        .unwrap();
        let (algo, _, size) =
            describe_public_key_line(&ecdsa.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ecdsa-sha2-nistp256");
        assert_eq!(size.as_deref(), Some("P-256"));

        // Garbage input → None (the caller shows an empty column rather than erroring)
        assert!(describe_public_key_line("not a key").is_none());
    }
}
