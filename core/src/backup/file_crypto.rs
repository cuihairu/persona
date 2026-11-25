//! PERSENC1 byte encryption: byte-level interoperable with the CLI
//! `--encrypt` export files.
//!
//! Format (ported verbatim from the CLI `utils/file_crypto`; the byte layout
//! must not change):
//! `[magic:8]"PERSENC1" [salt_len:1][salt] [nonce_len:1][nonce]
//! [kdf mem_kib:4 LE] [enc_len:8 LE] [ciphertext...]`
//!
//! KDF: Argon2id (salt is a random 16B, key is 32B; the decrypt side reads
//! only mem_kib from the header — iterations/parallelism are fixed at 3/1,
//! that is what the legacy format dictates and we stay compatible).
//! Encryption: AES-256-GCM (12B nonce).

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"PERSENC1";

/// Argon2id parameters (only mem_kib is written to the header; see the module
/// comment).
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

/// Whether this is PERSENC1 ciphertext (magic detection; the restore path
/// probes first, then decrypts).
pub fn is_persona_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// Encrypt arbitrary bytes (backup chain: the plaintext is always a gzipped
/// snapshot; export chain: file contents).
pub fn encrypt_bytes(
    plaintext: &[u8],
    passphrase: &str,
    kdf: Option<KdfParams>,
) -> Result<Vec<u8>> {
    let kdf_params = kdf.unwrap_or_default();

    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);

    let argon = argon2(
        kdf_params.mem_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
    )?;
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derive error: {:?}", e))?;

    let cipher = Aes256Gcm::new((&key).into());
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    let mut out = Vec::with_capacity(
        MAGIC.len() + 1 + salt.len() + 1 + nonce.len() + 4 + 8 + ciphertext.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(salt.len() as u8);
    out.extend_from_slice(&salt);
    out.push(nonce.len() as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&kdf_params.mem_kib.to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    key.zeroize();
    Ok(out)
}

/// Decrypt PERSENC1 bytes; a wrong passphrase or a corrupted file both error
/// out (GCM authentication failure).
pub fn decrypt_bytes(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        anyhow::bail!("Not a Persona encrypted file");
    }
    cursor += MAGIC.len();
    let salt_len = *data.get(cursor).ok_or_else(|| anyhow!("Bad header"))? as usize;
    cursor += 1;
    let salt = data
        .get(cursor..cursor + salt_len)
        .ok_or_else(|| anyhow!("Bad header salt"))?;
    cursor += salt_len;
    let nonce_len = *data.get(cursor).ok_or_else(|| anyhow!("Bad header"))? as usize;
    cursor += 1;
    let nonce = data
        .get(cursor..cursor + nonce_len)
        .ok_or_else(|| anyhow!("Bad header nonce"))?;
    cursor += nonce_len;
    let mem_kib = u32::from_le_bytes(
        data.get(cursor..cursor + 4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| anyhow!("Bad header kdf"))?,
    );
    cursor += 4;
    let enc_len = u64::from_le_bytes(
        data.get(cursor..cursor + 8)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| anyhow!("Bad header len"))?,
    ) as usize;
    cursor += 8;
    // checked_add: enc_len is a u64 straight from the file (untrusted), and
    // `cursor + enc_len` could overflow usize and panic in debug builds (a
    // DoS); check first, slice second.
    let ciphertext_end = cursor
        .checked_add(enc_len)
        .ok_or_else(|| anyhow!("Bad ciphertext len"))?;
    let ciphertext = data
        .get(cursor..ciphertext_end)
        .ok_or_else(|| anyhow!("Bad ciphertext len"))?;

    // Legacy format: on the decrypt side iterations/parallelism are fixed at
    // 3/1 (the header only stores mem_kib)
    let argon = argon2(mem_kib, 3, 1)?;
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derive error: {:?}", e))?;

    let cipher = Aes256Gcm::new((&key).into());
    let nonce_arr: &[u8; 12] = nonce.try_into().map_err(|_| anyhow!("Bad nonce length"))?;
    let plaintext = cipher
        .decrypt(nonce_arr.into(), ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;
    key.zeroize();
    Ok(plaintext)
}

fn argon2(mem_kib: u32, iterations: u32, parallelism: u32) -> Result<Argon2<'static>> {
    let params = Params::new(mem_kib, iterations, parallelism, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {:?}", e))?;
    // Matches the original CLI implementation: empty secret slice (no pepper)
    Argon2::new_with_secret(&[], Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|e| anyhow!("Argon2 init error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep the test KDF cheap: 8 MiB; iterations must stay at 3 (the decrypt
    // side assumes 3/1)
    fn fast_kdf() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    #[test]
    fn kdf_params_default_is_64mib_x3() {
        let kdf = KdfParams::default();
        assert_eq!(kdf.mem_kib, 64 * 1024);
        assert_eq!(kdf.iterations, 3);
        assert_eq!(kdf.parallelism, 1);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let encrypted =
            encrypt_bytes(b"top secret payload", "passphrase", Some(fast_kdf())).unwrap();
        assert!(is_persona_encrypted(&encrypted));
        // The plaintext must not be visible in the ciphertext
        assert!(!encrypted
            .windows(b"top secret".len())
            .any(|w| w == b"top secret"));
        let decrypted = decrypt_bytes(&encrypted, "passphrase").unwrap();
        assert_eq!(decrypted, b"top secret payload");
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase_and_foreign_bytes() {
        let encrypted = encrypt_bytes(b"data", "right", Some(fast_kdf())).unwrap();
        let err = decrypt_bytes(&encrypted, "wrong").unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));

        let err = decrypt_bytes(b"just text", "any").unwrap_err();
        assert!(err.to_string().contains("Not a Persona encrypted file"));
    }

    #[test]
    fn decrypt_rejects_truncated_headers() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],                             // empty
            MAGIC.to_vec(),                     // magic only
            [MAGIC.as_slice(), &[16]].concat(), // salt len without salt
            {
                let mut v = MAGIC.to_vec();
                v.push(16);
                v.extend_from_slice(&[7u8; 16]);
                v.push(12);
                v.extend_from_slice(&[9u8; 12]);
                v.extend_from_slice(&8u32.to_le_bytes()); // mem_kib
                v.extend_from_slice(&999u64.to_le_bytes()); // enc_len beyond EOF
                v
            },
            {
                // enc_len = u64::MAX: `cursor + enc_len` overflows usize
                // (panics in debug). checked_add must turn this into
                // "Bad ciphertext len" rather than crashing.
                let mut v = MAGIC.to_vec();
                v.push(16);
                v.extend_from_slice(&[7u8; 16]);
                v.push(12);
                v.extend_from_slice(&[9u8; 12]);
                v.extend_from_slice(&8u32.to_le_bytes()); // mem_kib
                v.extend_from_slice(&u64::MAX.to_le_bytes());
                v
            },
        ];
        for (i, blob) in cases.iter().enumerate() {
            let err = decrypt_bytes(blob, "pw").unwrap_err();
            let msg = err.root_cause().to_string();
            assert!(
                msg.contains("Bad header")
                    || msg.contains("Bad ciphertext")
                    || msg.contains("Not a Persona"),
                "case {}: unexpected error: {}",
                i,
                msg
            );
        }
    }

    /// Interoperable with the CLI's historical implementation: hand-decode
    /// the salt/nonce using the KdfParams default header layout, confirming the
    /// header length layout matches the documentation (a format regression pin).
    #[test]
    fn header_layout_is_stable() {
        let encrypted = encrypt_bytes(
            b"abc",
            "pw",
            Some(KdfParams {
                mem_kib: 8 * 1024,
                iterations: 3,
                parallelism: 1,
            }),
        )
        .unwrap();
        // magic(8) + salt_len(1) + salt(16) + nonce_len(1) + nonce(12) + mem(4) + enc_len(8)
        assert_eq!(encrypted[8], 16, "salt length byte");
        assert_eq!(encrypted[8 + 1 + 16], 12, "nonce length byte");
        let mem_kib = u32::from_le_bytes(encrypted[8 + 1 + 16 + 1 + 12..][..4].try_into().unwrap());
        assert_eq!(mem_kib, 8 * 1024);
        let enc_len = u64::from_le_bytes(
            encrypted[8 + 1 + 16 + 1 + 12 + 4..][..8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            enc_len as usize,
            encrypted.len() - (8 + 1 + 16 + 1 + 12 + 4 + 8)
        );
    }
}
