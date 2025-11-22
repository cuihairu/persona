use aes_gcm::{
    aead::{Aead, OsRng},
    Aes256Gcm, KeyInit,
};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

// Simple file encryption format:
// [magic:8] "PERSENC1"
// [salt_len:1][salt][nonce_len:1][nonce][kdf_params:4 bytes little endian mem_kib][enc_len:8][ciphertext...]
// KDF: Argon2id with provided salt; key length 32 bytes; params memory_kib (default 64MB), iterations=3, parallelism=1
// Cipher: AES-256-GCM with 12-byte nonce

const MAGIC: &[u8; 8] = b"PERSENC1";

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

pub fn encrypt_file_inplace(
    path: &std::path::Path,
    passphrase: &str,
    kdf: Option<KdfParams>,
) -> Result<()> {
    let kdf_params = kdf.unwrap_or_default();
    let plaintext =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;

    // Generate salt and nonce
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive key
    let argon = Argon2::new_with_secret(
        &[],
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            kdf_params.mem_kib,
            kdf_params.iterations,
            kdf_params.parallelism,
            Some(32),
        )
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {:?}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("Argon2 init error: {:?}", e))?;
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 derive error: {:?}", e))?;

    let cipher = Aes256Gcm::new((&key).into());
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    // Build output
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(salt.len() as u8);
    out.extend_from_slice(&salt);
    out.push(nonce.len() as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&kdf_params.mem_kib.to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);

    // Zeroize key
    key.zeroize();

    // Write back
    std::fs::write(path, out).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

pub fn decrypt_file_to_temp(
    path: &std::path::Path,
    passphrase: &str,
) -> Result<std::path::PathBuf> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut cursor = 0usize;
    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        anyhow::bail!("Not a Persona encrypted file");
    }
    cursor += MAGIC.len();
    let salt_len = *data
        .get(cursor)
        .ok_or_else(|| anyhow::anyhow!("Bad header"))? as usize;
    cursor += 1;
    let salt = data
        .get(cursor..cursor + salt_len)
        .ok_or_else(|| anyhow::anyhow!("Bad header salt"))?;
    cursor += salt_len;
    let nonce_len = *data
        .get(cursor)
        .ok_or_else(|| anyhow::anyhow!("Bad header"))? as usize;
    cursor += 1;
    let nonce = data
        .get(cursor..cursor + nonce_len)
        .ok_or_else(|| anyhow::anyhow!("Bad header nonce"))?;
    cursor += nonce_len;
    let mut mem_kib_bytes = [0u8; 4];
    mem_kib_bytes.copy_from_slice(
        data.get(cursor..cursor + 4)
            .ok_or_else(|| anyhow::anyhow!("Bad header kdf"))?,
    );
    cursor += 4;
    let mut enc_len_bytes = [0u8; 8];
    enc_len_bytes.copy_from_slice(
        data.get(cursor..cursor + 8)
            .ok_or_else(|| anyhow::anyhow!("Bad header len"))?,
    );
    cursor += 8;
    let enc_len = u64::from_le_bytes(enc_len_bytes) as usize;
    let ciphertext = data
        .get(cursor..cursor + enc_len)
        .ok_or_else(|| anyhow::anyhow!("Bad ciphertext len"))?;

    // Derive key
    let argon = Argon2::new_with_secret(
        &[],
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(u32::from_le_bytes(mem_kib_bytes), 3, 1, Some(32))
            .map_err(|e| anyhow::anyhow!("Argon2 params error: {:?}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("Argon2 init error: {:?}", e))?;
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 derive error: {:?}", e))?;

    let cipher = Aes256Gcm::new((&key).into());
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
    key.zeroize();

    // Write to temp file
    let mut out_path = path.to_path_buf();
    out_path.set_extension("decrypted.tmp");
    std::fs::write(&out_path, plaintext).with_context(|| "Failed to write decrypted temp file")?;
    Ok(out_path)
}
