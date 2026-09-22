//! PERSENC1 字节加密：与 CLI `--encrypt` 导出文件字节级互解。
//!
//! 格式（自 CLI `utils/file_crypto` 平移，字节布局不可变）：
//! `[magic:8]"PERSENC1" [salt_len:1][salt] [nonce_len:1][nonce]
//! [kdf mem_kib:4 LE] [enc_len:8 LE] [ciphertext...]`
//!
//! KDF：Argon2id（salt 随机 16B、key 32B；解密侧只从头部读 mem_kib，
//! iterations/parallelism 恒 3/1——历史格式如此，保持兼容）。
//! 加密：AES-256-GCM（nonce 12B）。

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"PERSENC1";

/// Argon2id 参数（写入头部的只有 mem_kib；见模块注释）。
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

/// 是否为 PERSENC1 密文（魔数探测；restore 链路先探测再走解密）。
pub fn is_persona_encrypted(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// 加密任意字节（备份链：明文恒为 gzip 过的快照；导出链：文件内容）。
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

/// 解密 PERSENC1 字节；口令错或文件损坏均报错（GCM 认证失败）。
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
    let ciphertext = data
        .get(cursor..cursor + enc_len)
        .ok_or_else(|| anyhow!("Bad ciphertext len"))?;

    // 历史格式：解密侧 iterations/parallelism 恒 3/1（头部只存 mem_kib）
    let argon = argon2(mem_kib, 3, 1)?;
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 derive error: {:?}", e))?;

    let cipher = Aes256Gcm::new((&key).into());
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;
    key.zeroize();
    Ok(plaintext)
}

fn argon2(mem_kib: u32, iterations: u32, parallelism: u32) -> Result<Argon2<'static>> {
    let params = Params::new(mem_kib, iterations, parallelism, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {:?}", e))?;
    // 与 CLI 原实现一致：secret 为空切片（无 pepper）
    Argon2::new_with_secret(&[], Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|e| anyhow!("Argon2 init error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试 KDF 保持便宜：8 MiB；iterations 必须保持 3（解密侧假定 3/1）
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
        // 密文里找不到明文
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

    /// 与 CLI 历史实现互解：用 KdfParams 默认头部布局手工解出 salt/nonce，
    /// 确认头部长度布局与文档一致（格式回归钉子）。
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
