//! PERSENC1 文件加密的薄包装：格式与算法实现平移至
//! `persona_core::backup::file_crypto`（备份链与 `--encrypt` 导出共用同一
//! 实现，字节级互解）。这里只保留文件 I/O 与 `.decrypted.tmp` 约定，
//! 对外签名与错误文案不变。

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub use persona_core::backup::{decrypt_bytes, encrypt_bytes, KdfParams};

/// 原地加密：读文件 → `encrypt_bytes` → 写回。
pub fn encrypt_file_inplace(path: &Path, passphrase: &str, kdf: Option<KdfParams>) -> Result<()> {
    let plaintext =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let encrypted = encrypt_bytes(&plaintext, passphrase, kdf)?;
    std::fs::write(path, encrypted)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

/// 解密到旁路临时文件 `<path>.decrypted.tmp`（原文件保持密文不动）。
pub fn decrypt_file_to_temp(path: &Path, passphrase: &str) -> Result<PathBuf> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let plaintext = decrypt_bytes(&data, passphrase)?;
    let mut out_path = path.to_path_buf();
    out_path.set_extension("decrypted.tmp");
    std::fs::write(&out_path, plaintext).with_context(|| "Failed to write decrypted temp file")?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep KDF cheap in tests: 8 MiB. Iterations must stay 3 — the
    // decryptor reads only mem_kib from the header and assumes 3/1.
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
    fn encrypt_then_decrypt_round_trips_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"top secret payload").unwrap();

        encrypt_file_inplace(&path, "passphrase", Some(fast_kdf())).unwrap();

        // The file is now encrypted: magic header, no plaintext inside.
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(b"PERSENC1"));
        assert!(!window_contains(&raw, b"top secret"));

        // Decrypting with the right passphrase restores the content.
        let decrypted = decrypt_file_to_temp(&path, "passphrase").unwrap();
        assert_eq!(std::fs::read(&decrypted).unwrap(), b"top secret payload");
        std::fs::remove_file(&decrypted).unwrap();
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        std::fs::write(&path, b"data").unwrap();
        encrypt_file_inplace(&path, "right", Some(fast_kdf())).unwrap();

        let err = decrypt_file_to_temp(&path, "wrong").unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));

        // A file without the magic header is refused before any crypto runs.
        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, b"just text").unwrap();
        let err = decrypt_file_to_temp(&plain, "any").unwrap_err();
        assert!(err.to_string().contains("Not a Persona encrypted file"));
    }

    #[test]
    fn decrypt_rejects_truncated_headers() {
        let dir = tempfile::tempdir().unwrap();

        let cases: Vec<Vec<u8>> = vec![
            vec![],                                   // empty
            b"PERSENC1".to_vec(),                     // magic only
            [b"PERSENC1".as_slice(), &[16]].concat(), // salt len without salt
            {
                let mut v = b"PERSENC1".to_vec();
                v.push(16);
                v.extend_from_slice(&[7u8; 16]);
                v
            }, // salt without nonce len
            {
                let mut v = b"PERSENC1".to_vec();
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
            let p = dir.path().join(format!("truncated-{}.bin", i));
            std::fs::write(&p, blob).unwrap();
            let err = decrypt_file_to_temp(&p, "pw").unwrap_err();
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

    #[test]
    fn encrypt_reports_missing_input_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("ghost.txt");
        let err = encrypt_file_inplace(&missing, "pw", Some(fast_kdf())).unwrap_err();
        assert!(err.to_string().contains("Failed to read"));
    }

    /// Case-insensitive substring search over bytes (test helper).
    fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
