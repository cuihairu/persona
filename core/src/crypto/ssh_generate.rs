//! 页面内生成 SSH 密钥对：ed25519 / rsa-4096 / ecdsa-p256。
//!
//! 产物与导入同构——明文 OpenSSH PEM 私钥入库，per-item key 封存由
//! vault 层负责；字段口径（类型名、算法名、指纹）复用 ssh_import 的
//! 映射，保证两条入口产出的条目形状完全一致。

use crate::{PersonaError, PersonaResult};
use ssh_key::private::{KeypairData, PrivateKey, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve};

/// 页面/CLI 生成结果；字段与 [`super::ssh_import::ImportedSshKey`] 同口径。
#[derive(Debug, Clone)]
pub struct GeneratedSshKey {
    /// 库内类型名：`ed25519` / `rsa` / `ecdsa`。
    pub key_type: String,
    /// SSH 线格式算法名：`ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-nistp256`。
    pub ssh_algorithm: String,
    /// OpenSSH 公钥单行（含 comment，可直接贴 authorized_keys）。
    pub public_key: String,
    /// SHA256 指纹（`SHA256:…`）。
    pub fingerprint: String,
    /// 未加密 OpenSSH PEM 私钥。
    pub private_key_pem: String,
    /// 写入钥匙的 comment。
    pub comment: String,
}

/// RSA 固定 4096（页面口径；要别的位数时再开口子）。
const RSA_BIT_SIZE: usize = 4096;

/// 按类型生成新密钥对。`key_type`：`ed25519`（默认）/ `rsa` / `ecdsa`。
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

    // ssh-key 对 RSA 不走 PrivateKey::random 的统一路径（要 rsa crate 的
    // 素数生成），单独组 KeypairData；comment 统一事后写入
    let mut key = if matches!(algorithm, Algorithm::Rsa { .. }) {
        let keypair = RsaKeypair::random(&mut rand_core::UnwrapErr(rand::rngs::SysRng), RSA_BIT_SIZE)
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

    /// 生成→再解析的往返一致性：三类钥各自验证类型/算法/公钥行/指纹，
    /// 指纹以重解析公钥为独立裁判（不是生成侧自己说了算）。
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
        // comment 进公钥行（贴 authorized_keys 时可见）
        assert!(generated.public_key.ends_with("cui@laptop"));
    }

    #[test]
    fn generates_rsa_4096() {
        let generated = generate_ssh_keypair("rsa", "rsa-test").unwrap();
        assert_roundtrip(&generated, "rsa", "ssh-rsa");
        // 模数恰为 4096 位（512 字节，生成器保证最高位为 1）
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
