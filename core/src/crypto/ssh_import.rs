//! OpenSSH 私钥文件导入（`id_ed25519` / `id_rsa` / `id_ecdsa`）。
//!
//! openssh-key-v1 容器解析、bcrypt-pbkdf KDF 与 aes*-ctr/cbc 解密交给
//! 审计过的 `ssh-key` crate；本模块只做产品口径：
//!
//! - passphrase 在导入时解锁（库内 `SshKeyData.passphrase` 置 `None`）——
//!   私钥入库后由 vault 的 per-item key 封存，密文旁边再存一遍口令
//!   不带来任何额外安全性，只会让 agent 加载链路多一个失败点；
//! - `private_key` 存**解锁后的 OpenSSH PEM**（与既有 ed25519 的
//!   BASE64 seed 约定并存，见 `agents/ssh-agent` 的双格式加载）；
//! - 指纹与公钥行在导入确认 UI 回显，用户核对指纹后再落库。

use crate::{PersonaError, PersonaResult};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding};

/// 导入结果：入库所需（`private_key_pem`）+ 确认 UI 所需（指纹/类型）。
#[derive(Debug, Clone)]
pub struct ImportedSshKey {
    /// 库内 `SshKeyData.key_type` 口径：`ed25519` / `rsa` / `ecdsa`。
    pub key_type: String,
    /// SSH 线格式算法名：`ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-nistp256`。
    pub ssh_algorithm: String,
    /// OpenSSH 公钥单行（`ssh-ed25519 AAAA… comment`），可直接贴 authorized_keys。
    pub public_key: String,
    /// SHA256 指纹（`SHA256:…`），导入确认时人工核对。
    pub fingerprint: String,
    /// 解锁后的私钥（OpenSSH PEM 明文）；入库由 per-item key 封存。
    pub private_key_pem: String,
    /// 原文件里的 comment（可用作条目默认名称）。
    pub comment: String,
}

/// 导入前预览：不要求口令（OpenSSH 容器的公钥半边是明文，密钥受保护时
/// 也能先给指纹让人核对，再决定是否输口令解锁）。
#[derive(Debug, Clone)]
pub struct SshKeyInspection {
    /// 库内 `SshKeyData.key_type` 口径。
    pub key_type: String,
    /// SSH 线格式算法名。
    pub ssh_algorithm: String,
    /// OpenSSH 公钥单行。
    pub public_key: String,
    /// SHA256 指纹（`SHA256:…`）。
    pub fingerprint: String,
    /// 原文件里的 comment。
    pub comment: String,
    /// 密钥是否受口令保护（导入时需要 passphrase）。
    pub encrypted: bool,
}

/// 把 ssh-key 的算法判定映射到库内口径；不支持的算法在此统一拒绝。
pub(crate) fn classify(algorithm: Algorithm) -> PersonaResult<(&'static str, &'static str)> {
    Ok(match algorithm {
        Algorithm::Ed25519 => ("ed25519", "ssh-ed25519"),
        // 0.6.7 的 Rsa 带 hash 字段（rsa-sha2-* 证书场景）；裸算法即 rsa
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

/// 解析私钥文件内容并返回导入所需字段——格式自动识别：
/// OpenSSH 容器（含 bcrypt 口令解锁）、PKCS#8（含 PBES2 加密）、
/// PKCS#1 RSA、SEC1 EC（仅 P-256）。PuTTY PPK 等明确不支持。
///
/// `passphrase`：密钥受口令保护时必传；错误口令返回明确错误（不静默重试）。
/// 未受保护的密钥传 `None`/`Some(_)` 均可（`Some` 被忽略）。
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

/// 未知格式错误：点名实际看到的 PEM 头（用户拿错文件时一眼定位——
/// 公钥/证书/ssh.com 格式各有典型头），再列全部期望格式。label 来自
/// 用户自己的输入，回显无泄密面；截断防畸形超长行撑爆提示。
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

/// 导入前预览（格式自动识别）：不解锁也能给指纹/类型/是否受保护。
/// OpenSSH 容器照旧（公钥半边明文）；加密 PKCS#8 PEM 没有明文公钥半边，
/// 无口令时报"需要口令"。
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
        // PEM 走到预览成功即已明文（加密件无口令在上一步就被拒）
        encrypted: false,
    })
}

/// 解析 OpenSSH 私钥文件内容并返回导入所需字段。
///
/// `passphrase`：密钥受口令保护时必传；错误口令返回明确错误（不静默重试）。
/// 未受保护的密钥传 `None`/`Some(_)` 均可（`Some` 被忽略）。
/// 不支持的算法（如 sk-* 硬件钥）与畸形内容同样返回明确错误。
pub fn import_openssh_private_key(
    pem: &str,
    passphrase: Option<&str>,
) -> PersonaResult<ImportedSshKey> {
    let key = decode_openssh(pem, passphrase)?;
    finish_import(key)
}

/// OpenSSH 容器解码 + 口令解锁（`import_openssh_private_key` 与格式分发共用）。
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

/// 解码结果 → 导入载荷（classify/公钥行/指纹/入库 PEM，双入口共用）。
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

/// 导入前预览：不解锁也能给指纹/类型/是否受保护。
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

/// 公钥单行（`ssh-ed25519 AAAA… comment`）→（线格式算法名，SHA256 指纹，
/// 位数/曲线标签）。供列表/详情展示与指纹核对；解析失败返回 None
/// （调用方按空列展示，不报错）。
///
/// 标签口径：Ed25519→`256`，RSA→模长位数十进制，ECDSA→`P-256` 曲线名，
/// DSA→素数位长；SK 硬件钥跟随其内部算法，证书/opaque 容器不适用为 None。
pub fn describe_public_key_line(line: &str) -> Option<(String, String, Option<String>)> {
    let pk = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
    Some((
        pk.algorithm().to_string(),
        pk.fingerprint(HashAlg::Sha256).to_string(),
        key_size_label(pk.key_data()),
    ))
}

/// 位长/曲线标签（纯展示口径，不参与任何校验）。
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
        // 证书/opaque 容器：算法名仍可展示，位数不适用
        _ => None,
    }
}

/// 正整数 Mpint 的位长（`as_positive_bytes` 剥掉符号零字节，首字节必非零）。
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

    /// 自举生成三类测试钥：ssh-key 自身既当生成器又当解析器，
    /// 断言走本模块的产品口径（解锁、字段完整性、指纹格式）。
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
        // 解锁后的 PEM 必须能被再次解析（往返一致），且不再是密文容器
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
        // 公钥不是私钥容器，必须在解析层被拒（用户拿错文件时给出明确口径）
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
        // OpenSSH 容器的公钥半边是明文：受保护密钥不给口令也能预览指纹，
        // 用户先核对指纹再决定输不输口令
        let pem = generate_encrypted_pem(Algorithm::Ed25519, "hunter2");
        let inspection = inspect_openssh_private_key(&pem).unwrap();
        assert!(inspection.encrypted);
        assert_eq!(inspection.key_type, "ed25519");
        assert!(inspection.fingerprint.starts_with("SHA256:"));
        assert!(inspection.public_key.starts_with("ssh-ed25519 AAAA"));

        // 解锁后的指纹与预览一致（同一把钥）
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
        // 拿错文件最常见：证书/公钥而非私钥——错误里点名实际看到的头
        let err = import_private_key_file(
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("\"-----BEGIN CERTIFICATE-----\""), "{msg}");
        assert!(msg.contains("is not supported"), "{msg}");
        // 期望格式清单照列
        assert!(msg.contains("BEGIN OPENSSH PRIVATE KEY"), "{msg}");
        assert!(msg.contains("BEGIN EC PRIVATE KEY"), "{msg}");

        // OpenSSL 老式 DSA（严格 PEM 头、不支持的算法）同样点名
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

        // 彻底没有 PEM 头的文件：明说不是 PEM 私钥文件（PPK 有专门提示在前拦）
        let err = inspect_private_key_file("random binary bytes").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a PEM private key file"), "{msg}");
        assert!(msg.contains("BEGIN RSA PRIVATE KEY"), "{msg}");
    }

    #[test]
    fn describe_public_key_reports_size_and_curve() {
        // Ed25519：固定位长 256
        let ed = PrivateKey::from_openssh(generate_pem(Algorithm::Ed25519)).unwrap();
        let (algo, fp, size) =
            describe_public_key_line(&ed.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ssh-ed25519");
        assert_eq!(fp, ed.public_key().fingerprint(HashAlg::Sha256).to_string());
        assert_eq!(size.as_deref(), Some("256"));

        // RSA：模长位数（与私钥自报的 key_size 交叉验证）
        let rsa = PrivateKey::from_openssh(generate_pem(Algorithm::Rsa { hash: None })).unwrap();
        let expected_bits = match rsa.key_data() {
            ssh_key::private::KeypairData::Rsa(rsa) => rsa.key_size().to_string(),
            other => panic!("expected rsa keypair, got {other:?}"),
        };
        let (algo, _, size) =
            describe_public_key_line(&rsa.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ssh-rsa");
        assert_eq!(size.as_deref(), Some(expected_bits.as_str()));

        // ECDSA：曲线标签
        let ecdsa = PrivateKey::from_openssh(generate_pem(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }))
        .unwrap();
        let (algo, _, size) =
            describe_public_key_line(&ecdsa.public_key().to_openssh().unwrap()).unwrap();
        assert_eq!(algo, "ecdsa-sha2-nistp256");
        assert_eq!(size.as_deref(), Some("P-256"));

        // 垃圾输入 → None（调用方按空列展示，不报错）
        assert!(describe_public_key_line("not a key").is_none());
    }
}
