//! PEM 家族私钥导入（PKCS#8 / PKCS#1 / SEC1）——OpenSSH 容器之外的常见格式。
//!
//! `openssl genpkey`、`genrsa -traditional`、`ecparam -genkey` 的输出都走
//! 这里。解码交给 RustCrypto 同系审计 crate：PKCS#8 用 `pkcs8`（含加密
//! PBES2 解锁），PKCS#1/SEC1 字段级结构用 `pkcs1`、`p256`（无需自写
//! DER），Ed25519 组装用 `ed25519-dalek`；本模块只做格式嗅探（PEM label
//! 与 PKCS#8 algorithm OID）及 `ssh-key` 容器组装（入库口径复用
//! `ssh_import`）。
//!
//! 口令口径与 OpenSSH 导入一致：加密 PKCS#8 在导入时解锁，入库存解锁后
//! 的 OpenSSH PEM。受保护 PEM 没有明文公钥半边（不像 OpenSSH 容器），
//! 预览（inspect）必须先解密才能算指纹——无口令的 inspect 直接报需要
//! 口令，由调用方提示。

use crate::{PersonaError, PersonaResult};
use pkcs8::der::asn1::{ObjectIdentifier, OctetStringRef};
use pkcs8::der::Decode;
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, SecretDocument};
use ssh_key::private::{KeypairData, PrivateKey};

/// PKCS#8 algorithm OID：rsaEncryption / ecPublicKey / Ed25519。
/// ecPublicKey 的 parameters 携带命名曲线，P-256 与否交给 p256 校验。
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// PEM 头嗅探结果。OpenSSH 容器头不在其中——它由 ssh_import 的既有路径
/// 先行处理（未命中任何已知头的输入也交给原路径报错，保持错误口径一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PemKind {
    /// `-----BEGIN PRIVATE KEY-----`（明文 PKCS#8，算法看 OID）
    Pkcs8,
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----`（PBES2 加密 PKCS#8）
    EncryptedPkcs8,
    /// `-----BEGIN RSA PRIVATE KEY-----`（PKCS#1 RSAPrivateKey）
    Pkcs1Rsa,
    /// `-----BEGIN EC PRIVATE KEY-----`（SEC1 ECPrivateKey）
    Sec1Ec,
}

/// 识别 PEM label；不认识的头返回 None。
pub(super) fn sniff_pem(content: &str) -> Option<PemKind> {
    let c = content.trim_start();
    if c.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        Some(PemKind::EncryptedPkcs8)
    } else if c.starts_with("-----BEGIN PRIVATE KEY-----") {
        Some(PemKind::Pkcs8)
    } else if c.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        Some(PemKind::Pkcs1Rsa)
    } else if c.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        Some(PemKind::Sec1Ec)
    } else {
        None
    }
}

/// 明确不支持的格式的专门提示（区别于笼统的"无法识别"）。
pub(super) fn unsupported_format_note(content: &str) -> Option<String> {
    if content.contains("PuTTY-User-Key-File") {
        Some(
            "PuTTY PPK private keys are not supported; \
             convert to OpenSSH format first (PuTTYgen → Conversions → Export OpenSSH key)"
                .to_string(),
        )
    } else {
        None
    }
}

/// 解码 PEM 私钥为 `ssh-key` 容器（已解锁明文）。
pub(super) fn decode(
    kind: PemKind,
    pem: &str,
    passphrase: Option<&str>,
) -> PersonaResult<PrivateKey> {
    match kind {
        PemKind::Pkcs8 => decode_pkcs8(pem, None),
        PemKind::EncryptedPkcs8 => {
            let pass = passphrase.ok_or_else(|| {
                PersonaError::InvalidInput(
                    "Private key is an encrypted PKCS#8 PEM: passphrase required to preview \
                     or import"
                        .to_string(),
                )
            })?;
            decode_pkcs8(pem, Some(pass))
        }
        PemKind::Pkcs1Rsa => {
            // pkcs1 的 DER 结构没有 pem 入口（DecodeRsaPrivateKey 只为 rsa crate
            // 的高级类型实现），PEM 壳自己剥，内层走 der::Decode
            let der = SecretDocument::from_pem(pem.trim())
                .map_err(|e| {
                    PersonaError::InvalidInput(format!("Failed to parse RSA PKCS#1 PEM: {e}"))
                })?
                .1;
            build_rsa(pkcs1::RsaPrivateKey::from_der(der.as_bytes()).map_err(|e| {
                PersonaError::InvalidInput(format!("Failed to decode RSA PKCS#1 key: {e}"))
            })?)
        }
        PemKind::Sec1Ec => decode_sec1(pem),
    }
}

/// PKCS#8：解出 `PrivateKeyInfo`（必要时先 PBES2 解密），按 algorithm OID
/// 分发；内层 `private_key` 字节对 Ed25519 是 DER OCTET STRING 包着的
/// 32B seed（RFC 8410 双层包裹）、对 EC 是 SEC1 ECPrivateKey DER
/// （RFC 5958/RFC 5915）、对 RSA 是 RSAPrivateKey DER（RFC 5208 → PKCS#1）。
fn decode_pkcs8(pem: &str, password: Option<&str>) -> PersonaResult<PrivateKey> {
    // PEM → DER 用 SecretDocument（密钥材料落盘前 zeroize）
    let der = SecretDocument::from_pem(pem.trim())
        .map_err(|e| {
            PersonaError::InvalidInput(format!("Failed to parse PKCS#8 private key PEM: {e}"))
        })?
        .1;
    // 明文 DER 统一收敛为 SecretDocument（pki 借用其字节，须活得一样长）
    let plain = match password {
        Some(pass) => {
            let encrypted = EncryptedPrivateKeyInfo::from_der(der.as_bytes()).map_err(|_| {
                PersonaError::InvalidInput(
                    "Failed to parse encrypted PKCS#8 private key".to_string(),
                )
            })?;
            encrypted.decrypt(pass).map_err(|_| {
                PersonaError::InvalidInput(
                    "Failed to decrypt PKCS#8 private key: wrong passphrase or corrupted file"
                        .to_string(),
                )
            })?
        }
        None => der,
    };
    let pki = PrivateKeyInfo::from_der(plain.as_bytes()).map_err(|e| {
        PersonaError::InvalidInput(format!("Failed to parse PKCS#8 private key: {e}"))
    })?;

    match pki.algorithm.oid {
        OID_ED25519 => {
            // RFC 8410 §7：privateKey 外层 OCTET STRING 里再包一层 DER
            // OCTET STRING（04 20 ‖ seed），两层都剥掉才到 32B seed
            let seed_bytes = OctetStringRef::from_der(pki.private_key)
                .map_err(|e| {
                    PersonaError::InvalidInput(format!("Malformed Ed25519 PKCS#8 key: {e}"))
                })?
                .as_bytes();
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                PersonaError::InvalidInput("Ed25519 private key seed must be 32 bytes".to_string())
            })?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let keypair = ssh_key::private::Ed25519Keypair {
                public: ssh_key::public::Ed25519PublicKey(sk.verifying_key().to_bytes()),
                private: ssh_key::private::Ed25519PrivateKey::from(sk),
            };
            PrivateKey::new(KeypairData::Ed25519(keypair), "").map_err(|e| {
                PersonaError::CryptographicError(format!("Failed to build SSH key: {e}"))
            })
        }
        OID_EC_PUBLIC_KEY => {
            let secret = p256::SecretKey::from_sec1_der(pki.private_key).map_err(|e| {
                PersonaError::InvalidInput(format!(
                    "Failed to decode EC private key (only NIST P-256 is supported): {e}"
                ))
            })?;
            Ok(build_ecdsa_p256(secret))
        }
        OID_RSA_ENCRYPTION => build_rsa(pkcs1::RsaPrivateKey::from_der(pki.private_key).map_err(
            |e| PersonaError::InvalidInput(format!("Failed to decode RSA private key: {e}")),
        )?),
        other => Err(PersonaError::InvalidInput(format!(
            "Unsupported private key algorithm OID: {other}"
        ))),
    }
}

/// SEC1 `ECPrivateKey`（`BEGIN EC PRIVATE KEY`）；非 P-256 曲线在此报错。
fn decode_sec1(pem: &str) -> PersonaResult<PrivateKey> {
    let secret = p256::SecretKey::from_sec1_pem(pem.trim()).map_err(|e| {
        PersonaError::InvalidInput(format!(
            "Failed to decode SEC1 EC private key (only NIST P-256 is supported): {e}"
        ))
    })?;
    Ok(build_ecdsa_p256(secret))
}

fn build_ecdsa_p256(secret: p256::SecretKey) -> PrivateKey {
    let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
        // ssh-key 的字段类型是 sec1::EncodedPoint<U32>；From<PublicKey> 即非压缩点
        public: secret.public_key().into(),
        private: ssh_key::private::EcdsaPrivateKey::from(secret),
    };
    // 组装错误只有曲线/尺寸不一致才可能触发，上面已按 P-256 校验过
    PrivateKey::new(KeypairData::Ecdsa(keypair), "").expect("P-256 keypair validated by decode")
}

/// RSA（PKCS#8 / PKCS#1 统一在此）：pkcs1 的字段级结构公开 n/e/d/p/q/
/// dp/dq/iqmp，SSH 线格式恰好只要 d/iqmp/p/q + n/e，coefficient 即 iqmp，
/// 无需自算任何大数。多素数 RSA（>2 素数）明确拒绝。
fn build_rsa(der_key: pkcs1::RsaPrivateKey<'_>) -> PersonaResult<PrivateKey> {
    if der_key.other_prime_infos.is_some() {
        return Err(PersonaError::InvalidInput(
            "Multi-prime RSA private keys are not supported".to_string(),
        ));
    }
    // ssh-key 0.7 把 Mpint/公私钥构造全部换成带规范校验的 new()：
    // from_positive_bytes 直接返回 Mpint，范围检查集中在 new() 一处报错。
    let mp = ssh_key::Mpint::from_positive_bytes;
    let public = ssh_key::public::RsaPublicKey::new(
        mp(der_key.public_exponent.as_bytes()),
        mp(der_key.modulus.as_bytes()),
    )
    .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA public key: {e}")))?;
    let private = ssh_key::private::RsaPrivateKey::new(
        mp(der_key.private_exponent.as_bytes()),
        mp(der_key.coefficient.as_bytes()),
        mp(der_key.prime1.as_bytes()),
        mp(der_key.prime2.as_bytes()),
    )
    .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA private key: {e}")))?;
    let keypair = ssh_key::private::RsaKeypair::new(public, private)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid RSA keypair: {e}")))?;
    PrivateKey::new(KeypairData::Rsa(keypair), "")
        .map_err(|e| PersonaError::CryptographicError(format!("Failed to build SSH key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ssh_import::{import_private_key_file, inspect_private_key_file};
    use ssh_key::HashAlg;

    // 一次性 openssl 生成的测试钥匙（从未用于任何真实场景）：
    //   openssl genpkey -algorithm ed25519 / RSA 2048 / ecparam prime256v1
    //   openssl rsa -traditional；加密件 -aes-128-cbc -pass pass:fixture-pass-1
    // 指纹由 ssh-keygen -lf 独立得出，钉死在此作第三方裁判。
    const ED25519_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKMDimteeX8+ZNEj5dWYYmLfi6CqdX8cZsKWyvXSUGTb
-----END PRIVATE KEY-----";
    const ED25519_PKCS8_FP: &str = "SHA256:dFtKDRZeeRorFCOVKXSjEDzH0cBmeRzSzwml+F8ISDY";

    const RSA_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2rkrELap3k1XW
jiBH4+FPPYyqNQYtca4l5LF3edVql87fMFW+qrQycVIzSz+l7C8EnXXVYW9Py5fU
hN0JfPlKkbQIbq+UwVvBYgHqS6TM/fNiLb5+UEpmGLkpW2E2JtgvETrmvMV5p4C4
4Z494G8hDf1JKj0AfGGZgRUqRvD/aqlp4yEOaKgi0QPWvzNomzRHbYOTjmjXmRns
VxubjFEyU/Mr7eZJ+8yqfEnJCuF111WWBrIJ465g7WN6HtutQz0+X+2jO0Zs3J6x
n6Yfo/Vsj9f3mKSE0K5WfVnpJoUYW/V/WI85r37CcqHD5wUPFEIIwlIglv8xA/cs
8853jh7fAgMBAAECggEANpzvhCukyT+2S0DNHMDfJEnhyia09JQGPJTcizvUlhvR
QD8aezhcS7I+IVCPNCLiQY5zYjnRRbk3aFTaIdKHUogxms3AVwfhTvRmXy2DFLec
8c58IxYMz+33OQp1CvPc8GFFyyJHJSHy5RKqNJRqlKaygJOMjh8hLHt/INb5iFnQ
g/qT0kv8N2Q8SPfqCk/wq64QWDiK1q1O7ur6vjriaIN1aDq+dFQVn6MkvUy5K4SW
NiT+mIdiizwgEbY1JZBJLM4VsNY8MwZMMJRnss0xt0ck03IzV5DxLkxJJuoCBM4H
cT20hXfNRbg7bXEOZfdt1/Op83XfZTWnZ/kQvoTKbQKBgQDsF9sCH48v6rOTTE4o
G3XIQ/50aZCWLNkqO2AJe2iUhNRZumy4jqLCg76om6wLaX0y8s38apqRXjifJief
w+WfNNQ+Q8MAAFBc5n7IKy9LV233BuJSVHqekBjmwEK5zzE/JtB82O4NYlryfRD8
Q4vt7N1zToOdM2acaekuBflvPQKBgQDGFYOodpPR5p10IZ8pSQ6EXgaCb+QHh7Kb
eE+lBsAQ6RUIRMU5oluvqjJQBg3+7DthhbVxaozyF85NBb2+lwKZ90nqkF8C1ehM
mdCyEBDo+iiw/G6n0/DyBs2CbMynmQ2Y9oAQt14O2xJfD5X0AaKvg+oFDqqFjKFg
ntQu+A0oSwKBgCCUmjCM0mG2bdmh6hc20uY0G+VMvBs9TSq6zuIAGcqFGhjX1TES
3fsh2ynBcdiRUim5wBtZSsNM0VuFFGrDyehSjgeZqktRv8VSOaS98OTgx9gTJyBd
cB55nDYbyhmCMjWY0aSo+xD1xb846yMk3yaSTW0gJKGI+lwTcY5cXLOxAoGBAKn3
R/NDW+9dvHkraFCamVRHAbrmm3lCnKT+hQiLVD6uYRepOroLcDS5C1bS+ytkNEen
3VqmHK6WcrRwWrGxDdBi+g/FNWFPfnZL/WDsnDXsgQHseF6VY0epQqnJBYpBsAMy
cAzn6lNA8vCShQ7MYHXN8P3J6dOSKd6oKlTrDw8lAoGBAMv+ZdAjDproi1J1fUL6
1L9cju6oN1QOR/x1R4Wrnlaxx2KMz1AmjkQtJFBHrO7LthZo90Pl6dWNH74dNlO1
k051WEQm94prEoDGejqZl5uO+f73YqgklNaNsR6gZa+XsNbcdnEHHSwVuxEIfWmb
DsPqD4LAXSTZdo7t96i5GcOy
-----END PRIVATE KEY-----";
    const RSA_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtq5KxC2qd5NV1o4gR+PhTz2MqjUGLXGuJeSxd3nVapfO3zBV
vqq0MnFSM0s/pewvBJ111WFvT8uX1ITdCXz5SpG0CG6vlMFbwWIB6kukzP3zYi2+
flBKZhi5KVthNibYLxE65rzFeaeAuOGePeBvIQ39SSo9AHxhmYEVKkbw/2qpaeMh
DmioItED1r8zaJs0R22Dk45o15kZ7Fcbm4xRMlPzK+3mSfvMqnxJyQrhdddVlgay
CeOuYO1jeh7brUM9Pl/toztGbNyesZ+mH6P1bI/X95ikhNCuVn1Z6SaFGFv1f1iP
Oa9+wnKhw+cFDxRCCMJSIJb/MQP3LPPOd44e3wIDAQABAoIBADac74QrpMk/tktA
zRzA3yRJ4comtPSUBjyU3Is71JYb0UA/Gns4XEuyPiFQjzQi4kGOc2I50UW5N2hU
2iHSh1KIMZrNwFcH4U70Zl8tgxS3nPHOfCMWDM/t9zkKdQrz3PBhRcsiRyUh8uUS
qjSUapSmsoCTjI4fISx7fyDW+YhZ0IP6k9JL/DdkPEj36gpP8KuuEFg4itatTu7q
+r464miDdWg6vnRUFZ+jJL1MuSuEljYk/piHYos8IBG2NSWQSSzOFbDWPDMGTDCU
Z7LNMbdHJNNyM1eQ8S5MSSbqAgTOB3E9tIV3zUW4O21xDmX3bdfzqfN132U1p2f5
EL6Eym0CgYEA7BfbAh+PL+qzk0xOKBt1yEP+dGmQlizZKjtgCXtolITUWbpsuI6i
woO+qJusC2l9MvLN/GqakV44nyYnn8PlnzTUPkPDAABQXOZ+yCsvS1dt9wbiUlR6
npAY5sBCuc8xPybQfNjuDWJa8n0Q/EOL7ezdc06DnTNmnGnpLgX5bz0CgYEAxhWD
qHaT0eaddCGfKUkOhF4Ggm/kB4eym3hPpQbAEOkVCETFOaJbr6oyUAYN/uw7YYW1
cWqM8hfOTQW9vpcCmfdJ6pBfAtXoTJnQshAQ6PoosPxup9Pw8gbNgmzMp5kNmPaA
ELdeDtsSXw+V9AGir4PqBQ6qhYyhYJ7ULvgNKEsCgYAglJowjNJhtm3ZoeoXNtLm
NBvlTLwbPU0qus7iABnKhRoY19UxEt37IdspwXHYkVIpucAbWUrDTNFbhRRqw8no
Uo4HmapLUb/FUjmkvfDk4MfYEycgXXAeeZw2G8oZgjI1mNGkqPsQ9cW/OOsjJN8m
kk1tICShiPpcE3GOXFyzsQKBgQCp90fzQ1vvXbx5K2hQmplURwG65pt5Qpyk/oUI
i1Q+rmEXqTq6C3A0uQtW0vsrZDRHp91aphyulnK0cFqxsQ3QYvoPxTVhT352S/1g
7Jw17IEB7HhelWNHqUKpyQWKQbADMnAM5+pTQPLwkoUOzGB1zfD9yenTkineqCpU
6w8PJQKBgQDL/mXQIw6a6ItSdX1C+tS/XI7uqDdUDkf8dUeFq55WscdijM9QJo5E
LSRQR6zuy7YWaPdD5enVjR++HTZTtZNOdVhEJveKaxKAxno6mZebjvn+92KoJJTW
jbEeoGWvl7DW3HZxBx0sFbsRCH1pmw7D6g+CwF0k2XaO7feouRnDsg==
-----END RSA PRIVATE KEY-----";
    const RSA_FP: &str = "SHA256:IVojBIR5zu1jlmWCOTC5ZHycjS7xrLWORTWVZN/QXO4";

    const EC_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFtYnHE9oaiIxJJ8hKvzPoUDJ50joAeohJKSVBtMTxdRoAoGCCqGSM49
AwEHoUQDQgAEWoAsrEJ6xfEyIfhv1E7aDKbIuxRJkAgww6uLGKPj7TejQG28qc6X
aPFZWt6j8Yk+Hv0necdm9z6Rhk1uepkj4g==
-----END EC PRIVATE KEY-----";
    const EC_FP: &str = "SHA256:TDpOFgHyZfNP3O192D0azqBHZGq2VEcxyqaZoN5fGUY";

    const ED25519_ENCRYPTED_PKCS8: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCrwkz0De3qYTGcS24y
qSCaAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBAgQQOMVVNthVrncZEDiI
GwkpzgRArm28dVEj732Z5SfPnv2AtlHHfOAMbYkQE0Zk8ZLzJJNlJh2l3CAot6uu
qkbvrvWWzBSQPEC0FxGXt6QnwJvTdA==
-----END ENCRYPTED PRIVATE KEY-----";
    const ED25519_ENCRYPTED_FP: &str = "SHA256:ho2O69nQ2o6hszOuYlGNyb+uA4y8c5fLh3h6ZHFwOCc";
    const ENCRYPTED_PASS: &str = "fixture-pass-1";

    fn assert_roundtrip(imported: &crate::crypto::ssh_import::ImportedSshKey, fp: &str) {
        assert_eq!(imported.fingerprint, fp);
        // 独立裁判：入库的 OpenSSH PEM 能被 ssh-key 原生解析，且指纹一致
        let reparsed = PrivateKey::from_openssh(&imported.private_key_pem)
            .expect("converted PEM must re-parse as OpenSSH");
        assert_eq!(
            reparsed
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            fp
        );
    }

    #[test]
    fn pkcs8_ed25519_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(ED25519_PKCS8, None).unwrap();
        assert_eq!(imported.key_type, "ed25519");
        assert_eq!(imported.ssh_algorithm, "ssh-ed25519");
        assert!(imported.public_key.starts_with("ssh-ed25519 "));
        assert_roundtrip(&imported, ED25519_PKCS8_FP);
    }

    #[test]
    fn pkcs8_rsa_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(RSA_PKCS8, None).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert!(imported.public_key.starts_with("ssh-rsa "));
        assert_roundtrip(&imported, RSA_FP);
    }

    #[test]
    fn pkcs1_rsa_imports_to_same_key_as_pkcs8() {
        let imported = import_private_key_file(RSA_PKCS1, None).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert_roundtrip(&imported, RSA_FP);
        let via_pkcs8 = import_private_key_file(RSA_PKCS8, None).unwrap();
        assert_eq!(imported.public_key, via_pkcs8.public_key);
    }

    #[test]
    fn sec1_ec_p256_imports_with_openssl_fingerprint() {
        let imported = import_private_key_file(EC_SEC1, None).unwrap();
        assert_eq!(imported.key_type, "ecdsa");
        assert_eq!(imported.ssh_algorithm, "ecdsa-sha2-nistp256");
        assert_roundtrip(&imported, EC_FP);
    }

    #[test]
    fn encrypted_pkcs8_imports_with_passphrase() {
        let imported = import_private_key_file(ED25519_ENCRYPTED_PKCS8, Some(ENCRYPTED_PASS))
            .expect("correct passphrase must unlock");
        assert_roundtrip(&imported, ED25519_ENCRYPTED_FP);
        // 入库口径：解锁后的明文 OpenSSH PEM，加密壳不随行
        assert!(!imported.private_key_pem.contains("ENCRYPTED"));
    }

    #[test]
    fn encrypted_pkcs8_requires_passphrase() {
        let err = import_private_key_file(ED25519_ENCRYPTED_PKCS8, None).unwrap_err();
        assert!(err.to_string().contains("passphrase required"), "{err}");
    }

    #[test]
    fn encrypted_pkcs8_rejects_wrong_passphrase() {
        let err = import_private_key_file(ED25519_ENCRYPTED_PKCS8, Some("wrong-pass")).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"), "{err}");
    }

    #[test]
    fn inspect_on_encrypted_pem_asks_for_passphrase() {
        let err = inspect_private_key_file(ED25519_ENCRYPTED_PKCS8).unwrap_err();
        assert!(err.to_string().contains("passphrase required"), "{err}");
    }

    #[test]
    fn inspect_on_plaintext_pem_previews_without_passphrase() {
        let inspection = inspect_private_key_file(ED25519_PKCS8).unwrap();
        assert_eq!(inspection.fingerprint, ED25519_PKCS8_FP);
        assert!(!inspection.encrypted);
    }

    #[test]
    fn putty_ppk_gets_dedicated_hint() {
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: \n";
        let err = import_private_key_file(ppk, None).unwrap_err();
        assert!(err.to_string().contains("PuTTY"), "{err}");
    }

    #[test]
    fn unrecognized_content_lists_supported_formats() {
        let err = import_private_key_file("hello world", None).unwrap_err();
        assert!(err.to_string().contains("OpenSSH"), "{err}");
    }

    #[test]
    fn sniffer_maps_labels() {
        assert_eq!(
            sniff_pem("-----BEGIN PRIVATE KEY-----\nx"),
            Some(PemKind::Pkcs8)
        );
        assert_eq!(
            sniff_pem("  -----BEGIN ENCRYPTED PRIVATE KEY-----\nx"),
            Some(PemKind::EncryptedPkcs8)
        );
        assert_eq!(
            sniff_pem("-----BEGIN RSA PRIVATE KEY-----\nx"),
            Some(PemKind::Pkcs1Rsa)
        );
        assert_eq!(
            sniff_pem("-----BEGIN EC PRIVATE KEY-----\nx"),
            Some(PemKind::Sec1Ec)
        );
        assert_eq!(sniff_pem("-----BEGIN OPENSSH PRIVATE KEY-----\nx"), None);
        assert_eq!(sniff_pem("garbage"), None);
    }
}
