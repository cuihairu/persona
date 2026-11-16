//! 配对密码学原语：参数常量、短码生成/规范化、Argon2id 派生、HKDF
//! 收缩、短指纹与组密钥 AEAD 封解。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::{PersonaError, PersonaResult};

// ---- 参数常量 ----

/// 动态密码长度（Crockford base32 字符数；9×5 bit = 45 bit 熵，
/// 短时效 + 单次使用 + 中转限次共同兜住在线爆破面）。
pub const PAIRING_CODE_LEN: usize = 9;
/// 配对 salt 字节数（经邀请面交给 guest，与 code 一起进 KDF）。
pub const PAIRING_SALT_LEN: usize = 16;
/// 组密钥长度（与 [`crate::sync::envelope`] 的组密钥同规格）。
pub const PAIRING_GROUP_KEY_LEN: usize = 32;
/// 双端比对的短指纹位数（10^6 空间；防 MITM 靠「不一致即人工拒绝」）。
pub const FINGERPRINT_LEN: usize = 6;

/// Argon2id 域前缀（进 KDF 的盐头）。
const PAIRING_KDF_DOMAIN: &[u8] = b"persona-pairing-v1";
/// SRP identity（配对路径固定身份，与账号登录的 username 空间隔离）。
pub(super) const PAIRING_IDENTITY: &[u8] = b"persona-pairing-v1";
/// HKDF info：premaster → pairing key。
const PAIRING_KEY_INFO: &[u8] = b"persona-pairing-key-v1";
/// 短指纹派生域。
const FINGERPRINT_DOMAIN: &[u8] = b"persona-pairing-fp-v1";
/// AEAD 附加认证数据（wrap 的域绑定）。
const WRAP_AAD: &[u8] = b"persona-pairing-wrap-v1";

/// Crockford base32（排除 I L O U 易混字形）。
pub(super) const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// nonce + 组密钥 + GCM tag。
pub const WRAPPED_GROUP_KEY_LEN: usize = 12 + PAIRING_GROUP_KEY_LEN + 16;

/// 生成动态密码：Crockford base32，[`PAIRING_CODE_LEN`] 字符。
pub fn generate_pairing_code() -> String {
    let bytes: [u8; 6] = rand::random();
    let mut extended = [0u8; 8];
    extended[..6].copy_from_slice(&bytes);
    let bits = u64::from_be_bytes(extended); // 48 bit，取高 45
    (0..PAIRING_CODE_LEN)
        .map(|i| {
            let idx = ((bits >> (3 + 5 * (PAIRING_CODE_LEN - 1 - i))) & 31) as usize;
            CROCKFORD[idx] as char
        })
        .collect()
}

/// 规范化用户输入的动态密码：去空白/连字符、大写、易混字形映射
/// （O→0、I→1、L→1、U→V）。非字母数字字符一律丢弃。
pub fn normalize_pairing_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            'U' => 'V',
            other => other,
        })
        .collect()
}

/// Argon2id 派生配对密钥材料（短码 → SRP 的「password」角色）。
pub(super) fn derive_pairing_secret(code: &str, salt: &[u8]) -> PersonaResult<[u8; 32]> {
    let mut domain_salt = Vec::with_capacity(PAIRING_KDF_DOMAIN.len() + salt.len());
    domain_salt.extend_from_slice(PAIRING_KDF_DOMAIN);
    domain_salt.extend_from_slice(salt);
    let mut out = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .hash_password_into(code.as_bytes(), &domain_salt, &mut out)
    .map_err(|e| PersonaError::CryptographicError(format!("pairing KDF failed: {e}")))?;
    Ok(out)
}

/// pairing key = HKDF-SHA256(premaster)——SRP premaster 到 AEAD 钥的
/// 域绑定收缩。
pub(super) fn pairing_key_from(premaster: &[u8]) -> PersonaResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PAIRING_KDF_DOMAIN), premaster);
    let mut out = [0u8; 32];
    hk.expand(PAIRING_KEY_INFO, &mut out)
        .map_err(|e| PersonaError::CryptographicError(format!("pairing HKDF failed: {e}")))?;
    Ok(out)
}

/// 双端比对的短指纹：6 位十进制（前导零保留）。
pub fn pairing_fingerprint(pairing_key: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(pairing_key)
        .finalize();
    let v = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{v:0>6}")
}

pub(super) fn seal_group_key_with(
    pairing_key: &[u8; 32],
    group_key: &[u8; PAIRING_GROUP_KEY_LEN],
) -> PersonaResult<Vec<u8>> {
    let cipher = Aes256Gcm::new((&pairing_key.clone()).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from(nonce_bytes).as_ref(),
            aes_gcm::aead::Payload {
                msg: group_key.as_ref(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| PersonaError::CryptographicError("group key seal failed".into()))?;
    let mut out = Vec::with_capacity(WRAPPED_GROUP_KEY_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(super) fn open_group_key_with(
    pairing_key: &[u8; 32],
    wrapped: &[u8],
) -> PersonaResult<[u8; PAIRING_GROUP_KEY_LEN]> {
    if wrapped.len() != WRAPPED_GROUP_KEY_LEN {
        return Err(PersonaError::CryptographicError(format!(
            "wrapped group key 长度应为 {WRAPPED_GROUP_KEY_LEN}，得 {}",
            wrapped.len()
        )));
    }
    let cipher = Aes256Gcm::new((&pairing_key.clone()).into());
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().expect("split_at(12) 后必为 12 字节");
    let pt = cipher
        .decrypt(
            &aes_gcm::Nonce::from(nonce),
            aes_gcm::aead::Payload {
                msg: ct,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| {
            PersonaError::CryptographicError("组密钥解封失败（码不对或信封被篡改）".into())
        })?;
    let mut out = [0u8; PAIRING_GROUP_KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}
