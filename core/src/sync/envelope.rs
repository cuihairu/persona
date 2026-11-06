//! device envelope（E2EE_SYNC_DESIGN DR-1，格式 `persona-dev-env-1`）。
//!
//! 字节布局：`ephemeral_pub(32B) ‖ AES-256-GCM 密文(含 16B tag)`，总长
//! [`ENVELOPE_LEN`]。加密密钥与 nonce 均从 ephemeral DH 经 HKDF-SHA256
//! 一次性展开 44B（key 32 ‖ nonce 12）：每次密封重新生成 ephemeral，
//! 同一 `(eph, device_pub)` 对永不重复，因此派生 nonce 的复用无碰撞风险。
//!
//! 服务器只存信封（每设备一个）——拆信封需要对应设备私钥，私钥永不上传。

use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::PersonaError;

/// HKDF info 域分隔（DR-1 定名）。
pub const DEV_ENVELOPE_INFO: &[u8] = b"persona-dev-env-1";

const EPH_PUB_LEN: usize = 32;
const GROUP_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// 信封总长 = eph_pub(32) + group_key(32) + tag(16)。
pub const ENVELOPE_LEN: usize = EPH_PUB_LEN + GROUP_KEY_LEN + TAG_LEN;

/// 用设备 X25519 公钥密封 group key（建组与为新设备授权时调用）。
/// `device_public` 来自服务器登记的设备记录，属不受信输入：若它是低阶点，
/// 共享密钥塌缩成公开常量，任何人（含恶意服务器）都能自行拆封信封、
/// 偷换 group key——因此拒封（fail-closed，与 [`open_group_key`] 拆封侧
/// 的同名防线对称）。
pub fn seal_group_key(
    group_key: &[u8; GROUP_KEY_LEN],
    device_public: &[u8; 32],
) -> Result<Vec<u8>, PersonaError> {
    reject_low_order_public("device public key", device_public)?;
    let mut eph_secret_bytes = [0u8; 32];
    rand::rng().fill(&mut eph_secret_bytes);
    let eph_secret = StaticSecret::from(eph_secret_bytes);
    let eph_public = PublicKey::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&PublicKey::from(*device_public));
    if !shared.was_contributory() {
        return Err(PersonaError::CryptographicError(
            "device public key is a low-order point".to_string(),
        ));
    }
    let okm = derive_okm(&shared);

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let key_bytes: [u8; 32] = okm[..32].try_into().expect("HKDF-SHA256 输出定长");
    let nonce_bytes: [u8; NONCE_LEN] = okm[32..32 + NONCE_LEN]
        .try_into()
        .expect("HKDF-SHA256 输出定长");
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let ciphertext = cipher
        .encrypt((&nonce_bytes).into(), group_key.as_ref())
        .expect("AES-GCM encryption with freshly derived key cannot fail");

    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 设备用自己的私钥拆信封。失败 = 信封不是包给这把私钥的（或被篡改）——
/// 两种成因不区分（[`PersonaError::CryptographicError`]），调用方一律按
/// 「未授权该同步组」处理（fail-closed）。
///
/// 信封来自服务器，属不受信输入：`eph_pub` 若是低阶点（如全零），X25519
/// 共享密钥塌缩成公开常量，攻击者可本地复算 HKDF 并自造合法信封把自选
/// group key 注入设备——因此低阶点在 AEAD 之前显式拒绝（fail-closed）。
pub fn open_group_key(
    envelope: &[u8],
    device_secret: &[u8; 32],
) -> Result<[u8; GROUP_KEY_LEN], PersonaError> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(PersonaError::InvalidInput(format!(
            "device envelope must be {ENVELOPE_LEN} bytes, got {}",
            envelope.len()
        )));
    }
    let eph_public_bytes: [u8; 32] = envelope[..EPH_PUB_LEN]
        .try_into()
        .expect("slice length checked above");
    reject_low_order_public("device envelope ephemeral key", &eph_public_bytes)?;
    let secret = StaticSecret::from(*device_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_public_bytes));
    if !shared.was_contributory() {
        return Err(PersonaError::CryptographicError(
            "device envelope ephemeral key is a low-order point".to_string(),
        ));
    }
    let okm = derive_okm(&shared);

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let key_bytes: [u8; 32] = okm[..32].try_into().expect("HKDF-SHA256 输出定长");
    let nonce_bytes: [u8; NONCE_LEN] = okm[32..32 + NONCE_LEN]
        .try_into()
        .expect("HKDF-SHA256 输出定长");
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let plaintext = cipher
        .decrypt((&nonce_bytes).into(), &envelope[EPH_PUB_LEN..])
        .map_err(|_| {
            PersonaError::CryptographicError("device envelope failed authentication".to_string())
        })?;
    plaintext.try_into().map_err(|_| {
        PersonaError::CryptographicError("device envelope payload length mismatch".to_string())
    })
}

/// 显式拒绝全零公钥字节（低阶点里最常见的一枚）：早拒给出精确错误，
/// 也为 DH 实现日后更替留一道不依赖 `was_contributory` 的防线。
/// 全部低阶点由 `SharedSecret::was_contributory` 兜底——低阶点的 X25519
/// 输出恒为全零 ⇒ 共享密钥非贡献性 ⇒ 对方可本地复算派生密钥。
fn reject_low_order_public(what: &str, bytes: &[u8; 32]) -> Result<(), PersonaError> {
    if *bytes == [0u8; 32] {
        return Err(PersonaError::CryptographicError(format!(
            "{what} is an all-zero low-order point"
        )));
    }
    Ok(())
}

/// HKDF-SHA256：salt = None（零盐），ikm = ephemeral DH 共享密钥，
/// info = `persona-dev-env-1`，展开 key(32) ‖ nonce(12)。
fn derive_okm(shared: &x25519_dalek::SharedSecret) -> [u8; 32 + NONCE_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32 + NONCE_LEN];
    hk.expand(DEV_ENVELOPE_INFO, &mut okm)
        .expect("44-byte OKM is valid for HKDF-SHA256");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::keys::DeviceKeyPair;

    fn keypair() -> DeviceKeyPair {
        DeviceKeyPair::generate().unwrap()
    }

    #[test]
    fn seal_open_round_trip() {
        let device = keypair();
        let group_key = [7u8; 32];
        let envelope = seal_group_key(&group_key, device.public_bytes()).unwrap();
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        let opened = open_group_key(&envelope, device.secret_bytes()).unwrap();
        assert_eq!(opened, group_key);
    }

    #[test]
    fn wrong_device_cannot_open() {
        let device = keypair();
        let outsider = keypair();
        let envelope = seal_group_key(&[1u8; 32], device.public_bytes()).unwrap();
        let err = open_group_key(&envelope, outsider.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("failed authentication"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let device = keypair();
        let mut envelope = seal_group_key(&[2u8; 32], device.public_bytes()).unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        assert!(open_group_key(&envelope, device.secret_bytes()).is_err());
    }

    #[test]
    fn tampered_ephemeral_public_is_rejected() {
        let device = keypair();
        let mut envelope = seal_group_key(&[3u8; 32], device.public_bytes()).unwrap();
        envelope[0] ^= 0xff;
        assert!(open_group_key(&envelope, device.secret_bytes()).is_err());
    }

    #[test]
    fn truncated_envelope_is_a_length_error() {
        let device = keypair();
        let err = open_group_key(&[0u8; 10], device.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("bytes, got 10"), "{err}");
    }

    #[test]
    fn sealing_twice_produces_unlinked_envelopes() {
        // ephemeral 每次重新生成：同一 group key 的两次密封产生不同信封
        // （不可链接性），且各自都能被设备私钥拆开
        let device = keypair();
        let group_key = [9u8; 32];
        let a = seal_group_key(&group_key, device.public_bytes()).unwrap();
        let b = seal_group_key(&group_key, device.public_bytes()).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            open_group_key(&a, device.secret_bytes()).unwrap(),
            group_key
        );
        assert_eq!(
            open_group_key(&b, device.secret_bytes()).unwrap(),
            group_key
        );
    }

    /// 回归（AUDIT-2026-11-05 P1-3）：恶意服务器把信封 `eph_pub` 换成
    /// 低阶点（全零）后，共享密钥塌成公开常量，攻击者可本地复算密钥并
    /// 自造「合法」信封注入自选 group key——必须在 AEAD 之前拒绝，且
    /// 错误信息指明低阶点（而非含糊的 authentication failed）。
    #[test]
    fn open_rejects_all_zero_ephemeral_public() {
        let device = keypair();
        let mut envelope = seal_group_key(&[4u8; 32], device.public_bytes()).unwrap();
        envelope[..EPH_PUB_LEN].fill(0);
        let err = open_group_key(&envelope, device.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("low-order"), "{err}");
    }

    /// 同一防线的封口侧：服务器登记的设备公钥若是低阶点，密封出的信封
    /// 对攻击者透明——拒封而不是产出可被拆的信封。
    #[test]
    fn seal_rejects_all_zero_device_public() {
        let err = seal_group_key(&[5u8; 32], &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("low-order"), "{err}");
    }
}
