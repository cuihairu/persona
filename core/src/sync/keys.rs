//! 同步组密钥与设备身份密钥（E2EE_SYNC_DESIGN DR-1 / DR-3）。
//!
//! - **group key**：随机 256 位，工作区一份，永不明文离开设备、永不明文上
//!   服务器——在服务器上只以「设备信封」形态存在（[`super::envelope`]）。
//!   换主密码不触碰它（同步与主密码解耦的关键）。
//! - **device key pair**：每台设备加入同步时生成一次性 X25519 密钥对；
//!   私钥由宿主持久化（OS keyring service `persona-device`，headless 环境
//!   显式 `--device-key-file` 0600 文件 fallback——core 不依赖 keyring，
//!   只提供生成与加载）。

use rand::RngExt;
use zeroize::Zeroize;

use crate::PersonaError;

/// 同步组密钥。`Drop` 时清零内存（不进持久层的 plaintext 副本尽量短命）。
#[derive(Clone, PartialEq, Eq, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GroupKey([u8; 32]);

impl core::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 密钥字节绝不进日志
        f.write_str("GroupKey(<32 bytes>)")
    }
}

impl GroupKey {
    /// 生成新组密钥（建组时一次）。
    pub fn generate() -> Result<Self, PersonaError> {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Ok(Self(bytes))
    }

    /// 从字节加载（拆信封/从本地存储恢复时用）。
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 设备身份密钥对（X25519）。私钥字节只在构造与 `secret_bytes` 读出时
/// 出现——宿主拿到后自行落 keyring/文件。
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKeyPair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl DeviceKeyPair {
    /// 生成新设备密钥对（加入同步时一次）。
    pub fn generate() -> Result<Self, PersonaError> {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        Ok(Self::from_secret(secret))
    }

    /// 从私钥字节恢复（宿主从 keyring/文件读回时用）；公钥即时派生。
    pub fn from_secret(secret: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};
        let public = PublicKey::from(&StaticSecret::from(secret));
        Self {
            secret,
            public: public.to_bytes(),
        }
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// 同步 payload 的 item key 包裹（`SyncPayload.wrapped_item_key`）。
///
/// oplog 只持密文：条目密文用 item key 封（主库同款），item key 再用
/// group key 对称封——远端设备拆开 group 信封得到 group key 后即可
/// 解出 item key 还原条目，服务器两级都不可读。格式复用
/// `EncryptionService` 的「随机 nonce 前置 12B ‖ AES-256-GCM 密文」：
/// 同一 (group, item) 对每次包裹 nonce 全新，无复用风险。
pub fn wrap_item_key_with_group(item_key: &[u8; 32], group_key: &GroupKey) -> Vec<u8> {
    crate::crypto::encryption::EncryptionService::new(group_key.as_bytes())
        .encrypt(item_key)
        .expect("AES-GCM with fresh random nonce cannot fail")
}

/// 拆开 group 包裹还原 item key。失败 = group key 不对或包裹被篡改
/// （不区分成因，fail-closed，同 [`super::envelope::open_group_key`]）。
pub fn unwrap_item_key_with_group(
    wrapped: &[u8],
    group_key: &GroupKey,
) -> Result<[u8; 32], PersonaError> {
    let plaintext = crate::crypto::encryption::EncryptionService::new(group_key.as_bytes())
        .decrypt(wrapped)
        .map_err(|_| {
            PersonaError::CryptographicError("failed to unwrap item key with group key".to_string())
        })?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|_| {
        PersonaError::CryptographicError("unwrapped item key has wrong length".to_string())
    })?;
    Ok(bytes)
}

impl Drop for DeviceKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_key_generation_is_unique() {
        let a = GroupKey::generate().unwrap();
        let b = GroupKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// 密钥字节绝不进 Debug/日志输出。
    #[test]
    fn group_key_debug_never_leaks_bytes() {
        let key = GroupKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "GroupKey(<32 bytes>)");
    }

    #[test]
    fn group_key_round_trips_through_bytes() {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let key = GroupKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    /// group key 解出的明文不是 32 字节 item key 时拒绝（协议不变量）。
    #[test]
    fn unwrap_item_key_rejects_wrong_plaintext_length() {
        let group = GroupKey::generate().unwrap();
        let cipher = crate::crypto::encryption::EncryptionService::new(group.as_bytes())
            .encrypt(b"only 7")
            .unwrap();
        let err = unwrap_item_key_with_group(&cipher, &group).unwrap_err();
        assert!(err.to_string().contains("wrong length"), "{err}");
    }

    #[test]
    fn device_keypair_public_is_derived_from_secret() {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        let pair = DeviceKeyPair::from_secret(secret);
        let again = DeviceKeyPair::from_secret(secret);
        assert_eq!(pair.public_bytes(), again.public_bytes());

        // 与 dalek 直接派生一致
        use x25519_dalek::{PublicKey, StaticSecret};
        let expected = PublicKey::from(&StaticSecret::from(secret));
        assert_eq!(pair.public_bytes(), &expected.to_bytes());
    }

    #[test]
    fn device_keypair_generation_is_unique() {
        let a = DeviceKeyPair::generate().unwrap();
        let b = DeviceKeyPair::generate().unwrap();
        assert_ne!(a.secret_bytes(), b.secret_bytes());
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn group_wrap_round_trips_item_key() {
        let group = GroupKey::generate().unwrap();
        let item_key = [7u8; 32];
        let wrapped = wrap_item_key_with_group(&item_key, &group);
        assert_ne!(wrapped[..32], item_key, "包裹必须是密文而非明文透传");
        let opened = unwrap_item_key_with_group(&wrapped, &group).unwrap();
        assert_eq!(opened, item_key);
    }

    #[test]
    fn group_wrap_is_randomized_per_call() {
        let group = GroupKey::generate().unwrap();
        let item_key = [9u8; 32];
        let a = wrap_item_key_with_group(&item_key, &group);
        let b = wrap_item_key_with_group(&item_key, &group);
        assert_ne!(a, b, "随机 nonce 使每次包裹字节不同");
        assert_eq!(
            unwrap_item_key_with_group(&a, &group).unwrap(),
            unwrap_item_key_with_group(&b, &group).unwrap()
        );
    }

    #[test]
    fn wrong_group_key_cannot_unwrap() {
        let group = GroupKey::generate().unwrap();
        let other = GroupKey::generate().unwrap();
        let wrapped = wrap_item_key_with_group(&[1u8; 32], &group);
        assert!(unwrap_item_key_with_group(&wrapped, &other).is_err());
        // 篡改包裹同样 fail-closed
        let mut tampered = wrapped.clone();
        tampered[20] ^= 0xff;
        assert!(unwrap_item_key_with_group(&tampered, &group).is_err());
        // 截断/超长同样报错而非 panic
        assert!(unwrap_item_key_with_group(&wrapped[..16], &group).is_err());
    }
}
