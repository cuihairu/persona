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
}
