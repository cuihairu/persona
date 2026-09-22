//! 同步条目快照（E2EE_SYNC_DESIGN §5）——oplog payload 密文的明文格式。
//!
//! 主库凭据行 = 明文元数据列 + `encrypted_data`（只含 [`CredentialData`]）。
//! 远端设备要物化出同样的行，光有 `CredentialData` 不够——所以同步 payload
//! 的密文携带**完整条目快照**：元数据 + `CredentialData` 复合序列化后用
//! item key 一次性加密。主库密文与同步密文因此是两份不同字节（同一把
//! item key）；「oplog 只持密文」不变，服务器两级都不可读。
//!
//! 格式：`bincode(SyncItemSnapshot)` → `EncryptionService`（随机 nonce 前置
//! 12B ‖ AES-256-GCM）。与 [`CredentialData`] 同款编码管线，字段演进靠
//! bincode 默认的严格性——不识别的字节流直接报错（fail-closed），未来加
//! 字段时升版本号再兼容。

use std::collections::HashMap;

use uuid::Uuid;

use crate::crypto::encryption::EncryptionService;
use crate::models::{Credential, CredentialData, CredentialType, SecurityLevel};
use crate::{PersonaError, Result};

/// 凭据条目的同步快照：远端物化一行凭据所需的全部语义字段。
///
/// **不含**设备本地的时间戳（`created_at`/`updated_at`/`last_accessed`）——
/// 它们是设备本地事实，跨设备复制只会制造噪音；物化时保留接收方已有行的
/// 本地时间戳（新行用物化时刻）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncItemSnapshot {
    pub identity_id: Uuid,
    pub name: String,
    pub credential_type: CredentialType,
    pub security_level: SecurityLevel,
    pub url: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub is_favorite: bool,
    pub is_active: bool,
    pub data: CredentialData,
}

impl SyncItemSnapshot {
    /// 从本地凭据行 + 已解密的 `CredentialData` 组装快照。
    pub fn from_credential(credential: &Credential, data: &CredentialData) -> Self {
        Self {
            identity_id: credential.identity_id,
            name: credential.name.clone(),
            credential_type: credential.credential_type.clone(),
            security_level: credential.security_level.clone(),
            url: credential.url.clone(),
            username: credential.username.clone(),
            notes: credential.notes.clone(),
            tags: credential.tags.clone(),
            metadata: credential.metadata.clone(),
            is_favorite: credential.is_favorite,
            is_active: credential.is_active,
            data: data.clone(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// 用 item key 加密封条（同步 payload 的 `ciphertext` 字段）。
    pub fn seal(&self, item_key: &[u8; 32]) -> Result<Vec<u8>> {
        EncryptionService::new(item_key)
            .encrypt(&self.to_bytes()?)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("failed to seal snapshot: {e}")).into()
            })
    }

    /// 拆封（物化路径；key 不对或密文被篡改一律 fail-closed）。
    pub fn open(sealed: &[u8], item_key: &[u8; 32]) -> Result<Self> {
        let plaintext = EncryptionService::new(item_key)
            .decrypt(sealed)
            .map_err(|_| {
                PersonaError::CryptographicError(
                    "failed to open snapshot with item key".to_string(),
                )
            })?;
        Self::from_bytes(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordCredentialData;

    fn sample() -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: "Email 邮箱".to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::High,
            url: Some("https://example.com".to_string()),
            username: Some("alice@example.com".to_string()),
            notes: Some("备注\n第二行".to_string()),
            tags: vec!["work".to_string(), "重要".to_string()],
            metadata: HashMap::from([("region".to_string(), "cn-north".to_string())]),
            is_favorite: true,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: "s3cret-π".to_string(),
                email: Some("alice@example.com".to_string()),
                security_questions: vec![],
            }),
        }
    }

    #[test]
    fn snapshot_bytes_round_trip_preserves_every_field() {
        let snap = sample();
        let opened = SyncItemSnapshot::from_bytes(&snap.to_bytes().unwrap()).unwrap();
        assert_eq!(opened.to_bytes().unwrap(), snap.to_bytes().unwrap());
    }

    #[test]
    fn seal_open_round_trips_with_item_key() {
        let snap = sample();
        let item_key = EncryptionService::generate_key();
        let sealed = snap.seal(&item_key).unwrap();
        assert_ne!(sealed, snap.to_bytes().unwrap(), "密封后必须是密文");
        assert_eq!(
            SyncItemSnapshot::open(&sealed, &item_key)
                .unwrap()
                .to_bytes()
                .unwrap(),
            snap.to_bytes().unwrap()
        );
    }

    #[test]
    fn wrong_item_key_cannot_open_snapshot() {
        let snap = sample();
        let sealed = snap.seal(&EncryptionService::generate_key()).unwrap();
        assert!(SyncItemSnapshot::open(&sealed, &EncryptionService::generate_key()).is_err());
        // 篡改与截断同样报错而非 panic
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(SyncItemSnapshot::open(&tampered, &EncryptionService::generate_key()).is_err());
        assert!(SyncItemSnapshot::open(&sealed[..12], &EncryptionService::generate_key()).is_err());
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicking() {
        assert!(SyncItemSnapshot::from_bytes(b"not bincode").is_err());
        assert!(SyncItemSnapshot::from_bytes(&[0u8; 4]).is_err());
    }

    #[test]
    fn from_credential_maps_every_semantic_field() {
        let credential = Credential::new(
            Uuid::new_v4(),
            "Bank".to_string(),
            CredentialType::BankCard,
            SecurityLevel::High,
            vec![1, 2, 3],
            None,
        );
        let data = CredentialData::Password(PasswordCredentialData {
            password: "x".to_string(),
            email: None,
            security_questions: vec![],
        });
        let snap = SyncItemSnapshot::from_credential(&credential, &data);
        assert_eq!(snap.identity_id, credential.identity_id);
        assert_eq!(snap.name, "Bank");
        assert_eq!(snap.credential_type, CredentialType::BankCard);
        assert_eq!(snap.data.to_bytes().unwrap(), data.to_bytes().unwrap());
    }
}
