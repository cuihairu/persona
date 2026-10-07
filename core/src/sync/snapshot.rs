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
use crate::sync::oplog::SyncOp;
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

/// 库级快照包（S2 收口，E2EE_SYNC_DESIGN §5「库级快照与指令压缩」）：
/// 某一服务器 seq 处的整库状态包——本机 oplog 的**视图充分集**（每条目的
/// 主位 op + 未裁决冲突副本，tombstone 主位同样在场；被 GC 的旧版本视图
/// 中性故缺席）。整包再用 group key 加密后上云——服务器只见一个 BLOB
/// （单快照 upsert + 压缩 `seq ≤ S` 的 ops）。
///
/// **打包原 op 而非凭据表行**（装包 = 按 op_id 幂等入本地 oplog + 既有物化
/// 路径，全链路复用）：
///
/// - **pending identity 不丢**：新设备缺身份行时 `materialize_put` 会
///   `SkippedPendingIdentity`——凭据表快照会把条目直接丢弃而其 op 已被
///   压缩（真数据洞）；op 入 oplog 则与全量重放同款挂起重试。
/// - **冲突副本不丢**：未裁决双版本是「数据不丢」底线的一部分，快照点
///   前的冲突 ops 同样被压缩。
/// - **tombstone 在场防复活**：`seq ≤ S` 被压缩后「点后增量」并不携带
///   快照点前的删除；快照缺席删除会让装到非空库的设备复活已删条目。
/// - **LWW 全序原样**：op_id/lamport/device_id 原封搬运，装包设备的
///   `item_view` 与未走快照的老设备逐条同序——「快照起步 + 点后增量 ==
///   全量重放」按视图相等（收敛等价性测试锚点的口径）。
///
/// 零知识不变式与单条快照相同：条目名/域名/用户名/口令只存在于 item key
/// 密文内，item key 只存在于 group key 密文内；包装格式错误一律
/// fail-closed（覆盖区间可能已被压缩删除，静默降级为全量重放不可行）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LibrarySnapshotPayload {
    /// 打包时刻（rfc3339，仅展示）。
    pub created_at: String,
    /// 视图充分集：主位（put 或 tombstone）+ 冲突副本，按条目收拢。
    pub ops: Vec<SyncOp>,
}

/// 快照上传触发阈值（E2EE_SYNC_DESIGN §5「触发时机」）：push ack 后
/// `head_seq − last_snapshot_seq > 此值` 才重打包（防频繁重打包）。
/// 配置化口径：CLI/桌面不暴露。
pub const UPLOAD_THRESHOLD_OPS: i64 = 1000;

impl LibrarySnapshotPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// group key 整包加密（服务器存储字节）。
    pub fn seal(&self, group_key: &super::keys::GroupKey) -> Result<Vec<u8>> {
        EncryptionService::new(group_key.as_bytes())
            .encrypt(&self.to_bytes()?)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("failed to seal library snapshot: {e}"))
                    .into()
            })
    }

    /// 拆封（bootstrap 路径；group key 不对或密文被篡改 fail-closed）。
    pub fn open(sealed: &[u8], group_key: &super::keys::GroupKey) -> Result<Self> {
        let plaintext = EncryptionService::new(group_key.as_bytes())
            .decrypt(sealed)
            .map_err(|_| {
                PersonaError::CryptographicError(
                    "failed to open library snapshot with group key".to_string(),
                )
            })?;
        Self::from_bytes(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PasswordCredentialData;
    use crate::sync::oplog::{ItemKind, OpType, SyncPayload};

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

    // ---- 库级快照包（S2，E2EE_SYNC_DESIGN §5）----

    /// 一条与打包路径同构的 op（put 带单条快照密文；tombstone payload 恒空）。
    fn library_op(
        item_key: &[u8; 32],
        group: &crate::sync::keys::GroupKey,
        lamport: u64,
        op: OpType,
    ) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            kind: ItemKind::Credential,
            op,
            lamport,
            device_id: Uuid::new_v4(),
            timestamp: None,
            payload: (op == OpType::Put).then(|| SyncPayload {
                ciphertext: sample().seal(item_key).unwrap(),
                wrapped_item_key: crate::sync::keys::wrap_item_key_with_group(item_key, group),
            }),
        }
    }

    fn library_sample(group: &crate::sync::keys::GroupKey) -> LibrarySnapshotPayload {
        let item_key = EncryptionService::generate_key();
        LibrarySnapshotPayload {
            created_at: "2026-10-07T00:00:00Z".to_string(),
            // 视图充分集：put 主位 + tombstone 主位（防删除复活）
            ops: vec![
                library_op(&item_key, group, 1, OpType::Put),
                library_op(&item_key, group, 2, OpType::Delete),
            ],
        }
    }

    #[test]
    fn library_snapshot_seal_open_round_trips_with_group_key() {
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let payload = library_sample(&group);
        let sealed = payload.seal(&group).unwrap();
        assert_ne!(sealed, payload.to_bytes().unwrap(), "整包必须是密文");

        let opened = LibrarySnapshotPayload::open(&sealed, &group).unwrap();
        assert_eq!(opened.ops.len(), 2);
        assert_eq!(opened.created_at, payload.created_at);
        // op 全字段原样（LWW 全序与 op_id 幂等都靠 op_id/lamport/device_id
        // 不走样——装包设备与老设备的 item_view 因此逐条同序）
        assert_eq!(opened.ops, payload.ops);
        // tombstone 主位在场且 payload 恒空
        assert!(opened.ops[1].is_tombstone());
        assert!(opened.ops[1].payload.is_none());

        // 逐条解链：group key → item key → 单条快照明文（物化路径原样）
        let put = opened.ops[0].payload.as_ref().expect("put 必带 payload");
        let item_key =
            crate::sync::keys::unwrap_item_key_with_group(&put.wrapped_item_key, &group).unwrap();
        let snap = SyncItemSnapshot::open(&put.ciphertext, &item_key).unwrap();
        assert_eq!(snap.name, "Email 邮箱");
        assert_eq!(snap.username.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn library_snapshot_wrong_group_key_and_tamper_fail_closed() {
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let sealed = library_sample(&group).seal(&group).unwrap();
        let other = crate::sync::keys::GroupKey::generate().unwrap();
        assert!(
            LibrarySnapshotPayload::open(&sealed, &other).is_err(),
            "错 key 必须 fail-closed（静默降级为全量重放不可行——区间可能已被压缩）"
        );
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(LibrarySnapshotPayload::open(&tampered, &group).is_err());
        assert!(LibrarySnapshotPayload::open(&sealed[..12], &group).is_err());
    }

    #[test]
    fn library_snapshot_bytes_never_leak_entry_plaintext() {
        // 零知识平移：整包字节里搜不到条目名/域名/用户名/口令与密钥原字节
        let group = crate::sync::keys::GroupKey::generate().unwrap();
        let item_key = EncryptionService::generate_key();
        let snap = SyncItemSnapshot {
            name: "机密条目Bravo".to_string(),
            url: Some("https://secret-site-b.example/login".to_string()),
            username: Some("bob@example.com".to_string()),
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            identity_id: Uuid::new_v4(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::High,
            data: CredentialData::Password(PasswordCredentialData {
                password: "特征口令-Δ9".to_string(),
                email: None,
                security_questions: vec![],
            }),
        };
        let payload = LibrarySnapshotPayload {
            created_at: "2026-10-07T00:00:00Z".to_string(),
            ops: vec![SyncOp {
                op_id: Uuid::new_v4(),
                item_id: Uuid::new_v4(),
                kind: ItemKind::Credential,
                op: OpType::Put,
                lamport: 1,
                device_id: Uuid::new_v4(),
                timestamp: None,
                payload: Some(SyncPayload {
                    ciphertext: snap.seal(&item_key).unwrap(),
                    wrapped_item_key: crate::sync::keys::wrap_item_key_with_group(
                        &item_key, &group,
                    ),
                }),
            }],
        };
        let stored = payload.seal(&group).unwrap();
        for plaintext in [
            "机密条目Bravo".as_bytes(),
            b"secret-site-b.example",
            b"bob@example.com",
            "特征口令-Δ9".as_bytes(),
        ] {
            assert!(
                !stored.windows(plaintext.len()).any(|w| w == plaintext),
                "整包字节泄露明文: {}",
                String::from_utf8_lossy(plaintext)
            );
        }
        assert!(
            !stored.windows(32).any(|w| w == item_key.as_slice()),
            "item key 原始字节泄露"
        );
        assert!(
            !stored.windows(32).any(|w| w == group.as_bytes().as_slice()),
            "group key 原始字节泄露"
        );
    }
}
