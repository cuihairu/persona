//! 冲突裁决数据面（E2EE_SYNC_DESIGN §7 / 阶段 3c）——把 oplog 冲突区
//! 变成宿主 UI 可消费的形态。
//!
//! 分层口径与会话装配一致：类型与纯逻辑（解密、校验）在本模块，
//! [`super::runtime::SyncSession`] 的 `list_conflicts` / `resolve_conflict`
//! 方法挂在 runtime（需要访问会话私有字段）。裁决语义：
//!
//! - **展示**：每个冲突条目给出主位与全部副本的可对比快照（group key 拆
//!   item key → 开快照；tombstone 版本标 `deleted`）。凭据是原子整体
//!   （DR-4 拍板：否决字段级合并），UI 只做取舍不做合并。
//! - **采纳**：把选中的副本以本机新 lamport 重新入账（put 复用副本
//!   payload 字节——快照与 wrapped item key 都是 group 域的，设备无关；
//!   tombstone 复用空 payload）并按其内容写主库。新 lamport 严格大于
//!   冲突双方 → LWW 自然赢回主位，其余版本全部淘汰出视图（oplog
//!   append-only，数据不丢，只是不再出现在裁决视图）。
//! - **写序**：先主库后 oplog。主库写失败即报错，oplog 未动，重试安全
//!   （重写主库幂等）；oplog 记账失败可重试（主库已是目标内容，重跑
//!   幂等补 op）——两个方向都不产生主库与 oplog 的静默分叉。

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::sync::keys::{unwrap_item_key_with_group, GroupKey};
use crate::sync::oplog::{item_view, ItemKind, SyncOp};
use crate::sync::snapshot::SyncItemSnapshot;

/// 冲突中一个版本的可展示形态。
#[derive(Debug, Clone)]
pub struct ConflictVersion {
    pub op_id: Uuid,
    pub device_id: Uuid,
    pub lamport: u64,
    pub timestamp: Option<DateTime<Utc>>,
    /// tombstone 版本：无快照，`deleted == true`（采纳 = 删除该条目）。
    pub deleted: bool,
    /// put 版本的解密快照。
    pub snapshot: Option<SyncItemSnapshot>,
}

/// 一个条目的冲突视图：主位 + 待裁决副本。
#[derive(Debug, Clone)]
pub struct ConflictEntry {
    pub item_id: Uuid,
    pub primary: ConflictVersion,
    pub copies: Vec<ConflictVersion>,
}

/// 把一条 op 变成可展示版本。put 快照解不开（group 信封坏/密文坏）返回
/// `None`——调用方跳过该条目（损坏副本不可裁决，留驻 oplog），tombstone
/// 恒 `Some`。
pub fn decrypt_version(op: &SyncOp, group: &GroupKey) -> Option<ConflictVersion> {
    let snapshot = match op.payload.as_ref() {
        None if op.is_tombstone() => None,
        None => return None, // put 无 payload：协议不变量违反，不可展示
        Some(payload) => {
            let item_key = unwrap_item_key_with_group(&payload.wrapped_item_key, group).ok()?;
            Some(SyncItemSnapshot::open(&payload.ciphertext, &item_key).ok()?)
        }
    };
    Some(ConflictVersion {
        op_id: op.op_id,
        device_id: op.device_id,
        lamport: op.lamport,
        timestamp: op.timestamp,
        deleted: op.is_tombstone(),
        snapshot,
    })
}

/// 从 op 集合提取冲突条目；任一版本不可解密 → `None`（整条跳过）。
/// 非 Credential 条目的冲突不在裁决范围（捕获/物化都不支持，防御臂）。
pub fn conflict_entry(item_id: Uuid, ops: &[SyncOp], group: &GroupKey) -> Option<ConflictEntry> {
    let view = item_view(ops.to_vec());
    if view.conflicts.is_empty() {
        return None;
    }
    let primary_op = view.primary.as_ref()?;
    if primary_op.kind != ItemKind::Credential {
        return None;
    }
    let primary = decrypt_version(primary_op, group)?;
    let mut copies = Vec::with_capacity(view.conflicts.len());
    for op in &view.conflicts {
        if op.kind != ItemKind::Credential {
            return None;
        }
        copies.push(decrypt_version(op, group)?);
    }
    Some(ConflictEntry {
        item_id,
        primary,
        copies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::{CredentialType, PasswordCredentialData, SecurityLevel};
    use crate::models::CredentialData;
    use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
    use crate::sync::oplog::{ItemKind, OpType, SyncPayload};
    use chrono::Utc;

    fn group() -> GroupKey {
        GroupKey::generate().unwrap()
    }

    fn snapshot(name: &str) -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: name.to_string(),
            credential_type: CredentialType::Password,
            security_level: SecurityLevel::Medium,
            url: None,
            username: None,
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: format!("{name}-secret"),
                email: None,
                security_questions: vec![],
            }),
        }
    }

    fn put_op(
        item_id: Uuid,
        device_id: Uuid,
        lamport: u64,
        snap: &SyncItemSnapshot,
        g: &GroupKey,
    ) -> SyncOp {
        let item_key = crate::crypto::encryption::EncryptionService::generate_key();
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: Some(SyncPayload {
                ciphertext: snap.seal(&item_key).unwrap(),
                wrapped_item_key: wrap_item_key_with_group(&item_key, g),
            }),
        }
    }

    fn delete_op(item_id: Uuid, device_id: Uuid, lamport: u64) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id,
            kind: ItemKind::Credential,
            op: OpType::Delete,
            lamport,
            device_id,
            timestamp: Some(Utc::now()),
            payload: None,
        }
    }

    #[test]
    fn decrypt_version_opens_snapshot_and_marks_tombstone() {
        let g = group();
        let item = Uuid::new_v4();
        let snap = snapshot("a");
        let put = put_op(item, Uuid::new_v4(), 3, &snap, &g);
        let version = decrypt_version(&put, &g).unwrap();
        assert!(!version.deleted);
        assert_eq!(version.snapshot.as_ref().unwrap().name, "a");

        let del = delete_op(item, Uuid::new_v4(), 4);
        let version = decrypt_version(&del, &g).unwrap();
        assert!(version.deleted);
        assert!(version.snapshot.is_none());
    }

    #[test]
    fn decrypt_version_rejects_broken_payload_and_payloadless_put() {
        let g = group();
        let item = Uuid::new_v4();
        // 密文坏：unwrap 通过但快照打不开
        let broken = SyncOp {
            payload: Some(SyncPayload {
                ciphertext: vec![7; 64],
                wrapped_item_key: wrap_item_key_with_group(
                    &crate::crypto::encryption::EncryptionService::generate_key(),
                    &g,
                ),
            }),
            ..put_op(item, Uuid::new_v4(), 1, &snapshot("x"), &g)
        };
        assert!(decrypt_version(&broken, &g).is_none());

        // put 无 payload：协议不变量违反
        let payloadless = SyncOp {
            payload: None,
            ..put_op(item, Uuid::new_v4(), 1, &snapshot("x"), &g)
        };
        assert!(decrypt_version(&payloadless, &g).is_none());
    }

    #[test]
    fn conflict_entry_extracts_primary_and_copies_or_none() {
        let g = group();
        let item = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (winner, loser) = if a > b { (a, b) } else { (b, a) };
        let win_op = put_op(item, winner, 5, &snapshot("win"), &g);
        let lose_op = put_op(item, loser, 5, &snapshot("lose"), &g);

        // 真冲突（同 lamport 异设备）：主位 + 1 副本
        let entry = conflict_entry(item, &[win_op.clone(), lose_op.clone()], &g).unwrap();
        assert_eq!(entry.primary.op_id, win_op.op_id);
        assert_eq!(entry.copies.len(), 1);
        assert_eq!(entry.copies[0].op_id, lose_op.op_id);

        // 单版本（无冲突）→ None
        let lone = put_op(item, Uuid::new_v4(), 1, &snapshot("lone"), &g);
        assert!(conflict_entry(item, &[lone], &g).is_none());

        // 任一版本损坏 → 整条跳过
        let broken = SyncOp {
            payload: Some(SyncPayload {
                ciphertext: vec![7; 64],
                wrapped_item_key: wrap_item_key_with_group(
                    &crate::crypto::encryption::EncryptionService::generate_key(),
                    &g,
                ),
            }),
            ..put_op(item, Uuid::new_v4(), 9, &snapshot("broken"), &g)
        };
        assert!(conflict_entry(item, &[win_op, lose_op, broken], &g).is_none());
    }

    #[test]
    fn conflict_entry_skips_non_credential_kinds() {
        let g = group();
        let item = Uuid::new_v4();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mk = |device: Uuid, lamport: u64, kind: ItemKind| SyncOp {
            op_id: Uuid::new_v4(),
            item_id: item,
            kind,
            op: OpType::Put,
            lamport,
            device_id: device,
            timestamp: None,
            payload: None,
        };
        // put 无 payload 本就不可解密，但 kind 校验先行：非 Credential 冲突不进裁决
        assert!(conflict_entry(
            item,
            &[mk(a, 5, ItemKind::Identity), mk(b, 5, ItemKind::Identity)],
            &g
        )
        .is_none());
    }
}
