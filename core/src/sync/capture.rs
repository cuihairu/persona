//! service 写路径 → 同步 oplog 的捕获缝（E2EE_SYNC_DESIGN §5「捕获点」）。
//!
//! `PersonaService` 在与 change_history 相同的调用点把条目级变更交给
//! [`SyncCapture`]：**只递条目密文与 item key 明文**，不持 group key——
//! group 包裹（[`super::keys::wrap_item_key_with_group`]）与
//! `SyncEngine::record_local_change` 都在装配层实现里做，保持密钥分层
//! （group key 只属于同步装配层，service 的解锁会话里永远没有它）。
//!
//! 容错语义与 `record_credential_history` 一致：捕获失败/未装配不得阻断
//! 主操作。trait 方法返回 `()`（实现方自行 log），service 侧调用前也
//! 不做可失败的准备工作——同步在本产品里是尽力而为的旁路，主库才是
//! 第一事实源（STORAGE_AND_SYNC 原则句）。

use std::sync::Arc;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::sync::engine::{SyncEngine, SyncRemote};
use crate::sync::keys::{wrap_item_key_with_group, GroupKey};
use crate::sync::oplog::{ItemKind, OpType, SyncPayload};

/// 条目级变更捕获（装配层实现；未装配时 service 侧零开销跳过）。
#[async_trait::async_trait]
pub trait SyncCapture: Send + Sync {
    /// `put`：带同步快照密文（[`super::snapshot::SyncItemSnapshot`] 密封，
    /// 元数据 + CredentialData 复合）与 item key 明文（实现方包完 group
    /// 信封即刻丢弃——`Zeroizing` 保证）；`delete`：两者皆 `None`
    /// （tombstone，payload 恒空）。
    async fn capture(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    );
}

/// 默认装配实现：group 包裹 + oplog 记账。
///
/// service 递来的 item key 在此用 group key 包成
/// `SyncPayload.wrapped_item_key`，随快照密文一起交给
/// [`SyncEngine::record_local_change`];之后 `item_key`（`Zeroizing`）离开
/// 作用域即清零。失败只 log 不上抛（trait 契约：捕获是尽力而为的旁路）。
pub struct OplogCapture<R: SyncRemote> {
    engine: Arc<SyncEngine<R>>,
    group_key: GroupKey,
}

impl<R: SyncRemote> OplogCapture<R> {
    pub fn new(engine: Arc<SyncEngine<R>>, group_key: GroupKey) -> Self {
        Self { engine, group_key }
    }
}

#[async_trait::async_trait]
impl<R: SyncRemote> SyncCapture for OplogCapture<R> {
    async fn capture(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        let payload = match (op, ciphertext, item_key) {
            (OpType::Put, Some(ciphertext), Some(item_key)) => Some(SyncPayload {
                ciphertext,
                wrapped_item_key: wrap_item_key_with_group(&item_key, &self.group_key),
            }),
            (OpType::Delete, None, None) => None,
            _ => {
                tracing::warn!(item_id = %item_id, op = ?op, "sync capture payload mismatch; dropped");
                return;
            }
        };
        if let Err(e) = self
            .engine
            .record_local_change(item_id, kind, op, payload)
            .await
        {
            tracing::warn!(item_id = %item_id, error = %e, "sync capture failed (best-effort bypass)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encryption::EncryptionService;
    use crate::models::{CredentialData, PasswordCredentialData};
    use crate::storage::sync_repository::SyncRepository;
    use crate::sync::engine::SyncRemote;
    use crate::sync::keys::unwrap_item_key_with_group;
    use crate::sync::oplog::SyncOp;
    use crate::sync::snapshot::SyncItemSnapshot;
    use crate::{Database, PersonaError, Result};

    struct DeadRemote;
    #[async_trait::async_trait]
    impl SyncRemote for DeadRemote {
        async fn push_ops(&self, _ops: &[SyncOp]) -> Result<(u64, u64)> {
            Err(PersonaError::InvalidInput("dead remote".into()).into())
        }
        async fn pull_ops(
            &self,
            _since: Option<&str>,
            _limit: u32,
        ) -> Result<(Vec<SyncOp>, Option<String>)> {
            Ok((vec![], None))
        }
    }

    fn sample_snapshot() -> SyncItemSnapshot {
        SyncItemSnapshot {
            identity_id: Uuid::new_v4(),
            name: "端到端".to_string(),
            credential_type: crate::models::CredentialType::Password,
            security_level: crate::models::SecurityLevel::High,
            url: None,
            username: Some("e2e@example.com".to_string()),
            notes: None,
            tags: vec![],
            metadata: Default::default(),
            is_favorite: false,
            is_active: true,
            data: CredentialData::Password(PasswordCredentialData {
                password: "pw".to_string(),
                email: None,
                security_questions: vec![],
            }),
        }
    }

    #[tokio::test]
    async fn oplog_capture_wraps_group_and_records_into_oplog() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            DeadRemote,
            Uuid::new_v4(),
            Box::new(|| false),
        ));
        let group = GroupKey::generate().unwrap();
        let capture = OplogCapture::new(engine.clone(), group.clone());

        let item_id = Uuid::new_v4();
        let snapshot = sample_snapshot();
        let item_key = EncryptionService::generate_key();
        capture
            .capture(
                item_id,
                ItemKind::Credential,
                OpType::Put,
                Some(snapshot.seal(&item_key).unwrap()),
                Some(Zeroizing::new(item_key)),
            )
            .await;

        // oplog 里恰好一条本地 op,payload 两级密文齐备
        let ops = SyncRepository::new(db).item_ops(item_id).await.unwrap();
        assert_eq!(ops.len(), 1);
        let payload = ops[0].payload.as_ref().unwrap();

        // group key 能还原 item key,进而解出快照——完整装配链
        let recovered_key = unwrap_item_key_with_group(&payload.wrapped_item_key, &group).unwrap();
        let opened = SyncItemSnapshot::open(&payload.ciphertext, &recovered_key).unwrap();
        assert_eq!(opened.name, "端到端");
        assert_eq!(opened.username.as_deref(), Some("e2e@example.com"));

        // lamport 从 1 起步,device_id 取 engine 的
        assert_eq!(ops[0].lamport, 1);
    }

    #[tokio::test]
    async fn oplog_capture_records_tombstone_without_payload() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let engine = Arc::new(SyncEngine::new(
            SyncRepository::new(db.clone()),
            DeadRemote,
            Uuid::new_v4(),
            Box::new(|| false),
        ));
        let capture = OplogCapture::new(engine.clone(), GroupKey::generate().unwrap());

        let item_id = Uuid::new_v4();
        capture
            .capture(item_id, ItemKind::Credential, OpType::Delete, None, None)
            .await;
        capture
            .capture(item_id, ItemKind::Credential, OpType::Put, None, None) // put 缺 payload:不记账
            .await;

        let ops = SyncRepository::new(db).item_ops(item_id).await.unwrap();
        assert_eq!(ops.len(), 1, "put 缺 payload 的畸形的调用被丢弃");
        assert_eq!(ops[0].op, OpType::Delete);
        assert!(ops[0].payload.is_none());
    }
}
