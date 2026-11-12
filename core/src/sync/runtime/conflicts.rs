//! `SyncSession` 冲突裁决域（LAY-021 拆分）：`list_conflicts` /
//! `conflict_item_count` / `resolve_conflict`（谓词矩阵见 `super::resolve`）。

use super::*;

impl<R: SyncRemote> SyncSession<R> {
    /// 冲突裁决视图（阶段 3c）：全部待裁决条目（主位 + 副本的解密快照）。
    /// 任一版本解不开（损坏）的条目整条跳过——不可裁决但留驻 oplog，
    /// 不阻塞其余条目的展示。
    pub async fn list_conflicts(&self) -> Result<Vec<ConflictEntry>> {
        let mut entries = Vec::new();
        for item_id in self.sync_repo.item_ids().await? {
            let ops = self.sync_repo.item_ops(item_id).await?;
            if let Some(entry) = resolve::conflict_entry(item_id, &ops, &self.group_key) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.item_id);
        Ok(entries)
    }

    /// 当前待裁决的冲突条目数（run_cycle 报告的 `conflicts` 真值）。
    pub async fn conflict_item_count(&self) -> Result<usize> {
        Ok(self.list_conflicts().await?.len())
    }

    /// 裁决：采纳一个冲突副本。副本内容以本机新 lamport 重新入账
    /// （put 复用副本 payload 字节——快照与 wrapped item key 都是 group 域
    /// 的，设备无关；tombstone 复用空 payload），并按其内容写主库。新
    /// lamport 严格大于冲突双方 → LWW 自然赢回主位，其余版本全部淘汰出
    /// 裁决视图（oplog append-only，数据不丢，只是不再出现在视图里）。
    ///
    /// 写序 = 先主库后 oplog（见 [`crate::sync::resolve`] 模块文档）：主库失败
    /// 即 Err（oplog 未动，重试安全）；oplog 失败可重试（重写主库幂等）。
    /// 副本引用的身份尚未同步时主库写不了 → Err 且绝不记账（记 op 不写
    /// 主库 = 静默分叉，下一轮同步补齐身份后再裁决）。
    pub async fn resolve_conflict(
        &self,
        master: &EncryptionService,
        item_id: Uuid,
        adopt_op_id: Uuid,
    ) -> Result<()> {
        let view = item_view(self.sync_repo.item_ops(item_id).await?);
        let Some(adopted) = view.conflicts.iter().find(|op| op.op_id == adopt_op_id) else {
            // 副本不存在 = 已被裁决过（采纳任一版本后其余版本淘汰出视图）
            // 或 op_id 打错——同一句话报给调用方。
            return Err(PersonaError::NotFound(format!(
                "conflict copy {adopt_op_id} not found for item {item_id} (already resolved?)"
            ))
            .into());
        };
        if adopted.kind != ItemKind::Credential {
            return Err(PersonaError::InvalidInput(format!(
                "conflict resolution only supports credential entries, got {:?}",
                adopted.kind
            ))
            .into());
        }
        let (kind, op, payload) = (adopted.kind, adopted.op, adopted.payload.clone());

        // 先主库后 oplog。
        match op {
            OpType::Put => {
                let Some(payload) = payload.as_ref() else {
                    return Err(PersonaError::InvalidInput(
                        "cannot adopt a put copy without payload".to_string(),
                    )
                    .into());
                };
                let outcome = Materializer::new(self.db.clone())
                    .materialize_put(
                        &item_id,
                        &payload.ciphertext,
                        &payload.wrapped_item_key,
                        master,
                        &self.group_key,
                    )
                    .await?;
                if let MaterializeOutcome::SkippedPendingIdentity { identity_id } = outcome {
                    return Err(PersonaError::Validation(format!(
                        "adopted copy references identity {identity_id} that is not synced yet; \
                         resolve again after the next sync"
                    ))
                    .into());
                }
            }
            OpType::Delete => {
                Materializer::new(self.db.clone())
                    .materialize_delete(&item_id)
                    .await?;
            }
        }

        // 入账前防御性时钟推进：保证本机新 op 的 lamport 严格大于被采纳
        // 副本。正常流程 pull 已 bump 过时钟（record 的 local+1 已够大）；
        // 直连裁决（不经 run_cycle）时本机时钟可能仍停在副本同高，先 MAX
        // 推进。放在主库写之后——前置校验失败（上方 Err 臂）零副作用。
        let local = self.sync_repo.get_state().await?.local_lamport;
        if local <= adopted.lamport {
            self.sync_repo.bump_lamport(adopted.lamport + 1).await?;
        }

        // oplog 记账：本机新 lamport 的采纳 op 入 push 队列，随下轮推走。
        self.engine
            .record_local_change(item_id, kind, op, payload)
            .await?;
        Ok(())
    }
}
