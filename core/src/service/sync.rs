use super::*;

impl PersonaService {
    /// 把一次条目级写变更交给同步捕获缝（未装配即零开销跳过）。
    ///
    /// 容错语义与 [`Self::record_credential_history`] 一致：捕获是尽力而为
    /// 的旁路（trait 方法返回 `()`，实现方自行 log），service 侧不做任何
    /// 可失败的准备——主库才是第一事实源。
    pub(crate) async fn capture_sync(
        &self,
        item_id: Uuid,
        kind: ItemKind,
        op: OpType,
        ciphertext: Option<Vec<u8>>,
        item_key: Option<Zeroizing<[u8; 32]>>,
    ) {
        let capture = self.sync_capture.read().await.clone();
        if let Some(capture) = capture {
            capture
                .capture(item_id, kind, op, ciphertext, item_key)
                .await;
        }
    }

    /// 为元数据级写变更（[`Self::update_credential`] / restore）构建同步
    /// put 载荷：解密现 payload 组装完整条目快照再密封。legacy 行（无
    /// per-item key）返回 `None`——它还不能与同步信封共享 item key，跳过
    /// 捕获；首次 [`Self::update_credential_data`] 会把它升级，此后恢复捕获。
    pub(crate) async fn sync_put_payload_for(
        &self,
        credential: &Credential,
    ) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let data = self.decrypt_credential(credential).ok()?;
        let master_encryption = self.get_master_encryption_service().ok()?;
        let item_key = KeyHierarchy::new(master_encryption)
            .unwrap_item_key(credential.wrapped_item_key.as_ref()?)
            .ok()?;
        match SyncItemSnapshot::from_credential(credential, &data).seal(&item_key) {
            Ok(sealed) => Some((sealed, Zeroizing::new(item_key))),
            Err(e) => {
                tracing::warn!(
                    credential_id = %credential.id,
                    error = %e,
                    "sync snapshot seal failed; capture skipped"
                );
                None
            }
        }
    }

    /// 记一条凭据历史行（created/updated/deleted/restored 由 change_type 区分）。
    ///
    /// - Updated 且无实质字段变化时不记（CLI/桌面 create 后紧跟的元数据
    ///   补写不产生噪声行）
    /// - version 取该实体当前最大版本 +1
    /// - `reason` 可选（restore 用来标注目标版本）
    /// - 记录失败仅告警不阻断主操作（与 log_audit 的尽力而为一致）：
    ///   主写已提交，历史是派生数据，不能让历史失败回滚业务事实
    pub(crate) async fn record_credential_history(
        &self,
        change_type: ChangeType,
        previous: Option<&Credential>,
        current: Option<&Credential>,
        reason: Option<String>,
    ) {
        let entity_id = match (current, previous) {
            (Some(c), _) => c.id,
            (None, Some(p)) => p.id,
            (None, None) => return,
        };

        let mut entry = ChangeHistory::new(EntityType::Credential, entity_id, change_type);
        if let Some(user) = self.current_user {
            entry = entry.with_user(user.to_string());
        }
        if let Some(reason) = reason {
            entry = entry.with_reason(reason);
        }

        match (previous, current) {
            (Some(old), Some(new)) => {
                let changes = Self::diff_credential_metadata(old, new);
                if changes.is_empty() {
                    return;
                }
                entry = entry.with_states(
                    Some(Self::credential_meta_snapshot(old)),
                    Some(Self::credential_meta_snapshot(new)),
                );
                for (field, old_value, new_value) in changes {
                    entry.add_field_change(field.to_string(), old_value, new_value);
                }
            }
            (None, Some(new)) => {
                entry = entry.with_states(None, Some(Self::credential_meta_snapshot(new)));
            }
            (Some(old), None) => {
                entry = entry.with_states(Some(Self::credential_meta_snapshot(old)), None);
            }
            (None, None) => return,
        }

        let version = self
            .change_history_repo
            .get_latest_version(EntityType::Credential, &entity_id)
            .await
            .unwrap_or(0)
            + 1;
        entry.version = version;

        if let Err(e) = self.change_history_repo.record(&entry).await {
            tracing::warn!("failed to record credential history: {}", e);
        }
    }
}
