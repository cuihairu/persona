//! `SyncSession` 密钥轮换域（LAY-021 拆分）：`rewrap_all` 全量重包、
//! `drain_push_queue` 推空本地队列、`rotate_group_key` 安全轮换
//!（E2EE_SYNC_DESIGN DR-3、§11 开放问题 2）。

use super::*;

impl<R: SyncRemote> SyncSession<R> {
    /// 全量重包：主库每条凭据以新组密钥重新密封快照 + 重包 item key，
    /// 各记一个新 lamport 的 put（LWW 使其成为主位）。与 backfill 同型
    /// 路径但**不跳过已入队条目**——轮换要求全部现存凭据换新密文。
    /// 返回（重包数，跳过数）。
    pub async fn rewrap_all(
        &self,
        master: &EncryptionService,
        new_group: &GroupKey,
    ) -> Result<(u64, u64)> {
        let cred_repo = CredentialRepository::new(self.db.clone());
        let all = cred_repo.list_all().await?;
        let hierarchy = KeyHierarchy::new(master);
        let mut rewrapped: u64 = 0;
        let mut skipped: u64 = 0;
        for credential in all {
            let Some(wrapped) = credential.wrapped_item_key.as_ref() else {
                tracing::warn!(
                    credential_id = %credential.id,
                    "legacy credential without wrapped item key; rewrap skipped"
                );
                skipped += 1;
                continue;
            };
            // 失败逐条跳过（坏行不阻断整批），与捕获缝的容错口径一致
            let item_key = match hierarchy.unwrap_item_key(wrapped) {
                Ok(item_key) => item_key,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "item key unwrap failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let plaintext = match hierarchy
                .decrypt_with_wrapped_key(wrapped, &credential.encrypted_data)
            {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "credential decrypt failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let data = match CredentialData::from_bytes(&plaintext) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "malformed credential data; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let sealed = match SyncItemSnapshot::from_credential(&credential, &data).seal(&item_key)
            {
                Ok(sealed) => sealed,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "snapshot seal failed; rewrap skipped");
                    skipped += 1;
                    continue;
                }
            };
            let payload = SyncPayload {
                ciphertext: sealed,
                wrapped_item_key: wrap_item_key_with_group(&item_key, new_group),
            };
            match self
                .engine
                .record_local_change(
                    credential.id,
                    ItemKind::Credential,
                    OpType::Put,
                    Some(payload),
                )
                .await
            {
                Ok(_) => rewrapped += 1,
                Err(e) => {
                    tracing::warn!(credential_id = %credential.id, error = %e, "oplog record failed; rewrap skipped");
                    skipped += 1;
                }
            }
        }
        Ok((rewrapped, skipped))
    }

    /// 把本地 push 队列推空（push_cycle 单轮 ≤500 条，循环到推不动为
    /// 止）。返回总推送条数。
    #[cfg(feature = "remote-auth")]
    pub(super) async fn drain_push_queue(&self) -> Result<u64> {
        let mut total: u64 = 0;
        loop {
            let report = self.engine.push_cycle().await?;
            total += report.pushed as u64;
            if report.pushed == 0 {
                return Ok(total);
            }
        }
    }

    /// group key 轮换（DR-3「安全轮换」，吊销设备真正闭环的 v1）：
    ///
    /// 1. 先把本机 pending 全部推走——旧组密文在换 key 前上线，仍持有
    ///    旧 key 的保留设备还来得及拉取；
    /// 2. 生成新 group key，为**每个已授权设备**（含本机）重封信封上传
    ///    （put_group_key 幂等 upsert；被吊销设备无信封自然跳过）；
    /// 3. [`Self::rewrap_all`] 全量重包 + 推空队列。
    ///
    /// 换 key 后各设备**零客户端改动**：`SyncSession::open` 每次拆本机
    /// 信封，下次同步天然拿到新 key；轮换者的本会话继续持有旧 key（不
    /// 回写），宿主用完即弃即可。旧组密文留驻服务器 oplog，只有新信封
    /// 的设备拆不开、按既有容错跳过——当前态由重包 op 完整补齐。
    ///
    /// 诚实边界（UI/文档须如实提示）：(a) 窗口内其他设备**尚未推送**的
    /// 本地改动仍以旧 key 入账，轮换者与新设备拆不开会按容错跳过——
    /// 轮换前应让所有保留设备各完成一次「立即同步」；(b) 未裁决的冲突
    /// 副本随重包 op 成为主位而清出裁决视图（主库当前态为准，oplog
    /// append-only 原始记录仍在）；(c) 并发轮换以 epoch 乐观锁互斥
    /// （2026-09-24）：本机读基线代数后 `begin_group_rotation` CAS 抢占，
    /// 另一台设备已抢先轮换时返回
    /// [`PersonaError::ConcurrentConflict`] fail-closed 中止——此时本机
    /// 未写任何信封、未重包，重新同步后重试即可；begin 之后本机崩溃则
    /// 信封族停留混合态，重试即重跑（幂等面不变；混合态自愈语义由
    /// server 真 TCP 集成测试 `crashed_mid_rotation_retry_rewrites_
    /// envelopes_and_converges` 锁定——残留信封被 upsert 覆盖，全组收敛）。
    #[cfg(feature = "remote-auth")]
    pub async fn rotate_group_key(
        &self,
        master: &EncryptionService,
        admin: &crate::sync::remote::SyncAdminApi,
    ) -> Result<SyncRotateReport> {
        // 1. 旧组密文先上线（此时其他保留设备的旧 key 仍有效）
        let pushed_before = self.drain_push_queue().await?;

        // 2. 已授权设备集 = 有信封的设备；生成新 key 并逐设备重封上传。
        //    写信封族前先抢轮换互斥（epoch CAS）：读到的基线若已被并发
        //    轮换者推进，409/ConcurrentConflict 在此干净中止。
        let devices = admin.list_devices().await?;
        let (keys, epoch) = admin.group_keys_with_epoch().await?;
        let authorized: std::collections::HashSet<Uuid> =
            keys.iter().map(|k| k.device_id).collect();
        admin.begin_group_rotation(epoch).await?;
        let new_group = GroupKey::generate()?;
        for device in &devices {
            if !authorized.contains(&device.id) {
                continue;
            }
            let envelope =
                crate::sync::envelope::seal_group_key(new_group.as_bytes(), &device.public_key)?;
            admin.put_group_key(device.id, &envelope).await?;
        }

        // 3. 全量重包入账 + 推空
        let (rewrapped, skipped) = self.rewrap_all(master, &new_group).await?;
        let pushed_after = self.drain_push_queue().await?;

        Ok(SyncRotateReport {
            rewrapped,
            skipped,
            pushed: pushed_before + pushed_after,
        })
    }
}
