use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct SyncPushNowRequest {
    #[serde(default)]
    pub(super) user_gesture: bool,
}

/// `sync_push_now_response`：与 core `SyncNowReport` 同字段的桥投影
/// （核心类型未实现 Serialize，桥侧镜像计数）。
#[derive(Debug, Serialize)]
pub(super) struct SyncPushNowPayload {
    pub(super) pulled: usize,
    pub(super) materialized: usize,
    pub(super) conflicts: usize,
    pub(super) pending_identity: usize,
    pub(super) pushed: usize,
    pub(super) backfilled: u64,
}

/// 立即同步（M5 批3：扩展侧新增/编辑走既有 `save_credential` 落主库，
/// 本 op 把存量+增量推上云）。与桌面 `sync_now` 同一 core 编排
/// （`SyncSession::open` → backfill → run_cycle），差异只在两点：
/// - master 密钥来自桥锁态（`PERSONA_MASTER_PASSWORD` 解锁），锁定即拒；
/// - **不挂捕获缝**——桥一请求一进程，缝随进程消亡没有意义；本请求
///   之外经桥落库的写入由下一轮 `backfill_existing` 幂等补齐。
pub(super) async fn run_sync_push_now(db_path: &Path) -> Result<SyncPushNowPayload> {
    let (session, service) = open_bridge_sync_session(db_path).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;

    let backfilled = session
        .backfill_existing(master)
        .await
        .map_err(|e| anyhow!("sync_cycle_failed: backfill: {e}"))?;
    let report = session
        .run_cycle(master)
        .await
        .map_err(|e| anyhow!("sync_cycle_failed: {e}"))?;

    Ok(SyncPushNowPayload {
        pulled: report.pulled,
        materialized: report.materialized,
        conflicts: report.conflicts,
        pending_identity: report.pending_identity,
        pushed: report.pushed,
        backfilled,
    })
}

pub(super) type BridgeSyncSession =
    persona_core::sync::runtime::SyncSession<persona_core::sync::remote::HttpSyncRemote>;

/// sync_push_now / sync_resolve_conflict 共用的会话装配：配置段错误分类
/// 最先（便宜的错误先报，也不必先解锁）→ keyring 身份/令牌 → 解锁
/// （桥锁态）→ travel 闸采样 → `SyncSession::open`。与桌面
/// `open_sync_session` 同语义；service 随返回值借出（master 从它借）。
pub(super) async fn open_bridge_sync_session(
    db_path: &Path,
) -> Result<(BridgeSyncSession, PersonaService)> {
    let server_url = read_sync_server_url(db_path).await?;
    let db_key = db_path.to_string_lossy().to_string();
    let token = read_keyring_entry(KEYRING_SERVICE_SYNC_TOKEN, &db_key)?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("sync_not_configured: sync server token is not set"))?;
    let identity_raw = read_keyring_entry(KEYRING_SERVICE_DEVICE_IDENTITY, &db_key)?
        .ok_or_else(|| anyhow!("sync_not_joined: this vault has not joined sync"))?;
    let identity = persona_core::sync::device::DeviceIdentity::from_stored_json(&identity_raw)
        .map_err(|e| {
            anyhow!("sync_identity_corrupted: stored device identity is unreadable: {e}")
        })?;

    let (service, _) = open_unlocked_service(db_path).await?;
    let db = open_db(db_path).await?;
    db.migrate().await?;
    // travel 闸在装配前采样一次（与桌面 open_sync_session 同语义）
    let travel_active = service
        .travel_mode_active()
        .await
        .map_err(|e| anyhow!("sync_session_failed: travel mode check failed: {e}"))?;
    let session = persona_core::sync::runtime::SyncSession::open(
        &db,
        &identity,
        &server_url,
        &token,
        Box::new(move || travel_active),
    )
    .await
    .map_err(|e| anyhow!("sync_session_failed: {e}"))?;
    Ok((session, service))
}

#[derive(Debug, Deserialize)]
pub(super) struct SyncResolveConflictRequest {
    pub(super) item_id: String,
    pub(super) adopt_op_id: String,
    #[serde(default)]
    pub(super) user_gesture: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct SyncResolveConflictPayload {
    pub(super) resolved: bool,
}

/// 冲突裁决（对齐桌面 SyncConflictsModal 的「采纳某版本」语义）：
/// `adopt_op_id` 是并发副本（同 lamport、异 device）的 op id；采纳后
/// 其余版本淘汰出视图（重复裁决/未知 op → NotFound，与 core 同话术）。
pub(super) async fn run_sync_resolve_conflict(
    db_path: &Path,
    item_id: &str,
    adopt_op_id: &str,
) -> Result<SyncResolveConflictPayload> {
    // UUID 解析在会话装配之前（便宜的错误先报，免 keyring 即可锚定）
    let item_uuid = uuid::Uuid::parse_str(item_id)
        .map_err(|_| anyhow!("invalid_payload: item_id is not a UUID"))?;
    let adopt_uuid = uuid::Uuid::parse_str(adopt_op_id)
        .map_err(|_| anyhow!("invalid_payload: adopt_op_id is not a UUID"))?;
    let (session, service) = open_bridge_sync_session(db_path).await?;
    let master = service
        .get_master_encryption_service()
        .map_err(|e| anyhow!("locked: master key unavailable: {e}"))?;
    session
        .resolve_conflict(master, item_uuid, adopt_uuid)
        .await
        .map_err(|e| anyhow!("sync_resolve_failed: {e}"))?;
    Ok(SyncResolveConflictPayload { resolved: true })
}
