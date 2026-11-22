//! 会话装配 + 解锁（CLI `persona sync` 的宿主编排）。
//!
//! 装配序镜像 desktop `open_sync_session`（`desktop/src-tauri/src/commands/
//! sync.rs:705`）+ CLI 解锁惯例（`connect.rs::open_unlocked`）：配置段错误
//! 最先（便宜的错误先报，也不必先解锁）→ keyring 身份/令牌 → 解锁 →
//! travel 闸采样 → `SyncSession::open`。**不挂捕获缝**——CLI 一进程一命令，
//! 缝随进程消亡没有意义（与 bridge/sync.rs 注释同一理由）；本命令之外经
//! CLI 落库的写入由下一轮 `backfill_existing` 幂等补齐。

use anyhow::{anyhow, Result};
use persona_core::storage::Database;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::remote::HttpSyncRemote;
use persona_core::sync::runtime::SyncSession;
use persona_core::PersonaService;

use super::keyring;
use crate::commands::service;
use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

/// CLI 版会话（HTTP 传输）。
pub(crate) type CliSyncSession = SyncSession<HttpSyncRemote>;

/// 装配同步会话：server_url → token → identity（keyring，免解锁）→ 解锁
/// → travel 闸采样 → `SyncSession::open`。service 随返回值借出（master
/// 从它借）。
pub(crate) async fn open_sync_session(
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<(CliSyncSession, PersonaService)> {
    let db_path = config.get_database_path();
    let server_url = keyring::read_sync_server_url(&db_path).await?;
    let db_key = db_path.to_string_lossy().to_string();
    let token = keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_TOKEN, &db_key)?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("sync_not_configured: sync server token is not set"))?;
    let identity_raw = keyring::read_entry(keyring::KEYRING_SERVICE_DEVICE_IDENTITY, &db_key)?
        .ok_or_else(|| anyhow!("sync_not_joined: this vault has not joined sync"))?;
    let identity = DeviceIdentity::from_stored_json(&identity_raw).map_err(|e| {
        anyhow!("sync_identity_corrupted: stored device identity is unreadable: {e}")
    })?;

    let service = open_unlocked(config, ui).await?;
    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| anyhow!("sync_session_failed: database connection failed: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("sync_session_failed: database migration failed: {e}"))?;
    // travel 闸在装配前采样一次（与桌面 open_sync_session 同语义）
    let travel_active = service
        .travel_mode_active()
        .await
        .map_err(|e| anyhow!("sync_session_failed: travel mode check failed: {e}"))?;
    let session = SyncSession::open(
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

/// 打开库 + 迁移 + 构造 service 并解锁（认证失败/未初始化即报错）。
/// 主密码解析走 service.rs 惯例（`PERSONA_MASTER_PASSWORD` env 优先）。
pub(crate) async fn open_unlocked(config: &CliConfig, ui: &dyn PromptUi) -> Result<PersonaService> {
    let db = Database::from_file(config.get_database_path())
        .await
        .map_err(|e| anyhow!("Failed to open database: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("Failed to run database migrations: {e}"))?;
    let mut service = service::new_service(db)
        .await
        .map_err(|e| anyhow!("Failed to create PersonaService: {e}"))?;
    if !service
        .has_users()
        .await
        .map_err(|e| anyhow!("Failed to check users: {e}"))?
    {
        anyhow::bail!("Workspace not initialized. Run `persona init` first");
    }
    let password = service::prompt_master_password(ui)?;
    match service
        .authenticate_user(&password)
        .await
        .map_err(|e| anyhow!("Failed to authenticate user: {e}"))?
    {
        persona_core::auth::authentication::AuthResult::Success => Ok(service),
        other => anyhow::bail!("Authentication failed: {other:?}"),
    }
}
