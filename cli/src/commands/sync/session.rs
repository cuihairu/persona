//! Session assembly + unlock (the hosting orchestration of CLI `persona sync`).
//!
//! The assembly order mirrors desktop `open_sync_session` (`desktop/src-tauri/src/commands/
//! sync.rs:705`) plus the CLI unlock convention (`connect.rs::open_unlocked`): config section
//! errors first (cheap errors first, and unlocking is not even needed yet) → keyring identity
//! /token → unlock → travel-gate sampling → `SyncSession::open`. **No capture seam is hung** —
//! the CLI is one process per command, so a seam dying with the process is meaningless (same
//! reason as the bridge/sync.rs comment); writes made outside this command through the CLI are
//! reconciled idempotently by the next round of `backfill_existing`.

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

/// The CLI session (HTTP transport).
pub(crate) type CliSyncSession = SyncSession<HttpSyncRemote>;

/// Assemble the sync session: server_url → token → identity (keyring, no unlock needed)
/// → unlock → travel-gate sampling → `SyncSession::open`. The service is lent out with the
/// return value (master is borrowed from it).
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
    // The travel gate is sampled once before assembly (same semantics as the desktop open_sync_session)
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

/// Open the vault + migrate + build the service and unlock (errors out on auth failure / not initialized).
/// Master password resolution follows the service.rs convention (`PERSONA_MASTER_PASSWORD` env takes priority).
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
