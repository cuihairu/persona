//! Device-surface orchestration (`persona sync join|leave|devices|authorize|revoke|set-remark`).
//!
//! Mirrors desktop `sync_join`/`sync_leave`/`sync_list_devices`/
//! `sync_authorize`/`sync_revoke`/`sync_set_device_remark` (`desktop/
//! src-tauri/src/commands/sync.rs`) line by line, only swapping `State<AppState>` for
//! `(config, an unlocked service)`: gating is done by the caller (mod.rs) unlocking first,
//! and this file only performs the server-side actions + persists the identity to the keyring.

use anyhow::{anyhow, Result};
use colored::Colorize;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::remote::SyncAdminApi;
use uuid::Uuid;

use super::keyring;
use crate::config::CliConfig;

/// The vault db_path text (the keyring entry key; same key as the desktop token_store).
fn db_key(config: &CliConfig) -> String {
    config.get_database_path().to_string_lossy().to_string()
}

/// The three states of this machine's device identity (no unlock needed): joined / not joined / corrupt record.
enum LocalDevice {
    Joined(DeviceIdentity),
    Corrupted,
    NotJoined,
}

fn local_device(config: &CliConfig) -> LocalDevice {
    match keyring::read_entry(keyring::KEYRING_SERVICE_DEVICE_IDENTITY, &db_key(config)) {
        Ok(Some(raw)) => match DeviceIdentity::from_stored_json(&raw) {
            Ok(identity) => LocalDevice::Joined(identity),
            Err(_) => LocalDevice::Corrupted,
        },
        Ok(None) => LocalDevice::NotJoined,
        // A keyring read failure counts as not joined (join reports the specific error afterwards)
        Err(_) => LocalDevice::NotJoined,
    }
}

/// settings.sync.server_url + the keyring sync token → the management client (sync).
pub(super) async fn admin_api_for(config: &CliConfig) -> Result<SyncAdminApi> {
    let server_url = keyring::read_sync_server_url(&config.get_database_path()).await?;
    let token = keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_TOKEN, &db_key(config))?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("sync_not_configured: sync server token is not set"))?;
    SyncAdminApi::new(&server_url, &token)
}

/// Join E2EE sync: generate this machine's device keypair → register with the server →
/// persist the identity to the keyring. If the keyring write fails, best-effort revoke the
/// just-registered server record (no half states left; fail-closed). The gates (unlocked,
/// device_name 1..=128 bytes, not already joined) are enforced up front by the caller.
pub(crate) async fn join(config: &CliConfig, device_name: &str) -> Result<()> {
    let device_name = device_name.trim().to_string();
    if device_name.is_empty() || device_name.len() > 128 {
        anyhow::bail!("Device name must be 1..=128 bytes");
    }
    match local_device(config) {
        LocalDevice::Joined(_) | LocalDevice::Corrupted => {
            anyhow::bail!("This vault already joined sync; leave first")
        }
        LocalDevice::NotJoined => {}
    }
    let api = admin_api_for(config).await?;
    let identity = DeviceIdentity::generate(&device_name)?;
    let device_id = api
        .register_device(&device_name, identity.key_pair.public_bytes())
        .await
        .map_err(|e| anyhow!("Server rejected device registration: {e}"))?;
    let identity = identity.with_device_id(device_id);
    if let Err(e) = keyring::write_entry(
        keyring::KEYRING_SERVICE_DEVICE_IDENTITY,
        &db_key(config),
        &identity.to_stored_json(),
    ) {
        tracing::warn!(
            %e,
            "keyring write failed after registration; revoking the just-registered device"
        );
        if let Err(revoke_error) = api.delete_device(device_id).await {
            tracing::error!(
                %revoke_error,
                device_id = %device_id,
                "rollback revoke failed; a stray device record remains on the server"
            );
        }
        return Err(anyhow!("Cannot store device identity in OS keyring: {e}"));
    }
    // pending = the group-keys entry has no local envelope yet; a query failure is handled
    // conservatively as "awaiting authorization" (fail-closed: authorization status would
    // rather show unauthorized). In an empty group this machine bootstraps itself.
    let pending = match api
        .bootstrap_group_if_empty(device_id, identity.key_pair.public_bytes())
        .await
    {
        Ok(bootstrapped) => !bootstrapped,
        Err(_) => true,
    };
    println!(
        "{}  {} ({})",
        "✓ Joined sync".green().bold(),
        device_name.cyan(),
        device_id
    );
    if pending {
        println!(
            "{}",
            "  ⏳ Waiting for authorization from an existing device.".bright_black()
        );
    } else {
        println!("  🎉 This device bootstrapped the sync group (authorized).");
    }
    Ok(())
}

/// Leave sync: best-effort revoke of the server-side record (unreachable only warns — local cleanup comes first), then
/// unconditionally clear the keyring identity.
pub(crate) async fn leave(config: &CliConfig) -> Result<()> {
    match local_device(config) {
        LocalDevice::NotJoined => anyhow::bail!("This vault has not joined sync"),
        LocalDevice::Joined(identity) => {
            if let Ok(api) = admin_api_for(config).await {
                if let Err(e) = api.delete_device(identity.device_id).await {
                    tracing::warn!(
                        %e,
                        device_id = %identity.device_id,
                        "server-side device revoke failed during leave; the record may remain"
                    );
                }
            } else {
                tracing::warn!(
                    "sync admin client unavailable during leave; skipping server-side revoke"
                );
            }
        }
        LocalDevice::Corrupted => {
            tracing::warn!(
                "corrupted device record during leave; clearing keyring without server-side revoke"
            );
        }
    }
    keyring::delete_entry(keyring::KEYRING_SERVICE_DEVICE_IDENTITY, &db_key(config))?;
    println!(
        "{}",
        "✓ Left sync (device identity removed from keyring)"
            .green()
            .bold()
    );
    Ok(())
}

/// List all devices in the sync group (including authorization status and the local marker). Requires being joined.
pub(crate) async fn list_devices(config: &CliConfig) -> Result<()> {
    let identity = match local_device(config) {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            anyhow::bail!("This vault has not joined sync")
        }
    };
    let api = admin_api_for(config).await?;
    let devices = api
        .list_devices()
        .await
        .map_err(|e| anyhow!("Failed to list devices: {e}"))?;
    if devices.is_empty() {
        println!("(no devices)");
        return Ok(());
    }
    println!("{}", "🖥 Sync group devices".cyan().bold());
    for device in devices {
        let is_self = device.id == identity.device_id;
        let marker = if is_self { " (this device)" } else { "" };
        let remark = if device.remark.is_empty() {
            String::new()
        } else {
            format!(" — {}", device.remark)
        };
        println!(
            "{}  {} ({}){}{}",
            if is_self { "●" } else { "○" },
            device.device_name,
            device.id,
            marker,
            remark
        );
    }
    Ok(())
}

/// Authorize the target device: unwrap the local envelope to get the group key → seal a new
/// envelope with the target's public key and upload. An unauthorized local machine (envelope
/// cannot be unwrapped) fails closed.
pub(crate) async fn authorize(config: &CliConfig, target: &str) -> Result<()> {
    let identity = match local_device(config) {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            anyhow::bail!("This vault has not joined sync")
        }
    };
    let target_id =
        Uuid::parse_str(target.trim()).map_err(|_| anyhow!("Malformed target device id"))?;
    if target_id == identity.device_id {
        anyhow::bail!("This device is already authorized; use leave to remove it");
    }
    let api = admin_api_for(config).await?;
    let keys = api
        .group_keys()
        .await
        .map_err(|e| anyhow!("Failed to fetch group keys: {e}"))?;
    let group_key_bytes = keyring::open_own_group_key(&keys, &identity)?;
    let target = api
        .list_devices()
        .await
        .map_err(|e| anyhow!("Failed to list devices: {e}"))?
        .into_iter()
        .find(|d| d.id == target_id)
        .ok_or_else(|| anyhow!("Target device not found on the server"))?;
    let envelope =
        persona_core::sync::envelope::seal_group_key(&group_key_bytes, &target.public_key)
            .map_err(|e| anyhow!("Failed to seal group key: {e}"))?;
    api.put_group_key(target_id, &envelope)
        .await
        .map_err(|e| anyhow!("Failed to upload group key: {e}"))?;
    println!(
        "{}  authorized {}",
        "✓ Group key delivered".green().bold(),
        target_id
    );
    Ok(())
}

/// Revoke a device (server-side deletion of the registration + envelope, idempotent). To revoke yourself, use leave.
pub(crate) async fn revoke(config: &CliConfig, target: &str) -> Result<()> {
    let identity = match local_device(config) {
        LocalDevice::Joined(identity) => identity,
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            anyhow::bail!("This vault has not joined sync")
        }
    };
    let target_id =
        Uuid::parse_str(target.trim()).map_err(|_| anyhow!("Malformed target device id"))?;
    if target_id == identity.device_id {
        anyhow::bail!("Use leave to remove this device from sync");
    }
    let api = admin_api_for(config).await?;
    api.delete_device(target_id)
        .await
        .map_err(|e| anyhow!("Failed to revoke device: {e}"))?;
    println!("{}  revoked {}", "✓ Revoked".green().bold(), target_id);
    Ok(())
}

/// Set this device's free-form remark (the server locks it to the token owner; an empty string = clear). Requires being joined.
pub(crate) async fn set_remark(config: &CliConfig, remark: &str) -> Result<()> {
    match local_device(config) {
        LocalDevice::Joined(_) => {}
        LocalDevice::NotJoined | LocalDevice::Corrupted => {
            anyhow::bail!("This vault has not joined sync")
        }
    }
    let api = admin_api_for(config).await?;
    let stored = api
        .set_device_remark(remark)
        .await
        .map_err(|e| anyhow!("Failed to set device remark: {e}"))?;
    if stored.is_empty() {
        println!("{}", "✓ Remark cleared".green().bold());
    } else {
        println!("{}  {}", "✓ Remark set".green().bold(), stored.cyan());
    }
    Ok(())
}
