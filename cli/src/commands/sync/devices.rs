//! 设备面编排（`persona sync join|leave|devices|authorize|revoke|set-remark`）。
//!
//! 逐条镜像 desktop `sync_join`/`sync_leave`/`sync_list_devices`/
//! `sync_authorize`/`sync_revoke`/`sync_set_device_remark`（`desktop/
//! src-tauri/src/commands/sync.rs`），仅把 `State<AppState>` 换成
//! `(config, 已解锁的 service)`：门禁由调用方（mod.rs）先解锁，这里只做
//! 服务器侧动作 + keyring 落身份。

use anyhow::{anyhow, Result};
use colored::Colorize;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::remote::SyncAdminApi;
use uuid::Uuid;

use super::keyring;
use crate::config::CliConfig;

/// vault db_path 文本（keyring 条目键；与 desktop token_store 同键）。
fn db_key(config: &CliConfig) -> String {
    config.get_database_path().to_string_lossy().to_string()
}

/// 本机设备身份三态（免解锁）：已加入 / 未加入 / 记录损坏。
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
        // keyring 读失败视同未加入（join 会再报具体错误）
        Err(_) => LocalDevice::NotJoined,
    }
}

/// settings.sync.server_url + keyring sync token → 管理客户端（同步）。
pub(super) async fn admin_api_for(config: &CliConfig) -> Result<SyncAdminApi> {
    let server_url = keyring::read_sync_server_url(&config.get_database_path()).await?;
    let token = keyring::read_entry(keyring::KEYRING_SERVICE_SYNC_TOKEN, &db_key(config))?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("sync_not_configured: sync server token is not set"))?;
    SyncAdminApi::new(&server_url, &token)
}

/// 加入 E2EE 同步：生成本机设备密钥对 → 向服务器登记 → keyring 落身份。
/// keyring 写失败时尽力吊销刚登记的服务器记录（不留半态，fail-closed）。
/// 门禁（已解锁、device_name 1..=128 字节、未加入）由调用方前置。
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
    // pending = group-keys 尚无本机信封；查询失败按「等授权」保守处理
    // （fail-closed：授权状态宁可显示未授权）。空组时本机自举。
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

/// 离开同步：尽力吊销服务器侧记录（不可达仅 warn——本地清理优先），然后
/// 无条件清 keyring 身份。
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

/// 列出同步组全部设备（含授权状态与本机标记）。要求已加入。
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

/// 为目标设备授权：拆本机信封得 group key → 用目标公钥封新信封上传。
/// 本机未授权（信封拆不开）fail-closed。
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

/// 吊销设备（服务器侧删登记+信封，幂等）。吊销自己请走 leave。
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

/// 设置本设备的自由备注（服务器锁到令牌归属；空串 = 清除）。要求已加入。
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
