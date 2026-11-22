//! 同步环境的 keyring 取用（**单源**：CLI `persona sync` 与浏览器扩展桥
//! 共用；`bridge/sync_connect` 只是转发本模块）。
//!
//! keyring 条目键 = vault db_path（与 desktop `token_store` 同键——一个
//! vault 一套条目）；service 名是**协议级常量**，桌面↔CLI↔扩展三方共用，
//! 改名即断链（已配对设备全部失效），只可新增不可改值。

use std::path::Path;

use anyhow::{anyhow, Result};
use persona_core::storage::WorkspaceRepository;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::remote::SyncGroupKeyEntry;
use persona_core::Database;

/// sync 服务器上报令牌（seahorse/Keychain 里按它展示）
pub const KEYRING_SERVICE_SYNC_TOKEN: &str = "persona-sync";

/// E2EE sync 设备身份（值 = `DeviceIdentity::to_stored_json`）
pub const KEYRING_SERVICE_DEVICE_IDENTITY: &str = "persona-device";

/// 同步组组密钥（零账号配对入组；值 = 32 字节组密钥的 hex）
pub const KEYRING_SERVICE_SYNC_GROUP: &str = "persona-sync-group";

/// 读 keyring 条目。条目不存在 → `None`；secret service 不可用 → 报错
/// **而非**当「未配置」——fail-closed：把「keyring 坏了」误报成「没加入
/// 同步」会把排障方向带偏。
pub fn read_entry(service: &str, account: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("sync_keyring_unavailable: {e}")),
    }
}

/// 写 keyring 条目（fail-closed：keyring 不可用即报错，**绝不**退回明文
/// 存储）。
pub fn write_entry(service: &str, account: &str, value: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    entry
        .set_password(value)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))
}

/// 删 keyring 条目（幂等：条目本就不存在 = 已是目标状态）。
pub fn delete_entry(service: &str, account: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow!("sync_keyring_unavailable: {e}")),
    }
}

/// 从信封条目里拆出本机 group key（纯装配）。本机信封缺失（待授权）→
/// `sync_not_authorized`；拆不开（信封不是包给这把私钥的/被篡改）→
/// fail-closed 报错。
pub fn open_own_group_key(
    entries: &[SyncGroupKeyEntry],
    identity: &DeviceIdentity,
) -> Result<[u8; 32]> {
    let own = entries
        .iter()
        .find(|k| k.device_id == identity.device_id)
        .ok_or_else(|| {
            anyhow!(
                "sync_not_authorized: this device has no group key envelope yet (pending authorization)"
            )
        })?;
    persona_core::sync::envelope::open_group_key(&own.envelope, identity.key_pair.secret_bytes())
        .map_err(|e| anyhow!("sync_group_key_failed: failed to open own group key envelope: {e}"))
}

/// vault `settings.sync.server_url`（**免解锁**读取：settings 是低敏配置，
/// 不含凭据材料——与桌面 `read_sync_config` 的读取口径一致）。
pub async fn read_sync_server_url(db_path: &Path) -> Result<String> {
    let db = Database::from_file(db_path)
        .await
        .map_err(|e| anyhow!("sync_session_failed: failed to open vault database: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| anyhow!("sync_session_failed: failed to migrate vault database: {e}"))?;
    let workspace_path = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_string_lossy()
        .to_string();
    let repo = WorkspaceRepository::new(db);
    let ws = repo
        .find_by_path(&workspace_path)
        .await
        .map_err(|e| anyhow!("sync_session_failed: {e}"))?
        .ok_or_else(|| anyhow!("sync_not_configured: no workspace found for this vault"))?;
    let server_url = ws
        .settings
        .sync
        .map(|s| s.server_url.trim().to_string())
        .unwrap_or_default();
    if server_url.is_empty() {
        return Err(anyhow!("sync_not_configured: sync server URL is not set"));
    }
    Ok(server_url)
}

/// 组密钥 hex 编码（32 字节 ↔ 64 字符；keyring 值格式）。
pub fn group_key_to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// 组密钥 hex 解码（长度不足或非 hex 一律 `None`——不猜）。
pub fn group_key_from_hex(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}
