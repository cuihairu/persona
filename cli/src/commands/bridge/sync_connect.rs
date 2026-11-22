use super::*;

/// 同步环境的 keyring 读写与 service 常量（协议级，与 desktop/
/// src-tauri/src/token_store.rs 一致——两边读写同一条目，改名即断链）。
/// 单源：CLI `persona sync` 与扩展桥共用 `commands::sync::keyring`，本模块
/// 只转发，避免两处漂移。
pub(super) use crate::commands::sync::keyring::read_entry as read_keyring_entry;
pub(super) use crate::commands::sync::keyring::{
    open_own_group_key, read_sync_server_url, KEYRING_SERVICE_DEVICE_IDENTITY,
    KEYRING_SERVICE_SYNC_TOKEN,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SyncConnectRequest {
    /// 必须来自显式用户操作（popup 点选）；发放的是保险库解密钥。
    pub(super) user_gesture: bool,
}

/// `sync_connect_response` 负载。token 与 group key 是敏感材料：扩展侧只存
/// 内存区（chrome.storage.session），安全口径见 BRIDGE_PROTOCOL.md §17。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SyncConnectPayload {
    pub(super) server_url: String,
    pub(super) token: String,
    pub(super) device_id: String,
    pub(super) device_name: String,
    /// group key 十六进制（与桌面 sync_group_store 的 group_key_to_hex 同编码）。
    pub(super) group_key_hex: String,
}

pub(super) async fn run_sync_connect(db_path: &Path) -> Result<SyncConnectPayload> {
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

    let admin = persona_core::sync::remote::SyncAdminApi::new(&server_url, &token)
        .map_err(|e| anyhow!("sync_not_configured: invalid sync server configuration: {e}"))?;
    let entries = admin
        .group_keys()
        .await
        .map_err(|e| anyhow!("sync_server_unreachable: {e}"))?;
    let group_key = open_own_group_key(&entries, &identity)?;

    Ok(SyncConnectPayload {
        server_url,
        token,
        device_id: identity.device_id.to_string(),
        device_name: identity.device_name,
        group_key_hex: hex::encode(group_key),
    })
}
