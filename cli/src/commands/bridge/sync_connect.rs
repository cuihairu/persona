use super::*;

/// Keyring read/write for the sync environment plus the service constants (protocol-level,
/// consistent with desktop/src-tauri/src/token_store.rs — both sides read/write the same
/// entry, and renaming it breaks the chain).
/// Single source: CLI `persona sync` and the extension bridge share `commands::sync::keyring`;
/// this module only forwards, avoiding divergence between the two.
pub(super) use crate::commands::sync::keyring::read_entry as read_keyring_entry;
pub(super) use crate::commands::sync::keyring::{
    open_own_group_key, read_sync_server_url, KEYRING_SERVICE_DEVICE_IDENTITY,
    KEYRING_SERVICE_SYNC_TOKEN,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SyncConnectRequest {
    /// Must come from an explicit user action (a popup click); what is granted is the vault decryption key.
    pub(super) user_gesture: bool,
}

/// The `sync_connect_response` payload. The token and group key are sensitive material:
/// the extension side stores them only in a memory area (chrome.storage.session); see
/// BRIDGE_PROTOCOL.md §17 for the security terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct SyncConnectPayload {
    pub(super) server_url: String,
    pub(super) token: String,
    pub(super) device_id: String,
    pub(super) device_name: String,
    /// The group key as hex (the same encoding as the desktop sync_group_store's group_key_to_hex).
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
