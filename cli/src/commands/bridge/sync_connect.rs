use super::*;

/// keyring service 名（协议级常量，与 desktop/src-tauri/src/token_store.rs
/// 的 SYNC_SERVICE / DEVICE_SERVICE 一致——两边读写同一条目，改名即断链）。
pub(super) const KEYRING_SERVICE_SYNC_TOKEN: &str = "persona-sync";

pub(super) const KEYRING_SERVICE_DEVICE_IDENTITY: &str = "persona-device";

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

/// 读 keyring 条目（条目键 = vault db 路径，与桌面 token_store 同键）。
/// 无条目 → None；secret service 不可用 → 报错而非当「未配置」——
/// fail-closed：把「keyring 坏了」误报成「没加入同步」会误导排障方向。
pub(super) fn read_keyring_entry(service: &str, account: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("sync_keyring_unavailable: {e}")),
    }
}

/// vault settings.sync.server_url（免解锁读取：settings 是低敏配置，
/// 不含凭据材料——与桌面 read_sync_config 的读取口径一致）。
pub(super) async fn read_sync_server_url(db_path: &Path) -> Result<String> {
    let db = open_db(db_path).await?;
    db.migrate().await?;
    let workspace_path = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_string_lossy()
        .to_string();
    let repo = WorkspaceRepository::new(db);
    let ws = repo
        .find_by_path(&workspace_path)
        .await?
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

/// 从信封条目里拆出本机 group key（纯装配，测试锚点：信封可本地构造，
/// 不需要真服务器）。
pub(super) fn open_own_group_key(
    entries: &[persona_core::sync::remote::SyncGroupKeyEntry],
    identity: &persona_core::sync::device::DeviceIdentity,
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
