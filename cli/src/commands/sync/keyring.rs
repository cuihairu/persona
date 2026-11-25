//! Keyring access for the sync environment (**single source**: shared by CLI `persona sync`
//! and the browser-extension bridge; `bridge/sync_connect` merely forwards to this module).
//!
//! The keyring entry key = the vault db_path (same key as the desktop `token_store` — one
//! vault, one set of entries); the service name is a **protocol-level constant** shared by
//! desktop ↔ CLI ↔ extension; renaming it breaks the chain (all paired devices fail), so
//! entries may only be added, never re-valued.

use std::path::Path;

use anyhow::{anyhow, Result};
use persona_core::storage::WorkspaceRepository;
use persona_core::sync::device::DeviceIdentity;
use persona_core::sync::remote::SyncGroupKeyEntry;
use persona_core::Database;

/// The sync server reporting token (displayed as such in seahorse/Keychain)
pub const KEYRING_SERVICE_SYNC_TOKEN: &str = "persona-sync";

/// The E2EE sync device identity (value = `DeviceIdentity::to_stored_json`)
pub const KEYRING_SERVICE_DEVICE_IDENTITY: &str = "persona-device";

/// The sync group key (zero-account pairing enrollment; value = hex of the 32-byte group key)
pub const KEYRING_SERVICE_SYNC_GROUP: &str = "persona-sync-group";

/// Read a keyring entry. A missing entry → `None`; the secret service being unavailable →
/// error, **not** "unconfigured" — fail-closed: misreporting a broken keyring as "not
/// joined to sync" would steer debugging in the wrong direction.
pub fn read_entry(service: &str, account: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("sync_keyring_unavailable: {e}")),
    }
}

/// Write a keyring entry (fail-closed: an unavailable keyring errors out, **never**
/// falling back to plaintext storage).
pub fn write_entry(service: &str, account: &str, value: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    entry
        .set_password(value)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))
}

/// Delete a keyring entry (idempotent: an entry that already does not exist = the target state).
pub fn delete_entry(service: &str, account: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| anyhow!("sync_keyring_unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow!("sync_keyring_unavailable: {e}")),
    }
}

/// Unwrap this machine's group key from its envelope entry (pure assembly). A missing
/// local envelope (awaiting authorization) → `sync_not_authorized`; an envelope that
/// cannot be unwrapped (not addressed to this private key / tampered with) → fail-closed error.
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

/// The vault's `settings.sync.server_url` (**unlock-free** read: settings is low-sensitivity
/// configuration with no credential material — the same read terms as the desktop
/// `read_sync_config`).
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

/// Group-key hex encoding (32 bytes ↔ 64 chars; the keyring value format).
pub fn group_key_to_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Group-key hex decoding (a short length or non-hex always yields `None` — no guessing).
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
