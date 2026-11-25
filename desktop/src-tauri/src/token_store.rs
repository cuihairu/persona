//! Field-level encrypted storage abstraction for the sync token.
//!
//! The reporting token (the real value behind `settings.sync.server_token`)
//! does not go into the vault settings JSON — only an empty-string placeholder
//! is stored there. The production implementation writes to the OS keyring
//! (keyring crate: Linux secret-service / macOS Keychain / Windows Credential
//! Manager), keyed by vault db_path; tests use [`InMemoryTokenStore`] (CI and
//! headless environments have no secret service). When the keyring is
//! unavailable, the caller fails closed: reporting stays disabled and saves are
//! rejected — never falls back to plaintext storage.

use std::collections::HashMap;
use std::sync::Mutex;

/// Keyring service name of the sync token entry (shown under it in
/// seahorse/Keychain)
pub const SYNC_SERVICE: &str = "persona-sync";

/// Keyring service name of the biometric-managed master password entry (a
/// separate service isolated from sync; whether the entry exists = whether
/// biometric unlock is enabled, the single source of truth)
pub const BIOMETRIC_SERVICE: &str = "persona-biometric";

/// Keyring service name of the wrap blob from hardware-bound biometrics (the
/// biometric_wrap module). The blob is ciphertext (the master key is wrapped by
/// a platform hardware key) and is mutually exclusive with the gate-layer
/// password entry — when both entries exist, the wrap entry takes precedence
/// (the unlock chain branches on it).
pub const BIOMETRIC_WRAP_SERVICE: &str = "persona-biometric-wrap";

/// Keyring service name of the E2EE sync device identity entry (per the
/// core/src/sync/mod.rs docs: persisting the device private key is the host's
/// responsibility). Value = `DeviceIdentity::to_stored_json`; the key is the
/// same as token_store = vault db_path (naturally invalid after the vault file
/// is copied to another machine, requiring a re-join).
pub const DEVICE_SERVICE: &str = "persona-device";
/// Keyring service for the account-domain bearer (static server token / SRP
/// short-lived token / account 24h session token — one of the three, chosen by
/// the server's require_account_bearer). Entry key same as token_store =
/// vault db_path. Whether the entry exists = whether the account is logged in
/// on this machine (single source of truth; after the vault is copied, no
/// keyring entry = re-login required).
pub const ACCOUNT_SERVICE: &str = "persona-account";

/// Keyring service of the sync group key (cross-device sync, account-free
/// pairing into the group). Value = hex of the 32-byte group key; the key is
/// the same as token_store = vault db_path. Whether the entry exists = whether
/// this vault has joined a sync group (single source of truth; after the vault
/// is copied, no keyring entry = re-pairing required — the group key is handed
/// over by the host wrapped via PAKE, with no local copy).
/// S1 only stores/reads it; the directive-stream consumption connects to S2.
pub const SYNC_GROUP_SERVICE: &str = "persona-sync-group";

/// Access interface for the sync server reporting token.
///
/// Keyed by vault db_path: one token per vault; once the vault file is copied
/// to another machine there is no matching keyring entry there, so reporting is
/// naturally disabled (it must be re-entered — a safe default).
pub trait TokenStore: Send + Sync + 'static {
    /// Write/overwrite the token. Err = OS keyring unavailable or the operation
    /// failed (fail-closed).
    fn set(&self, db_path: &str, token: &str) -> Result<(), String>;
    /// Read the token; `Ok(None)` = not stored.
    fn get(&self, db_path: &str) -> Result<Option<String>, String>;
    /// Delete the token; a missing entry counts as success (idempotent).
    fn delete(&self, db_path: &str) -> Result<(), String>;
}

/// Production implementation: the OS keyring (through the keyring crate's
/// platform backends).
///
/// The service name is parameterized (one service each for the sync token and
/// the biometric managed password). Construction performs no I/O — real keyring
/// access happens on each method call, and failures are returned as `Result`
/// rather than panicking (safe degradation in headless / no-secret-service
/// environments).
pub struct OsKeyringTokenStore(&'static str);

impl OsKeyringTokenStore {
    /// Storage for a given keyring service (entry key = vault db_path)
    pub fn new(service: &'static str) -> Self {
        Self(service)
    }
}

impl Default for OsKeyringTokenStore {
    fn default() -> Self {
        Self(SYNC_SERVICE)
    }
}

impl TokenStore for OsKeyringTokenStore {
    fn set(&self, db_path: &str, token: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        entry
            .set_password(token)
            .map_err(|e| format!("OS keyring write failed: {}", e))
    }

    fn get(&self, db_path: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("OS keyring read failed: {}", e)),
        }
    }

    fn delete(&self, db_path: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // The entry never existed = already the desired state (idempotent delete)
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("OS keyring delete failed: {}", e)),
        }
    }
}

/// Test implementation: an in-process HashMap (CI/headless has no secret
/// service).
#[derive(Default)]
pub struct InMemoryTokenStore(Mutex<HashMap<String, String>>);

impl TokenStore for InMemoryTokenStore {
    fn set(&self, db_path: &str, token: &str) -> Result<(), String> {
        self.0
            .lock()
            .expect("token store mutex poisoned")
            .insert(db_path.to_string(), token.to_string());
        Ok(())
    }

    fn get(&self, db_path: &str) -> Result<Option<String>, String> {
        Ok(self
            .0
            .lock()
            .expect("token store mutex poisoned")
            .get(db_path)
            .cloned())
    }

    fn delete(&self, db_path: &str) -> Result<(), String> {
        self.0
            .lock()
            .expect("token store mutex poisoned")
            .remove(db_path);
        Ok(())
    }
}
