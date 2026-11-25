use crate::error::map_persona_error;
use crate::types::*;
use persona_core::models::wallet::BlockchainNetwork;
use persona_core::models::wallet::CryptoWallet;
use persona_core::models::CredentialType;
use persona_core::storage::{CryptoWalletRepository, Database, WorkspaceRepository};
use persona_core::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tauri::{command, Emitter, State};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

// Error discipline at the command boundary (same semantics as the earlier
// hand-written match in get_workspace_settings): infrastructure failures never
// escape the #[command] boundary — always `return Ok(ApiResponse::error(..))`
// — since the frontend's `catch(e) => String(e)` should only ever receive the
// ApiResponse error/error_code, never a bare String from the invoke layer.
// The `return` inside the macros returns from the command function in place,
// without crossing the boundary. Internal helpers (e.g.
// ensure_workspace_for_path / wallet_db) legitimately keep a bare
// `Result<T, String>` signature since they never cross the boundary.

/// Missing `state.db_path` -> Ok(ApiResponse::error); otherwise unwrap the String.
macro_rules! db_path_or_return {
    ($state:expr) => {{
        let guard = $state.db_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                return Ok(ApiResponse::error(
                    "Database path unavailable. Initialize the service first.".to_string(),
                ))
            }
        }
    }};
}

/// Open the vault (from_file + migrate); a connection/migration failure ->
/// Ok(ApiResponse::error).
macro_rules! open_db_or_return {
    ($db_path:expr) => {{
        let db = match Database::from_file(&$db_path).await {
            Ok(db) => db,
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Database connection failed: {}",
                    e
                )))
            }
        };
        if let Err(e) = db.migrate().await {
            return Ok(ApiResponse::error(format!(
                "Database migration failed: {}",
                e
            )));
        }
        db
    }};
}

/// An ensure_workspace_for_path failure -> Ok(ApiResponse::error).
macro_rules! workspace_or_return {
    ($db:expr, $workspace_path:expr) => {
        match ensure_workspace_for_path(&$db, &$workspace_path).await {
            Ok(ws) => ws,
            Err(e) => {
                return Ok(ApiResponse::error(format!(
                    "Failed to access workspace metadata: {}",
                    e
                )))
            }
        }
    };
}

/// Result<T, E: Display> -> T; Err -> Ok(ApiResponse::error(e.to_string())).
/// Suited to call sites where the Err is already a String
/// (map_err(|_| "...".to_string()), ok_or_else) or where the semantics are
/// precisely the raw error text.
macro_rules! ok_or_error_response {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    };
}

/// Same as [`ok_or_error_response`], but keeps a semantic prefix via a format
/// string: `ok_or_error_response_ctx!(repo.find().await, "Failed to load X: {}")`.
macro_rules! ok_or_error_response_ctx {
    ($expr:expr, $fmt:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(format!($fmt, e))),
        }
    };
}

/// The command-boundary form of wallet_db: "Service is locked" maps to the
/// SERVICE_LOCKED code (the frontend returns to the unlock screen);
/// "Service not initialized" passes through without a code.
macro_rules! wallet_db_or_return {
    ($state:expr) => {
        match wallet_db(&$state).await {
            Ok(db) => db,
            Err(msg) => {
                let code = if msg == "Service is locked" {
                    Some(crate::error::CODE_SERVICE_LOCKED.to_string())
                } else {
                    None
                };
                return Ok(ApiResponse::error_maybe_coded(code, msg));
            }
        }
    };
}

/// Borrow the master key after the lock check; a failure returns
/// `Ok(ApiResponse::error(...))`.
/// Must be called inside the command body (the borrow is tied to the service
/// guard and cannot cross a function boundary).
macro_rules! sync_master_or_return {
    ($service_guard:expr) => {{
        let service = match $service_guard.as_ref() {
            Some(service) => service,
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        };
        match service.get_master_encryption_service() {
            Ok(master) => master,
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    }};
}

mod account;
mod attachments;
mod audit;
mod autolock;
mod backup;
mod biometric;
mod connect;
mod credentials;
mod health;
mod identity;
mod lifecycle;
mod passkey;
mod quickaccess;
mod reveal;
mod ssh;
mod sync;
mod travel;
mod wallet;

pub use self::account::*;
#[allow(unused_imports)]
pub(crate) use self::account::*;
pub use self::attachments::*;
pub use self::audit::*;
#[allow(unused_imports)]
pub(crate) use self::audit::*;
pub use self::autolock::*;
pub use self::backup::*;
#[allow(unused_imports)]
pub(crate) use self::backup::*;
pub use self::biometric::*;
#[allow(unused_imports)]
pub(crate) use self::biometric::*;
pub use self::connect::*;
#[allow(unused_imports)]
pub(crate) use self::connect::*;
pub use self::credentials::*;
#[allow(unused_imports)]
pub(crate) use self::credentials::*;
pub use self::health::*;
#[allow(unused_imports)]
pub(crate) use self::health::*;
pub use self::identity::*;
pub use self::lifecycle::*;
#[allow(unused_imports)]
pub(crate) use self::lifecycle::*;
pub use self::passkey::*;
#[allow(unused_imports)]
pub(crate) use self::passkey::*;
pub use self::quickaccess::*;
#[allow(unused_imports)]
pub(crate) use self::quickaccess::*;
pub use self::reveal::*;
#[allow(unused_imports)]
pub(crate) use self::reveal::*;
pub use self::ssh::*;
#[allow(unused_imports)]
pub(crate) use self::ssh::*;
pub use self::sync::*;
#[allow(unused_imports)]
pub(crate) use self::sync::*;
pub use self::travel::*;
pub use self::wallet::*;
#[allow(unused_imports)]
pub(crate) use self::wallet::*;

#[cfg(test)]
mod tests;
