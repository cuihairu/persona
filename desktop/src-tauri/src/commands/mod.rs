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

// 命令边界错误纪律（与 get_workspace_settings 早期手写 match 同语义）：
// 基础设施失败不逃出 #[command] 边界，一律 `return Ok(ApiResponse::error(..))`
// ——前端 `catch(e) => String(e)` 只该收到 ApiResponse 的 error/error_code，
// 不该收到 invoke 层的裸 String。宏内 `return` 就地从命令函数返回，不跨边界。
// 内部 helper（如 ensure_workspace_for_path / wallet_db）裸签名
// `Result<T, String>` 不跨边界，合法保留。

/// `state.db_path` 缺失 → Ok(ApiResponse::error)，否则解出 String。
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

/// 打开 vault（from_file + migrate）；连接/迁移失败 → Ok(ApiResponse::error)。
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

/// ensure_workspace_for_path 失败 → Ok(ApiResponse::error)。
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

/// Result<T, E: Display> → T；Err → Ok(ApiResponse::error(e.to_string()))。
/// 适合 Err 已是 String（map_err(|_| "...".to_string())、ok_or_else）或
/// 语义就是原始错误文本的调用点。
macro_rules! ok_or_error_response {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(e.to_string())),
        }
    };
}

/// 同 [`ok_or_error_response`]，但用格式串保留语义前缀：
/// `ok_or_error_response_ctx!(repo.find().await, "Failed to load X: {}")`。
macro_rules! ok_or_error_response_ctx {
    ($expr:expr, $fmt:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(ApiResponse::error(format!($fmt, e))),
        }
    };
}

/// wallet_db 的命令边界形态："Service is locked" 映射 SERVICE_LOCKED
/// 码（前端回解锁屏），"Service not initialized" 无码透传。
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

/// 锁定检查后借出 master 密钥；失败转 `Ok(ApiResponse::error(...))` 返回。
/// 须在命令体内调用（借用挂 service guard，不跨函数边界）。
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
