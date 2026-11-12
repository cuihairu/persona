//! 仓储模块（LAY-017 拆分）：identity/credential/workspace/audit 四个仓储各自
//! 独立成子模块，通用 `Repository<T>` trait 与再导出留在枢纽。
//!
//! 外部路径零改动：`storage::repository::{IdentityRepository, CredentialRepository,
//! WorkspaceRepository, AuditLogRepository, AuditLogStatistics,
//! SECURITY_SENSITIVE_AUDIT_ACTIONS, Repository}` 均经 `pub use` 保持原路径，
//! `storage::*`（storage/mod.rs 的 `pub use repository::*`）亦不变。

use crate::Result;
use async_trait::async_trait;
use uuid::Uuid;

/// Generic repository trait
#[async_trait]
pub trait Repository<T> {
    async fn create(&self, entity: &T) -> Result<T>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<T>>;
    async fn find_all(&self) -> Result<Vec<T>>;
    async fn update(&self, entity: &T) -> Result<T>;
    async fn delete(&self, id: &Uuid) -> Result<bool>;
}

mod audit;
mod credential;
mod identity;
mod workspace;

pub use audit::*;
pub use credential::*;
pub use identity::*;
pub use workspace::*;

#[cfg(test)]
mod tests;
