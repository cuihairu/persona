//! Repository module (LAY-017 split): the identity/credential/workspace/audit repositories each
//! become their own submodule, while the generic `Repository<T>` trait and the re-exports stay in the hub.
//!
//! External paths are unchanged: `storage::repository::{IdentityRepository, CredentialRepository,
//! WorkspaceRepository, AuditLogRepository, AuditLogStatistics,
//! SECURITY_SENSITIVE_AUDIT_ACTIONS, Repository}` all keep their original paths via `pub use`,
//! and `storage::*` (storage/mod.rs's `pub use repository::*`) is unaffected as well.

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
