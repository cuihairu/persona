//! Workspace 仓储：`WorkspaceRepository` 与 `Repository<Workspace>` 实现。
//! 原 repository.rs 拆分（LAY-017）：workspace 段原样迁出。

use super::Repository;
use crate::models::Workspace;
use crate::storage::Database;
use crate::{PersonaError, Result};
use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

/// Workspace repository (aligns with initial schema for MVP; supports v2 if available)
pub struct WorkspaceRepository {
    db: Database,
}

impl WorkspaceRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find workspace by name (no path in initial schema)
    pub async fn find_by_path(&self, path: &str) -> Result<Option<Workspace>> {
        if self.has_workspace_v2().await.unwrap_or(false) {
            // v2 schema stores real path and settings
            let row = sqlx::query(
                "SELECT id, name, path, active_identity_id, settings, created_at, updated_at FROM workspaces WHERE path = ?"
            )
            .bind(path)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            Ok(row.map(|r| self.row_to_workspace_v2(r)).transpose()?)
        } else {
            // Legacy: map path to name field
            let row = sqlx::query(
                "SELECT id, name, description, created_at, updated_at, is_active FROM workspaces WHERE name = ?"
            )
            .bind(path)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            match row {
                Some(row) => Ok(Some(self.row_to_workspace_legacy(row)?)),
                None => Ok(None),
            }
        }
    }

    // For current schema in 001_initial.sql (no path/settings fields)
    fn row_to_workspace_legacy(&self, row: sqlx::sqlite::SqliteRow) -> Result<Workspace> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let name: String = row.get("name");
        let _description: Option<String> = row.get("description");
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc);
        let updated_at = chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        Ok(Workspace {
            id,
            // Legacy schema doesn't have path/active_identity_id/settings; use defaults
            path: std::path::PathBuf::from("."),
            name,
            active_identity_id: None,
            settings: crate::models::WorkspaceSettings::default(),
            created_at,
            updated_at,
        })
    }

    // For v2 schema with path/active_identity_id/settings
    fn row_to_workspace_v2(&self, row: sqlx::sqlite::SqliteRow) -> Result<Workspace> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;
        let name: String = row.get("name");
        let path_str: String = row.get("path");
        let settings_json: String = row.get("settings");
        let settings: crate::models::WorkspaceSettings = serde_json::from_str(&settings_json)
            .unwrap_or_else(|_| crate::models::WorkspaceSettings::default());
        let active_identity_id: Option<Uuid> = row
            .get::<Option<String>, _>("active_identity_id")
            .and_then(|s| Uuid::parse_str(&s).ok());
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc);
        let updated_at = chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc);
        Ok(Workspace {
            id,
            path: std::path::PathBuf::from(path_str),
            name,
            active_identity_id,
            settings,
            created_at,
            updated_at,
        })
    }

    pub(crate) async fn has_workspace_v2(&self) -> Result<bool> {
        let rows = sqlx::query("PRAGMA table_info('workspaces')")
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        for row in rows {
            let col: String = row.get("name");
            if col == "path" {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl Repository<Workspace> for WorkspaceRepository {
    async fn create(&self, workspace: &Workspace) -> Result<Workspace> {
        if self.has_workspace_v2().await.unwrap_or(false) {
            let settings_json = serde_json::to_string(&workspace.settings).map_err(|e| {
                PersonaError::Database(format!("Failed to serialize settings: {}", e))
            })?;
            sqlx::query(
                r#"
                INSERT INTO workspaces (id, name, path, active_identity_id, settings, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(workspace.id.to_string())
            .bind(&workspace.name)
            .bind(workspace.path.to_string_lossy().to_string())
            .bind(workspace.active_identity_id.map(|id| id.to_string()))
            .bind(settings_json)
            .bind(workspace.created_at.to_rfc3339())
            .bind(workspace.updated_at.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        } else {
            sqlx::query(
                r#"
                INSERT INTO workspaces (id, name, description, created_at, updated_at, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                "#,
            )
            .bind(workspace.id.to_string())
            .bind(&workspace.name)
            .bind::<Option<String>>(None)
            .bind(workspace.created_at.to_rfc3339())
            .bind(workspace.updated_at.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        }

        Ok(workspace.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Workspace>> {
        if self.has_workspace_v2().await.unwrap_or(false) {
            let row = sqlx::query(
                "SELECT id, name, path, active_identity_id, settings, created_at, updated_at FROM workspaces WHERE id = ?"
            )
            .bind(id.to_string())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            Ok(row.map(|r| self.row_to_workspace_v2(r)).transpose()?)
        } else {
            let row = sqlx::query(
                "SELECT id, name, description, created_at, updated_at, is_active FROM workspaces WHERE id = ?"
            )
            .bind(id.to_string())
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            match row {
                Some(row) => Ok(Some(self.row_to_workspace_legacy(row)?)),
                None => Ok(None),
            }
        }
    }

    async fn find_all(&self) -> Result<Vec<Workspace>> {
        if self.has_workspace_v2().await.unwrap_or(false) {
            let rows = sqlx::query(
                "SELECT id, name, path, active_identity_id, settings, created_at, updated_at FROM workspaces"
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            let mut v = Vec::new();
            for row in rows {
                v.push(self.row_to_workspace_v2(row)?);
            }
            Ok(v)
        } else {
            let rows = sqlx::query(
                "SELECT id, name, description, created_at, updated_at, is_active FROM workspaces",
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
            let mut v = Vec::new();
            for row in rows {
                v.push(self.row_to_workspace_legacy(row)?);
            }
            Ok(v)
        }
    }

    async fn update(&self, workspace: &Workspace) -> Result<Workspace> {
        if self.has_workspace_v2().await.unwrap_or(false) {
            let settings_json = serde_json::to_string(&workspace.settings).map_err(|e| {
                PersonaError::Database(format!("Failed to serialize settings: {}", e))
            })?;
            sqlx::query(
                r#"
                UPDATE workspaces
                SET name = ?, path = ?, active_identity_id = ?, settings = ?, updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&workspace.name)
            .bind(workspace.path.to_string_lossy().to_string())
            .bind(workspace.active_identity_id.map(|id| id.to_string()))
            .bind(settings_json)
            .bind(workspace.updated_at.to_rfc3339())
            .bind(workspace.id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        } else {
            sqlx::query(
                r#"
                UPDATE workspaces SET name = ?, updated_at = ? WHERE id = ?
                "#,
            )
            .bind(&workspace.name)
            .bind(workspace.updated_at.to_rfc3339())
            .bind(workspace.id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        }
        Ok(workspace.clone())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM workspaces WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}
