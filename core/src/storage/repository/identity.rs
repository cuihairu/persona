//! Identity 仓储：`IdentityRepository` 与 `Repository<Identity>` 实现。
//! 原 repository.rs 拆分（LAY-017）：identity 段原样迁出，外部路径经
//! `storage::repository::*` 再导出保持。

use super::Repository;
use crate::models::{Identity, IdentityType};
use crate::storage::Database;
use crate::{PersonaError, Result};
use async_trait::async_trait;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

/// Identity repository
pub struct IdentityRepository {
    db: Database,
}

impl IdentityRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find identities by type
    pub async fn find_by_type(&self, identity_type: &IdentityType) -> Result<Vec<Identity>> {
        let type_str = identity_type.to_string();
        let rows = sqlx::query(
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active, travel_marked FROM identities WHERE identity_type = ?"
        )
        .bind(&type_str)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut identities = Vec::new();
        for row in rows {
            identities.push(self.row_to_identity(row)?);
        }
        Ok(identities)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<Identity>> {
        let row = sqlx::query(
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active, travel_marked FROM identities WHERE name = ?"
        )
        .bind(name)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_identity(row)?)),
            None => Ok(None),
        }
    }

    fn row_to_identity(&self, row: sqlx::sqlite::SqliteRow) -> Result<Identity> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let identity_type_str: String = row.get("identity_type");
        let identity_type = identity_type_str
            .parse::<IdentityType>()
            .map_err(|e| PersonaError::Database(format!("Invalid identity type: {}", e)))?;

        let tags_json: String = row.get("tags");
        let tags: Vec<String> = serde_json::from_str(&tags_json)
            .map_err(|e| PersonaError::Database(format!("Invalid tags JSON: {}", e)))?;

        let attributes_json: String = row.get("attributes");
        let attributes: HashMap<String, String> = serde_json::from_str(&attributes_json)
            .map_err(|e| PersonaError::Database(format!("Invalid attributes JSON: {}", e)))?;

        let created_at_str: String = row.get("created_at");
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        let updated_at_str: String = row.get("updated_at");
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        Ok(Identity {
            id,
            name: row.get("name"),
            identity_type,
            description: row.get("description"),
            email: row.get("email"),
            phone: row.get("phone"),
            ssh_key: row.get("ssh_key"),
            gpg_key: row.get("gpg_key"),
            tags,
            attributes,
            created_at,
            updated_at,
            is_active: row.get("is_active"),
            travel_marked: row.get("travel_marked"),
        })
    }
}

#[async_trait]
impl Repository<Identity> for IdentityRepository {
    async fn create(&self, identity: &Identity) -> Result<Identity> {
        let tags_json = serde_json::to_string(&identity.tags)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize tags: {}", e)))?;

        let attributes_json = serde_json::to_string(&identity.attributes).map_err(|e| {
            PersonaError::Database(format!("Failed to serialize attributes: {}", e))
        })?;

        sqlx::query(
            r#"
            INSERT INTO identities (
                id, name, identity_type, description, email, phone, ssh_key, gpg_key,
                tags, attributes, created_at, updated_at, is_active, travel_marked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(identity.id.to_string())
        .bind(&identity.name)
        .bind(identity.identity_type.to_string())
        .bind(&identity.description)
        .bind(&identity.email)
        .bind(&identity.phone)
        .bind(&identity.ssh_key)
        .bind(&identity.gpg_key)
        .bind(&tags_json)
        .bind(&attributes_json)
        .bind(identity.created_at.to_rfc3339())
        .bind(identity.updated_at.to_rfc3339())
        .bind(identity.is_active)
        .bind(identity.travel_marked)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(identity.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Identity>> {
        let row = sqlx::query(
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active, travel_marked FROM identities WHERE id = ?"
        )
        .bind(id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_identity(row)?)),
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<Identity>> {
        let rows = sqlx::query(
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active, travel_marked FROM identities ORDER BY created_at DESC"
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut identities = Vec::new();
        for row in rows {
            identities.push(self.row_to_identity(row)?);
        }
        Ok(identities)
    }

    async fn update(&self, identity: &Identity) -> Result<Identity> {
        let tags_json = serde_json::to_string(&identity.tags)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize tags: {}", e)))?;

        let attributes_json = serde_json::to_string(&identity.attributes).map_err(|e| {
            PersonaError::Database(format!("Failed to serialize attributes: {}", e))
        })?;

        sqlx::query(
            r#"
            UPDATE identities SET
                name = ?, identity_type = ?, description = ?, email = ?, phone = ?,
                ssh_key = ?, gpg_key = ?, tags = ?, attributes = ?, updated_at = ?, is_active = ?,
                travel_marked = ?
            WHERE id = ?
            "#,
        )
        .bind(&identity.name)
        .bind(identity.identity_type.to_string())
        .bind(&identity.description)
        .bind(&identity.email)
        .bind(&identity.phone)
        .bind(&identity.ssh_key)
        .bind(&identity.gpg_key)
        .bind(&tags_json)
        .bind(&attributes_json)
        .bind(identity.updated_at.to_rfc3339())
        .bind(identity.is_active)
        .bind(identity.travel_marked)
        .bind(identity.id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(identity.clone())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM identities WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}
