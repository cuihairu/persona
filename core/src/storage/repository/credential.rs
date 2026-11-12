//! Credential 仓储：`CredentialRepository` 与 `Repository<Credential>` 实现。
//! 原 repository.rs 拆分（LAY-017）：credential 段原样迁出。

use super::Repository;
use crate::models::{Credential, CredentialType, SecurityLevel};
use crate::storage::Database;
use crate::{PersonaError, Result};
use async_trait::async_trait;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

/// Credential repository
pub struct CredentialRepository {
    db: Database,
}

impl CredentialRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find credentials by identity
    pub async fn find_by_identity(&self, identity_id: &Uuid) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE identity_id = ? ORDER BY created_at DESC
            "#,
        )
        .bind(identity_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    /// 全表列举（sync backfill 用：主库存在但 oplog 缺席的凭据灌入 oplog）
    pub async fn list_all(&self) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials ORDER BY created_at DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    /// Find credentials by type
    pub async fn find_by_type(&self, credential_type: &CredentialType) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE credential_type = ? ORDER BY created_at DESC
            "#,
        )
        .bind(credential_type.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    /// Search credentials by name / username / url (substring, case-insensitive
    /// per SQLite LIKE). NULL columns simply never match.
    pub async fn search_by_fields(&self, query: &str) -> Result<Vec<Credential>> {
        let search_query = format!("%{}%", query);
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials
            WHERE (name LIKE ? OR username LIKE ? OR url LIKE ?) AND is_active = 1
            ORDER BY created_at DESC
            "#,
        )
        .bind(&search_query)
        .bind(&search_query)
        .bind(&search_query)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    /// Get favorite credentials
    pub async fn find_favorites(&self) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE is_favorite = 1 AND is_active = 1 ORDER BY created_at DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    fn row_to_credential(&self, row: sqlx::sqlite::SqliteRow) -> Result<Credential> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let identity_id_str: String = row.get("identity_id");
        let identity_id = Uuid::parse_str(&identity_id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid identity UUID: {}", e)))?;

        let credential_type_str: String = row.get("credential_type");
        let credential_type = match credential_type_str.as_str() {
            "Password" => CredentialType::Password,
            "CryptoWallet" => CredentialType::CryptoWallet,
            "SshKey" => CredentialType::SshKey,
            "ApiKey" => CredentialType::ApiKey,
            "BankCard" => CredentialType::BankCard,
            "GameAccount" => CredentialType::GameAccount,
            "ServerConfig" => CredentialType::ServerConfig,
            "Certificate" => CredentialType::Certificate,
            "TwoFactor" => CredentialType::TwoFactor,
            "SecureNote" => CredentialType::SecureNote,
            "Identity" => CredentialType::Identity,
            "SoftwareLicense" => CredentialType::SoftwareLicense,
            custom => CredentialType::Custom(custom.to_string()),
        };

        let security_level_str: String = row.get("security_level");
        let security_level = match security_level_str.as_str() {
            "Critical" => SecurityLevel::Critical,
            "High" => SecurityLevel::High,
            "Medium" => SecurityLevel::Medium,
            "Low" => SecurityLevel::Low,
            _ => SecurityLevel::Medium,
        };

        let tags_json: String = row.get("tags");
        let tags: Vec<String> = serde_json::from_str(&tags_json)
            .map_err(|e| PersonaError::Database(format!("Invalid tags JSON: {}", e)))?;

        let metadata_json: String = row.get("metadata");
        let metadata: HashMap<String, String> = serde_json::from_str(&metadata_json)
            .map_err(|e| PersonaError::Database(format!("Invalid metadata JSON: {}", e)))?;

        let created_at_str: String = row.get("created_at");
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        let updated_at_str: String = row.get("updated_at");
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| PersonaError::Database(format!("Invalid updated_at: {}", e)))?
            .with_timezone(&chrono::Utc);

        let last_accessed: Option<chrono::DateTime<chrono::Utc>> = row
            .get::<Option<String>, _>("last_accessed")
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let encrypted_data: Vec<u8> = row.get("encrypted_data");

        let wrapped_item_key: Option<Vec<u8>> = row.get("wrapped_item_key");

        Ok(Credential {
            id,
            identity_id,
            name: row.get("name"),
            credential_type,
            security_level,
            url: row.get("url"),
            username: row.get("username"),
            encrypted_data,
            wrapped_item_key,
            notes: row.get("notes"),
            tags,
            metadata,
            created_at,
            updated_at,
            last_accessed,
            is_active: row.get("is_active"),
            is_favorite: row.get("is_favorite"),
        })
    }
}

#[async_trait]
impl Repository<Credential> for CredentialRepository {
    async fn create(&self, credential: &Credential) -> Result<Credential> {
        let tags_json = serde_json::to_string(&credential.tags)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize tags: {}", e)))?;

        let metadata_json = serde_json::to_string(&credential.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, identity_id, name, credential_type, security_level, url, username,
                encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                last_accessed, is_active, is_favorite
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(credential.id.to_string())
        .bind(credential.identity_id.to_string())
        .bind(&credential.name)
        .bind(credential.credential_type.to_string())
        .bind(credential.security_level.to_string())
        .bind(&credential.url)
        .bind(&credential.username)
        .bind(&credential.encrypted_data)
        .bind(&credential.wrapped_item_key)
        .bind(&credential.notes)
        .bind(&tags_json)
        .bind(&metadata_json)
        .bind(credential.created_at.to_rfc3339())
        .bind(credential.updated_at.to_rfc3339())
        .bind(credential.last_accessed.map(|dt| dt.to_rfc3339()))
        .bind(credential.is_active)
        .bind(credential.is_favorite)
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(credential.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Credential>> {
        let row = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_credential(row)?)),
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<Credential>> {
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials ORDER BY created_at DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut credentials = Vec::new();
        for row in rows {
            credentials.push(self.row_to_credential(row)?);
        }
        Ok(credentials)
    }

    async fn update(&self, credential: &Credential) -> Result<Credential> {
        let tags_json = serde_json::to_string(&credential.tags)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize tags: {}", e)))?;

        let metadata_json = serde_json::to_string(&credential.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE credentials SET
                identity_id = ?, name = ?, credential_type = ?, security_level = ?, url = ?,
                username = ?, encrypted_data = ?, wrapped_item_key = ?, notes = ?, tags = ?, metadata = ?,
                updated_at = ?, last_accessed = ?, is_active = ?, is_favorite = ?
            WHERE id = ?
            "#
        )
        .bind(credential.identity_id.to_string())
        .bind(&credential.name)
        .bind(credential.credential_type.to_string())
        .bind(credential.security_level.to_string())
        .bind(&credential.url)
        .bind(&credential.username)
        .bind(&credential.encrypted_data)
        .bind(&credential.wrapped_item_key)
        .bind(&credential.notes)
        .bind(&tags_json)
        .bind(&metadata_json)
        .bind(credential.updated_at.to_rfc3339())
        .bind(credential.last_accessed.map(|dt| dt.to_rfc3339()))
        .bind(credential.is_active)
        .bind(credential.is_favorite)
        .bind(credential.id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(credential.clone())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}
