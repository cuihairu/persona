use crate::models::{
    AuditAction, AuditLog, Credential, CredentialType, Identity, IdentityType, ResourceType,
    SecurityLevel, Workspace,
};
use crate::storage::Database;
use crate::{PersonaError, Result};
use async_trait::async_trait;
use sqlx::Row;
use std::collections::HashMap;
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
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active FROM identities WHERE identity_type = ?"
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
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active FROM identities WHERE name = ?"
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
                tags, attributes, created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(identity.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Identity>> {
        let row = sqlx::query(
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active FROM identities WHERE id = ?"
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
            "SELECT id, name, identity_type, description, email, phone, ssh_key, gpg_key, tags, attributes, created_at, updated_at, is_active FROM identities ORDER BY created_at DESC"
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
                ssh_key = ?, gpg_key = ?, tags = ?, attributes = ?, updated_at = ?, is_active = ?
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

    /// Search credentials by name
    pub async fn search_by_name(&self, query: &str) -> Result<Vec<Credential>> {
        let search_query = format!("%{}%", query);
        let rows = sqlx::query(
            r#"
            SELECT id, identity_id, name, credential_type, security_level, url, username,
                   encrypted_data, wrapped_item_key, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE name LIKE ? AND is_active = 1 ORDER BY created_at DESC
            "#,
        )
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

    async fn has_workspace_v2(&self) -> Result<bool> {
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

/// 安全敏感的审计动作列表（与 `AuditLogRepository::find_security_sensitive` 保持一致，
/// 供服务层做内存过滤）。
pub const SECURITY_SENSITIVE_AUDIT_ACTIONS: [&str; 9] = [
    "login",
    "login_failed",
    "password_change",
    "credential_decrypted",
    "credential_exported",
    "unauthorized_access",
    "brute_force_detected",
    "suspicious_activity",
    "data_exfiltration",
];

/// Audit log repository for security monitoring
#[derive(Clone)]
pub struct AuditLogRepository {
    db: Database,
}

impl AuditLogRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Detach audit logs from an identity before deleting the identity.
    ///
    /// SQLite enforces the `audit_logs.identity_id -> identities.id` foreign key, and we want to
    /// keep audit records even after an identity is removed.
    pub async fn clear_identity_reference(&self, identity_id: &Uuid) -> Result<u64> {
        let res = sqlx::query("UPDATE audit_logs SET identity_id = NULL WHERE identity_id = ?")
            .bind(identity_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }

    /// Detach audit logs from a credential before deleting the credential.
    pub async fn clear_credential_reference(&self, credential_id: &Uuid) -> Result<u64> {
        let res = sqlx::query("UPDATE audit_logs SET credential_id = NULL WHERE credential_id = ?")
            .bind(credential_id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }

    /// Find audit logs by user ID
    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find audit logs by identity ID
    pub async fn find_by_identity(&self, identity_id: &Uuid) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE identity_id = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(identity_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find audit logs by action type
    pub async fn find_by_action(&self, action: &AuditAction) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE action = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(action.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find failed operations
    pub async fn find_failures(&self) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE success = 0 ORDER BY timestamp DESC
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find security-sensitive operations
    pub async fn find_security_sensitive(&self) -> Result<Vec<AuditLog>> {
        let security_actions = SECURITY_SENSITIVE_AUDIT_ACTIONS;

        let placeholders = security_actions
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE action IN ({}) ORDER BY timestamp DESC
            "#,
            placeholders
        );

        let mut query_builder = sqlx::query(&query);
        for action in &security_actions {
            query_builder = query_builder.bind(action);
        }

        let rows = query_builder
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Find logs within time range
    pub async fn find_by_time_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC
            "#,
        )
        .bind(start.to_rfc3339())
        .bind(end.to_rfc3339())
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Search logs by IP address
    pub async fn find_by_ip(&self, ip_address: &str) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE ip_address = ? ORDER BY timestamp DESC
            "#,
        )
        .bind(ip_address)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    /// Get log statistics
    pub async fn get_statistics(&self) -> Result<AuditLogStatistics> {
        // Total logs count
        let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Failed operations count
        let failed_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
                .fetch_one(self.db.pool())
                .await
                .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Recent login attempts (last 24 hours)
        let yesterday = chrono::Utc::now() - chrono::Duration::hours(24);
        let recent_logins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action IN ('login', 'login_failed') AND timestamp >= ?"
        )
        .bind(yesterday.to_rfc3339())
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        // Unique users (last 7 days)
        let last_week = chrono::Utc::now() - chrono::Duration::days(7);
        let active_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT user_id) FROM audit_logs WHERE timestamp >= ? AND user_id IS NOT NULL"
        )
        .bind(last_week.to_rfc3339())
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(AuditLogStatistics {
            total_logs: total_count as u64,
            failed_operations: failed_count as u64,
            recent_login_attempts: recent_logins as u64,
            active_users_last_week: active_users as u64,
        })
    }

    /// Clean up old logs (retain logs for specified days)
    pub async fn cleanup_old_logs(&self, retain_days: u32) -> Result<u64> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(retain_days as i64);
        let result = sqlx::query("DELETE FROM audit_logs WHERE timestamp < ?")
            .bind(cutoff_date.to_rfc3339())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Convert database row to AuditLog
    fn row_to_audit_log(&self, row: sqlx::sqlite::SqliteRow) -> Result<AuditLog> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;

        let action_str: String = row.get("action");
        let action = action_str
            .parse::<AuditAction>()
            .map_err(|e| PersonaError::Database(format!("Invalid action: {}", e)))?;

        let resource_type_str: String = row.get("resource_type");
        let resource_type = resource_type_str
            .parse::<ResourceType>()
            .map_err(|e| PersonaError::Database(format!("Invalid resource type: {}", e)))?;

        let metadata_json: String = row.get("metadata");
        let metadata: HashMap<String, String> = serde_json::from_str(&metadata_json)
            .map_err(|e| PersonaError::Database(format!("Invalid metadata JSON: {}", e)))?;

        let timestamp_str: String = row.get("timestamp");
        let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map_err(|e| PersonaError::Database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&chrono::Utc);

        // Handle optional fields
        let user_id: Option<String> = row.get("user_id");

        let identity_id: Option<Uuid> = row
            .get::<Option<String>, _>("identity_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid identity UUID: {}", e)))?;

        let credential_id: Option<Uuid> = row
            .get::<Option<String>, _>("credential_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid credential UUID: {}", e)))?;

        Ok(AuditLog {
            id,
            user_id,
            identity_id,
            credential_id,
            session_id: row.get("session_id"),
            action,
            resource_type,
            resource_id: row.get("resource_id"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            success: row.get("success"),
            error_message: row.get("error_message"),
            metadata,
            timestamp,
        })
    }
}

#[async_trait]
impl Repository<AuditLog> for AuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        let metadata_json = serde_json::to_string(&log.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, user_id, identity_id, credential_id, session_id, action,
                resource_type, resource_id, ip_address, user_agent, success,
                error_message, metadata, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(log.id.to_string())
        .bind(&log.user_id)
        .bind(log.identity_id.map(|id| id.to_string()))
        .bind(log.credential_id.map(|id| id.to_string()))
        .bind(&log.session_id)
        .bind(log.action.to_string())
        .bind(log.resource_type.to_string())
        .bind(&log.resource_id)
        .bind(&log.ip_address)
        .bind(&log.user_agent)
        .bind(log.success)
        .bind(&log.error_message)
        .bind(&metadata_json)
        .bind(log.timestamp.to_rfc3339())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(log.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditLog>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(self.row_to_audit_log(row)?)),
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, session_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs ORDER BY timestamp DESC LIMIT 1000
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(self.row_to_audit_log(row)?);
        }
        Ok(logs)
    }

    async fn update(&self, log: &AuditLog) -> Result<AuditLog> {
        // 审计日志通常不允许更新，为了数据完整性
        // 但这里提供实现以满足 Repository trait 要求
        let metadata_json = serde_json::to_string(&log.metadata)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize metadata: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE audit_logs SET
                user_id = ?, identity_id = ?, credential_id = ?, action = ?,
                resource_type = ?, resource_id = ?, ip_address = ?, user_agent = ?,
                success = ?, error_message = ?, metadata = ?, timestamp = ?
            WHERE id = ?
            "#,
        )
        .bind(&log.user_id)
        .bind(log.identity_id.map(|id| id.to_string()))
        .bind(log.credential_id.map(|id| id.to_string()))
        .bind(log.action.to_string())
        .bind(log.resource_type.to_string())
        .bind(&log.resource_id)
        .bind(&log.ip_address)
        .bind(&log.user_agent)
        .bind(log.success)
        .bind(&log.error_message)
        .bind(&metadata_json)
        .bind(log.timestamp.to_rfc3339())
        .bind(log.id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(log.clone())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        // 审计日志通常不允许删除，为了数据完整性
        // 但这里提供实现以满足 Repository trait 要求
        let result = sqlx::query("DELETE FROM audit_logs WHERE id = ?")
            .bind(id.to_string())
            .execute(self.db.pool())
            .await
            .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}

/// Audit log statistics
#[derive(Debug, Clone)]
pub struct AuditLogStatistics {
    pub total_logs: u64,
    pub failed_operations: u64,
    pub recent_login_attempts: u64,
    pub active_users_last_week: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CredentialData, PasswordCredentialData};
    use chrono::Duration;

    async fn test_db() -> Database {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    fn sample_identity(name: &str) -> Identity {
        Identity::new(name.to_string(), IdentityType::Personal)
    }

    fn sample_credential(identity_id: Uuid, name: &str) -> Credential {
        let data = CredentialData::Password(PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        });
        let plaintext = data.to_bytes().unwrap();
        let mut cred = Credential::new(
            identity_id,
            name.to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            plaintext.clone(),
            None,
        );
        cred.encrypted_data = plaintext;
        cred
    }

    fn audit_log(action: AuditAction) -> AuditLog {
        AuditLog::new(action, ResourceType::User, true)
            .with_user_id(Some("tester".to_string()))
            .with_ip_address(Some("127.0.0.1".to_string()))
            .with_user_agent(Some("repo-test".to_string()))
    }

    async fn insert_audit_user(db: &Database) {
        // audit_logs.user_id has an FK to user_auth(user_id); seed a matching row.
        sqlx::query("INSERT INTO user_auth (user_id, failed_attempts, password_change_required, created_at, updated_at) VALUES (?, 0, 0, ?, ?)")
            .bind("tester")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(db.pool())
            .await
            .unwrap();
    }

    // ------------------------------------------------------------------
    // CredentialRepository
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn credential_repository_crud_and_queries() {
        let db = test_db().await;
        // credentials.identity_id has an FK to identities; seed the parent first.
        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("cred owner"))
            .await
            .unwrap();
        let repo = CredentialRepository::new(db);

        let identity_id = identities.find_all().await.unwrap()[0].id;
        let mut cred = sample_credential(identity_id, "Repo credential");
        cred.username = Some("user".to_string());
        cred.url = Some("https://example.com".to_string());
        cred.notes = Some("note".to_string());
        cred.tags = vec!["work".to_string()];
        cred.metadata.insert("env".to_string(), "test".to_string());

        repo.create(&cred).await.unwrap();
        assert!(repo.create(&cred).await.is_err()); // PK conflict

        let fetched = repo.find_by_id(&cred.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "Repo credential");
        assert_eq!(fetched.username.as_deref(), Some("user"));
        assert_eq!(fetched.tags, vec!["work".to_string()]);
        assert_eq!(
            fetched.metadata.get("env").map(String::as_str),
            Some("test")
        );

        // Every enum variant round-trips through the stored string form.
        for (name, variant) in [
            ("BankCard", CredentialType::BankCard),
            ("GameAccount", CredentialType::GameAccount),
            ("ServerConfig", CredentialType::ServerConfig),
            ("Certificate", CredentialType::Certificate),
            ("TwoFactor", CredentialType::TwoFactor),
            ("SecureNote", CredentialType::SecureNote),
            ("Identity", CredentialType::Identity),
            ("SoftwareLicense", CredentialType::SoftwareLicense),
            (
                "SomethingCustom",
                CredentialType::Custom("SomethingCustom".to_string()),
            ),
        ] {
            let mut special = sample_credential(identity_id, &format!("{} cred", name));
            special.credential_type = variant;
            repo.create(&special).await.unwrap();
            let round_trip = repo.find_by_id(&special.id).await.unwrap().unwrap();
            assert_eq!(round_trip.credential_type.to_string(), name);
        }

        // SecurityLevel Medium and Low round-trip through their string form
        // (High is the default used by the sample above).
        for (level_name, level) in [
            ("Medium", SecurityLevel::Medium),
            ("Low", SecurityLevel::Low),
        ] {
            let mut lvl_cred = sample_credential(identity_id, &format!("{} level", level_name));
            lvl_cred.security_level = level;
            repo.create(&lvl_cred).await.unwrap();
            let round_trip = repo.find_by_id(&lvl_cred.id).await.unwrap().unwrap();
            assert_eq!(round_trip.security_level.to_string(), level_name);
        }

        let mut renamed = fetched.clone();
        renamed.name = "Renamed credential".to_string();
        renamed.is_favorite = true;
        repo.update(&renamed).await.unwrap();

        // 8 from the earlier section plus the 2 security-level variants
        // plus the 2 new type variants (Identity / SoftwareLicense).
        assert_eq!(repo.find_all().await.unwrap().len(), 12);
        assert_eq!(repo.find_by_identity(&identity_id).await.unwrap().len(), 12);
        // The security-level variants reuse the Password sample shape, so
        // Password count is 3 (original + Medium + Low).
        assert_eq!(
            repo.find_by_type(&CredentialType::Password)
                .await
                .unwrap()
                .len(),
            3
        );
        assert_eq!(repo.find_favorites().await.unwrap().len(), 1);

        let hits = repo.search_by_name("Renamed").await.unwrap();
        assert_eq!(hits.len(), 1);
        assert!(repo
            .search_by_name("no-match-xyz")
            .await
            .unwrap()
            .is_empty());

        assert!(repo.delete(&renamed.id).await.unwrap());
        assert!(!repo.delete(&renamed.id).await.unwrap());
    }

    // ------------------------------------------------------------------
    // WorkspaceRepository (legacy schema used by the current migrations)
    // ------------------------------------------------------------------

    async fn rebuild_workspaces_table(db: &Database, ddl: &str) {
        sqlx::query("DROP TABLE IF EXISTS workspaces")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query(ddl).execute(db.pool()).await.unwrap();
    }

    #[tokio::test]
    async fn workspace_repository_legacy_schema_round_trip() {
        let db = test_db().await;
        // The shipped migrations ship the v2 layout; rebuild the pre-v2 table
        // (no path/settings columns) to exercise the legacy code paths.
        rebuild_workspaces_table(
            &db,
            r#"
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1
            )
            "#,
        )
        .await;
        let repo = WorkspaceRepository::new(db.clone());

        assert!(!repo.has_workspace_v2().await.unwrap());

        let mut ws = Workspace::new("/tmp/legacy-ws", "legacy".to_string());
        repo.create(&ws).await.unwrap();

        let by_id = repo.find_by_id(&ws.id).await.unwrap().unwrap();
        assert_eq!(by_id.name, "legacy");
        assert_eq!(by_id.path, std::path::PathBuf::from("."));

        let by_path = repo.find_by_path("legacy").await.unwrap().unwrap();
        assert_eq!(by_path.id, ws.id);
        assert!(repo.find_by_path("missing").await.unwrap().is_none());

        ws.name = "legacy renamed".to_string();
        ws.touch();
        repo.update(&ws).await.unwrap();
        assert_eq!(repo.find_all().await.unwrap()[0].name, "legacy renamed");

        assert!(repo.delete(&ws.id).await.unwrap());
        assert!(!repo.delete(&ws.id).await.unwrap());
    }

    #[tokio::test]
    async fn workspace_repository_v2_schema_round_trip() {
        let db = test_db().await;
        // The shipped migrations already carry the v2 layout (path/settings).
        let repo = WorkspaceRepository::new(db);
        assert!(repo.has_workspace_v2().await.unwrap());

        let mut ws = Workspace::new("/tmp/v2-ws", "v2".to_string());
        ws.settings.session_timeout_seconds = 1234;
        repo.create(&ws).await.unwrap();

        let identity_id = Uuid::new_v4();
        ws.active_identity_id = Some(identity_id);
        ws.name = "v2 renamed".to_string();
        ws.touch();
        repo.update(&ws).await.unwrap();

        let by_id = repo.find_by_id(&ws.id).await.unwrap().unwrap();
        assert_eq!(by_id.name, "v2 renamed");
        assert_eq!(by_id.path, std::path::PathBuf::from("/tmp/v2-ws"));
        assert_eq!(by_id.active_identity_id, Some(identity_id));
        assert_eq!(by_id.settings.session_timeout_seconds, 1234);

        let by_path = repo.find_by_path("/tmp/v2-ws").await.unwrap().unwrap();
        assert_eq!(by_path.id, ws.id);
        assert_eq!(repo.find_all().await.unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // AuditLogRepository queries
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn audit_log_repository_crud_and_filters() {
        let db = test_db().await;
        insert_audit_user(&db).await;

        // audit_logs carries FKs to identities/credentials; seed both parents.
        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("audit owner"))
            .await
            .unwrap();
        let identity_id = identities.find_all().await.unwrap()[0].id;
        let credentials = CredentialRepository::new(db.clone());
        credentials
            .create(&sample_credential(identity_id, "audit cred"))
            .await
            .unwrap();
        let credential_id = credentials.find_all().await.unwrap()[0].id;

        let repo = AuditLogRepository::new(db.clone());

        let mut ok_login = audit_log(AuditAction::Login)
            .with_identity_id(Some(identity_id))
            .with_session_id(Some("sess-1".to_string()));
        ok_login.metadata.insert("k".to_string(), "v".to_string());
        repo.create(&ok_login).await.unwrap();

        let mut failed = AuditLog::new(AuditAction::LoginFailed, ResourceType::User, false)
            .with_user_id(Some("tester".to_string()))
            .with_credential_id(Some(credential_id))
            .with_error_message(Some("bad password".to_string()));
        failed.ip_address = Some("10.0.0.7".to_string());
        repo.create(&failed).await.unwrap();

        repo.create(&audit_log(AuditAction::PasswordChange))
            .await
            .unwrap();

        // find_by_id / find_all / update
        let stored = repo.find_by_id(&ok_login.id).await.unwrap().unwrap();
        assert_eq!(stored.session_id.as_deref(), Some("sess-1"));
        assert_eq!(stored.metadata.get("k").map(String::as_str), Some("v"));
        assert_eq!(repo.find_all().await.unwrap().len(), 3);

        let mut edited = stored.clone();
        edited.success = false;
        repo.update(&edited).await.unwrap();
        assert!(
            !repo
                .find_by_id(&ok_login.id)
                .await
                .unwrap()
                .unwrap()
                .success
        );

        // Filters
        assert_eq!(repo.find_by_user("tester").await.unwrap().len(), 3);
        assert_eq!(repo.find_by_identity(&identity_id).await.unwrap().len(), 1);
        assert_eq!(
            repo.find_by_action(&AuditAction::LoginFailed)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(repo.find_failures().await.unwrap().len(), 2);
        let sensitive = repo.find_security_sensitive().await.unwrap();
        assert_eq!(sensitive.len(), 3);
        assert_eq!(repo.find_by_ip("10.0.0.7").await.unwrap().len(), 1);

        let now = chrono::Utc::now();
        assert_eq!(
            repo.find_by_time_range(now - Duration::hours(1), now + Duration::hours(1))
                .await
                .unwrap()
                .len(),
            3
        );
        assert!(repo
            .find_by_time_range(now + Duration::hours(2), now + Duration::hours(3))
            .await
            .unwrap()
            .is_empty());

        // Statistics
        let stats = repo.get_statistics().await.unwrap();
        assert_eq!(stats.total_logs, 3);
        assert_eq!(stats.failed_operations, 2);
        assert_eq!(stats.recent_login_attempts, 2);
        assert_eq!(stats.active_users_last_week, 1);

        // Cleanup only removes rows older than the cutoff.
        assert_eq!(repo.cleanup_old_logs(7).await.unwrap(), 0);
        assert_eq!(repo.cleanup_old_logs(0).await.unwrap(), 3);
        assert_eq!(repo.find_all().await.unwrap().len(), 0);

        // Delete trait method.
        let keep = audit_log(AuditAction::Logout);
        repo.create(&keep).await.unwrap();
        assert!(repo.delete(&keep.id).await.unwrap());
        assert!(!repo.delete(&keep.id).await.unwrap());
    }

    #[tokio::test]
    async fn audit_log_clear_identity_and_credential_references() {
        let db = test_db().await;
        insert_audit_user(&db).await;

        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("detach owner"))
            .await
            .unwrap();
        let identity_id = identities.find_all().await.unwrap()[0].id;
        let credentials = CredentialRepository::new(db.clone());
        credentials
            .create(&sample_credential(identity_id, "detach cred"))
            .await
            .unwrap();
        let credential_id = credentials.find_all().await.unwrap()[0].id;

        let repo = AuditLogRepository::new(db.clone());
        repo.create(
            &audit_log(AuditAction::Login)
                .with_identity_id(Some(identity_id))
                .with_credential_id(Some(credential_id)),
        )
        .await
        .unwrap();
        repo.create(&audit_log(AuditAction::Logout).with_identity_id(Some(identity_id)))
            .await
            .unwrap();
        // A third log without references must not be counted or touched.
        repo.create(&audit_log(AuditAction::PasswordChange))
            .await
            .unwrap();

        assert_eq!(
            repo.clear_credential_reference(&credential_id)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.clear_identity_reference(&identity_id).await.unwrap(),
            2
        );
        // Clearing again is a no-op with a zero count.
        assert_eq!(
            repo.clear_identity_reference(&identity_id).await.unwrap(),
            0
        );

        // The referenced rows can now be deleted (that is the point of the
        // detaching helpers), while the audit trail survives with NULL refs.
        assert!(credentials.delete(&credential_id).await.unwrap());
        assert!(identities.delete(&identity_id).await.unwrap());

        let survivors = repo.find_all().await.unwrap();
        assert_eq!(survivors.len(), 3);
        assert!(survivors.iter().all(|log| log.identity_id.is_none()));
        assert!(survivors.iter().all(|log| log.credential_id.is_none()));
    }

    // ------------------------------------------------------------------
    // IdentityRepository extras
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn identity_repository_find_by_type_and_name() {
        let db = test_db().await;
        let repo = IdentityRepository::new(db);

        let mut personal = sample_identity("personal one");
        personal.tags = vec!["tag-a".to_string()];
        personal
            .attributes
            .insert("dept".to_string(), "eng".to_string());
        repo.create(&personal).await.unwrap();

        let mut work = Identity::new("work one".to_string(), IdentityType::Work);
        work.email = Some("work@example.com".to_string());
        repo.create(&work).await.unwrap();

        assert_eq!(repo.find_all().await.unwrap().len(), 2);
        assert_eq!(
            repo.find_by_type(&IdentityType::Work).await.unwrap().len(),
            1
        );
        let by_name = repo.find_by_name("personal one").await.unwrap().unwrap();
        assert_eq!(by_name.tags, vec!["tag-a".to_string()]);
        assert_eq!(
            by_name.attributes.get("dept").map(String::as_str),
            Some("eng")
        );
        assert!(repo.find_by_name("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn row_to_credential_falls_back_to_medium_for_unknown_level() {
        let db = test_db().await;
        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("weird level"))
            .await
            .unwrap();
        let identity_id = identities.find_all().await.unwrap()[0].id;

        // The schema does not constrain security_level, so a legacy or corrupt
        // row can carry an unrecognized value; it must map back to Medium.
        let cred_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO credentials (id, identity_id, name, credential_type, security_level,
               encrypted_data, tags, metadata, created_at, updated_at, is_active, is_favorite)
               VALUES (?, ?, 'corrupt', 'Password', 'ULTRA-SECRET', x'00', '[]', '{}', ?, ?, 1, 0)"#,
        )
        .bind(cred_id.to_string())
        .bind(identity_id.to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(db.pool())
        .await
        .unwrap();

        let repo = CredentialRepository::new(db);
        let fetched = repo.find_by_id(&cred_id).await.unwrap().unwrap();
        assert_eq!(fetched.security_level, SecurityLevel::Medium);
    }

    #[tokio::test]
    async fn credential_create_persists_last_accessed() {
        let db = test_db().await;
        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("accessed"))
            .await
            .unwrap();
        let identity_id = identities.find_all().await.unwrap()[0].id;
        let repo = CredentialRepository::new(db);

        let mut cred = sample_credential(identity_id, "accessed once");
        cred.last_accessed = Some(chrono::Utc::now());
        repo.create(&cred).await.unwrap();

        let fetched = repo.find_by_id(&cred.id).await.unwrap().unwrap();
        assert!(fetched.last_accessed.is_some());
    }

    #[tokio::test]
    async fn workspace_create_persists_active_identity() {
        let db = test_db().await;
        let repo = WorkspaceRepository::new(db);

        let mut ws = Workspace::new("/tmp/v2-active", "active".to_string());
        ws.active_identity_id = Some(Uuid::new_v4());
        repo.create(&ws).await.unwrap();

        let fetched = repo.find_by_id(&ws.id).await.unwrap().unwrap();
        assert_eq!(fetched.active_identity_id, ws.active_identity_id);
    }

    #[tokio::test]
    async fn audit_log_update_persists_credential_reference() {
        let db = test_db().await;
        insert_audit_user(&db).await;

        // audit_logs carries FKs to identities/credentials; seed both parents.
        let identities = IdentityRepository::new(db.clone());
        identities
            .create(&sample_identity("audit updater"))
            .await
            .unwrap();
        let identity_id = identities.find_all().await.unwrap()[0].id;
        let credentials = CredentialRepository::new(db.clone());
        credentials
            .create(&sample_credential(identity_id, "updated cred"))
            .await
            .unwrap();
        let credential_id = credentials.find_all().await.unwrap()[0].id;

        let repo = AuditLogRepository::new(db);
        let log = audit_log(AuditAction::Login).with_credential_id(Some(credential_id));
        repo.create(&log).await.unwrap();

        // The update path serializes the credential reference as well.
        let updated = log.clone().with_identity_id(Some(identity_id));
        repo.update(&updated).await.unwrap();

        let fetched = repo.find_by_id(&log.id).await.unwrap().unwrap();
        assert_eq!(fetched.credential_id, Some(credential_id));
        assert_eq!(fetched.identity_id, Some(identity_id));
    }
}
