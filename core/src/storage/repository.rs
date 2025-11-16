use async_trait::async_trait;
use crate::{Result, PersonaError};
use crate::models::{Identity, Workspace, Credential, AuditLog, CredentialType, IdentityType, SecurityLevel, AuditAction, ResourceType};
use crate::storage::Database;
use sqlx::Row;
use uuid::Uuid;
use std::collections::HashMap;

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
        let identity_type = identity_type_str.parse::<IdentityType>()
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

        let attributes_json = serde_json::to_string(&identity.attributes)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize attributes: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO identities (
                id, name, identity_type, description, email, phone, ssh_key, gpg_key,
                tags, attributes, created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
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

        let attributes_json = serde_json::to_string(&identity.attributes)
            .map_err(|e| PersonaError::Database(format!("Failed to serialize attributes: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE identities SET
                name = ?, identity_type = ?, description = ?, email = ?, phone = ?,
                ssh_key = ?, gpg_key = ?, tags = ?, attributes = ?, updated_at = ?, is_active = ?
            WHERE id = ?
            "#
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE identity_id = ? ORDER BY created_at DESC
            "#
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE credential_type = ? ORDER BY created_at DESC
            "#
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE name LIKE ? AND is_active = 1 ORDER BY created_at DESC
            "#
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE is_favorite = 1 AND is_active = 1 ORDER BY created_at DESC
            "#
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

        Ok(Credential {
            id,
            identity_id,
            name: row.get("name"),
            credential_type,
            security_level,
            url: row.get("url"),
            username: row.get("username"),
            encrypted_data,
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
                encrypted_data, notes, tags, metadata, created_at, updated_at,
                last_accessed, is_active, is_favorite
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(credential.id.to_string())
        .bind(credential.identity_id.to_string())
        .bind(&credential.name)
        .bind(credential.credential_type.to_string())
        .bind(credential.security_level.to_string())
        .bind(&credential.url)
        .bind(&credential.username)
        .bind(&credential.encrypted_data)
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials WHERE id = ?
            "#
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
                   encrypted_data, notes, tags, metadata, created_at, updated_at,
                   last_accessed, is_active, is_favorite
            FROM credentials ORDER BY created_at DESC
            "#
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
                username = ?, encrypted_data = ?, notes = ?, tags = ?, metadata = ?,
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
            let settings_json = serde_json::to_string(&workspace.settings)
                .map_err(|e| PersonaError::Database(format!("Failed to serialize settings: {}", e)))?;
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
                "#
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
                "SELECT id, name, description, created_at, updated_at, is_active FROM workspaces"
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
            let settings_json = serde_json::to_string(&workspace.settings)
                .map_err(|e| PersonaError::Database(format!("Failed to serialize settings: {}", e)))?;
            sqlx::query(
                r#"
                UPDATE workspaces
                SET name = ?, path = ?, active_identity_id = ?, settings = ?, updated_at = ?
                WHERE id = ?
                "#
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
                "#
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

/// Audit log repository for security monitoring
pub struct AuditLogRepository {
    db: Database,
}

impl AuditLogRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find audit logs by user ID
    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC
            "#
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
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE identity_id = ? ORDER BY timestamp DESC
            "#
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
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE action = ? ORDER BY timestamp DESC
            "#
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
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE success = 0 ORDER BY timestamp DESC
            "#
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
        let security_actions = [
            "login", "login_failed", "password_change", "credential_decrypted",
            "credential_exported", "unauthorized_access", "brute_force_detected",
            "suspicious_activity", "data_exfiltration"
        ];

        let placeholders = security_actions.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            r#"
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
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
        end: chrono::DateTime<chrono::Utc>
    ) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC
            "#
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
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE ip_address = ? ORDER BY timestamp DESC
            "#
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
        let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
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
        let action = action_str.parse::<AuditAction>()
            .map_err(|e| PersonaError::Database(format!("Invalid action: {}", e)))?;

        let resource_type_str: String = row.get("resource_type");
        let resource_type = resource_type_str.parse::<ResourceType>()
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

        let identity_id: Option<Uuid> = row.get::<Option<String>, _>("identity_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid identity UUID: {}", e)))?;

        let credential_id: Option<Uuid> = row.get::<Option<String>, _>("credential_id")
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| PersonaError::Database(format!("Invalid credential UUID: {}", e)))?;

        Ok(AuditLog {
            id,
            user_id,
            identity_id,
            credential_id,
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
                id, user_id, identity_id, credential_id, action, resource_type,
                resource_id, ip_address, user_agent, success, error_message,
                metadata, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(log.id.to_string())
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
        .execute(self.db.pool())
        .await
        .map_err(|e| PersonaError::Database(e.to_string()))?;

        Ok(log.clone())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditLog>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs WHERE id = ?
            "#
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
            SELECT id, user_id, identity_id, credential_id, action, resource_type,
                   resource_id, ip_address, user_agent, success, error_message,
                   metadata, timestamp
            FROM audit_logs ORDER BY timestamp DESC LIMIT 1000
            "#
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
            "#
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
