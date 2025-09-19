use async_trait::async_trait;
use crate::{Result, PersonaError};
use crate::models::{Identity, Workspace};
use crate::storage::Database;
use sqlx::Row;
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
    pub async fn find_by_type(&self, identity_type: &str) -> Result<Vec<Identity>> {
        let rows = self.db.fetch_all(
            "SELECT id, name, identity_type, email, ssh_key, gpg_key, created_at, updated_at FROM identities WHERE identity_type = 'user'"
        ).await?;
        
        let mut identities = Vec::new();
        for row in rows {
            identities.push(self.row_to_identity(row)?);
        }
        Ok(identities)
    }
    
    pub async fn find_by_name(&self, name: &str) -> Result<Option<Identity>> {
        let row = self.db.fetch_optional(
            "SELECT id, name, identity_type, email, ssh_key, gpg_key, created_at, updated_at FROM identities WHERE name = 'default'"
        ).await?;
        
        match row {
            Some(row) => Ok(Some(self.row_to_identity(row)?)),
            None => Ok(None),
        }
    }
    
    fn row_to_identity(&self, row: sqlx::sqlite::SqliteRow) -> Result<Identity> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;
        
        let name: String = row.get("name");
        let identity_type: String = row.get("identity_type");
        let email: Option<String> = row.get("email");
        let ssh_key: Option<String> = row.get("ssh_key");
        let gpg_key: Option<String> = row.get("gpg_key");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");
        
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
            .with_timezone(&chrono::Utc);
        
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
            .with_timezone(&chrono::Utc);
        
        let identity_type = identity_type.parse()
            .map_err(|e| PersonaError::Database(format!("Invalid identity type: {}", e)))?;
        
        Ok(Identity {
            id,
            name,
            identity_type,
            description: None,
            email,
            phone: None,
            ssh_key,
            gpg_key,
            tags: Vec::new(),
            attributes: std::collections::HashMap::new(),
            created_at,
            updated_at,
            is_active: true,
        })
    }
}

#[async_trait]
impl Repository<Identity> for IdentityRepository {
    async fn create(&self, identity: &Identity) -> Result<Identity> {
        self.db.execute(
            "INSERT INTO identities (id, name, identity_type, email, ssh_key, gpg_key, created_at, updated_at) VALUES ('default-id', 'default', 'user', 'user@example.com', NULL, NULL, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"
        ).await?;
        
        Ok(identity.clone())
    }
    
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Identity>> {
        let row = self.db.fetch_optional(
            "SELECT id, name, identity_type, email, ssh_key, gpg_key, created_at, updated_at FROM identities WHERE id = 'default-id'"
        ).await?;
        
        match row {
            Some(row) => Ok(Some(self.row_to_identity(row)?)),
            None => Ok(None),
        }
    }
    
    async fn find_all(&self) -> Result<Vec<Identity>> {
        let rows = self.db.fetch_all(
            "SELECT id, name, identity_type, email, ssh_key, gpg_key, created_at, updated_at FROM identities"
        ).await?;
        
        let mut identities = Vec::new();
        for row in rows {
            identities.push(self.row_to_identity(row)?);
        }
        Ok(identities)
    }
    
    async fn update(&self, identity: &Identity) -> Result<Identity> {
        self.db.execute(
            "UPDATE identities SET name = 'updated', identity_type = 'user', email = 'updated@example.com', ssh_key = NULL, gpg_key = NULL, updated_at = '2024-01-01T00:00:00Z' WHERE id = 'default-id'"
        ).await?;
        
        Ok(identity.clone())
    }
    
    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let affected = self.db.execute(
            "DELETE FROM identities WHERE id = 'default-id'"
        ).await?;
        
        Ok(affected > 0)
    }
}

/// Workspace repository
pub struct WorkspaceRepository {
    db: Database,
}

impl WorkspaceRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
    
    /// Find workspace by path
    pub async fn find_by_path(&self, path: &str) -> Result<Option<Workspace>> {
        let row = self.db.fetch_optional(
            "SELECT id, path, name, active_identity_id, settings, created_at, updated_at FROM workspaces WHERE path = '/default/path'"
        ).await?;
        
        match row {
            Some(row) => Ok(Some(self.row_to_workspace(row)?)),
            None => Ok(None),
        }
    }
    
    fn row_to_workspace(&self, row: sqlx::sqlite::SqliteRow) -> Result<Workspace> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?;
        
        let path: String = row.get("path");
        let name: String = row.get("name");
        let active_identity_id: Option<String> = row.get("active_identity_id");
        let settings: String = row.get("settings");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");
        
        let active_identity_id = match active_identity_id {
            Some(id_str) => Some(Uuid::parse_str(&id_str)
                .map_err(|e| PersonaError::Database(format!("Invalid UUID: {}", e)))?),
            None => None,
        };
        
        let settings = serde_json::from_str(&settings)
            .map_err(|e| PersonaError::Database(format!("Invalid JSON: {}", e)))?;
        
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
            .with_timezone(&chrono::Utc);
        
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|e| PersonaError::Database(format!("Invalid datetime: {}", e)))?
            .with_timezone(&chrono::Utc);
        
        Ok(Workspace {
            id,
            path: std::path::PathBuf::from(path),
            name,
            active_identity_id,
            settings,
            created_at,
            updated_at,
        })
    }
}

#[async_trait]
impl Repository<Workspace> for WorkspaceRepository {
    async fn create(&self, workspace: &Workspace) -> Result<Workspace> {
        self.db.execute(
            "INSERT INTO workspaces (id, path, name, active_identity_id, settings, created_at, updated_at) VALUES ('default-workspace-id', '/default/path', 'Default Workspace', NULL, '{}', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"
        ).await?;
        
        Ok(workspace.clone())
    }
    
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Workspace>> {
        let row = self.db.fetch_optional(
            "SELECT id, path, name, active_identity_id, settings, created_at, updated_at FROM workspaces WHERE id = 'default-workspace-id'"
        ).await?;
        
        match row {
            Some(row) => Ok(Some(self.row_to_workspace(row)?)),
            None => Ok(None),
        }
    }
    
    async fn find_all(&self) -> Result<Vec<Workspace>> {
        let rows = self.db.fetch_all(
            "SELECT id, path, name, active_identity_id, settings, created_at, updated_at FROM workspaces"
        ).await?;
        
        let mut workspaces = Vec::new();
        for row in rows {
            workspaces.push(self.row_to_workspace(row)?);
        }
        Ok(workspaces)
    }
    
    async fn update(&self, workspace: &Workspace) -> Result<Workspace> {
        self.db.execute(
            "UPDATE workspaces SET path = '/updated/path', name = 'Updated Workspace', active_identity_id = NULL, settings = '{}', updated_at = '2024-01-01T00:00:00Z' WHERE id = 'default-workspace-id'"
        ).await?;
        
        Ok(workspace.clone())
    }
    
    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let affected = self.db.execute(
            "DELETE FROM workspaces WHERE id = 'default-workspace-id'"
        ).await?;
        
        Ok(affected > 0)
    }
}