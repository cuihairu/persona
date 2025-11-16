use crate::{
    Result, PersonaError,
    models::{Identity, Credential, CredentialType, SecurityLevel, CredentialData, IdentityType, AuditLog, AuditAction, ResourceType},
    storage::{Database, Repository, IdentityRepository, CredentialRepository, UserAuthRepository, AuditLogRepository},
    auth::{AuthService, AuthResult, UserAuth, MasterKeyService},
    crypto::{EncryptionService, Sha256Hasher},
};
use uuid::Uuid;
use std::collections::HashMap;

/// High-level service for managing digital identities and credentials
pub struct PersonaService {
    auth_service: AuthService,
    master_key_service: MasterKeyService,
    identity_repo: IdentityRepository,
    credential_repo: CredentialRepository,
    user_auth_repo: UserAuthRepository,
    audit_repo: AuditLogRepository,
    encryption_service: Option<EncryptionService>,
    current_user: Option<Uuid>,
}

impl PersonaService {
    /// Create a new Persona service instance
    pub async fn new(db: Database) -> Result<Self> {
        Ok(Self {
            auth_service: AuthService::new(),
            master_key_service: MasterKeyService::new(),
            identity_repo: IdentityRepository::new(db.clone()),
            credential_repo: CredentialRepository::new(db.clone()),
            user_auth_repo: UserAuthRepository::new(db.clone()),
            audit_repo: AuditLogRepository::new(db),
            encryption_service: None,
            current_user: None,
        })
    }

    /// Initialize the service with a master password
    pub fn unlock(&mut self, master_password: &str, salt: &[u8]) -> Result<()> {
        let encryption_service = self.master_key_service.create_encryption_service(master_password, salt);
        self.encryption_service = Some(encryption_service);
        Ok(())
    }

    /// Lock the service and clear encryption keys
    pub fn lock(&mut self) {
        self.encryption_service = None;
        self.current_user = None;
    }

    /// Check if the service is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.encryption_service.is_some()
    }

    /// Authenticate user and unlock service
    pub async fn authenticate(&mut self, user_id: Uuid, password: &str, salt: &[u8]) -> Result<AuthResult> {
        // For now, simplified authentication - in a real implementation,
        // you would load UserAuth from database
        let mut user_auth = UserAuth::new(user_id);
        let auth_result = self.auth_service.authenticate_password(&mut user_auth, password)?;

        if auth_result == AuthResult::Success {
            self.unlock(password, salt)?;
            self.current_user = Some(user_id);
        }

        Ok(auth_result)
    }

    /// Create a new identity
    pub async fn create_identity(&self, name: String, identity_type: IdentityType) -> Result<Identity> {
        self.ensure_unlocked()?;

        let identity = Identity::new(name, identity_type);
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        ).await;
        Ok(created)
    }

    /// Create a new identity with all fields pre-populated.
    /// Use this when the caller already collected metadata such as email/phone/tags.
    pub async fn create_identity_full(&self, mut identity: Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        // Ensure timestamps are reasonable and updated on create
        identity.touch();
        let created = self.identity_repo.create(&identity).await?;
        self.log_audit(
            AuditAction::IdentityCreated,
            ResourceType::Identity,
            true,
            Some(created.id),
            None,
            None,
        ).await;
        Ok(created)
    }

    /// Get all identities
    pub async fn get_identities(&self) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.identity_repo.find_all().await
    }

    /// Get identity by name
    pub async fn get_identity_by_name(&self, name: &str) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        let res = self.identity_repo.find_by_name(name).await?;
        if let Some(ref ident) = res {
            self.log_audit(AuditAction::IdentityViewed, ResourceType::Identity, true, Some(ident.id), None, None).await;
        }
        Ok(res)
    }

    /// Get identity by ID
    pub async fn get_identity(&self, id: &Uuid) -> Result<Option<Identity>> {
        self.ensure_unlocked()?;
        let res = self.identity_repo.find_by_id(id).await?;
        if let Some(ref ident) = res {
            self.log_audit(AuditAction::IdentityViewed, ResourceType::Identity, true, Some(ident.id), None, None).await;
        }
        Ok(res)
    }

    /// Update an identity
    pub async fn update_identity(&self, identity: &Identity) -> Result<Identity> {
        self.ensure_unlocked()?;
        let updated = self.identity_repo.update(identity).await?;
        self.log_audit(AuditAction::IdentityUpdated, ResourceType::Identity, true, Some(updated.id), None, None).await;
        Ok(updated)
    }

    /// Delete an identity
    pub async fn delete_identity(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        let ok = self.identity_repo.delete(id).await?;
        self.log_audit(AuditAction::IdentityDeleted, ResourceType::Identity, ok, Some(*id), None, None).await;
        Ok(ok)
    }

    /// Create a new credential
    pub async fn create_credential(
        &self,
        identity_id: Uuid,
        name: String,
        credential_type: CredentialType,
        security_level: SecurityLevel,
        credential_data: &CredentialData,
    ) -> Result<Credential> {
        self.ensure_unlocked()?;
        let encryption_service = self.get_encryption_service()?;

        // Serialize and encrypt the credential data
        let plaintext = credential_data.to_bytes()
            .map_err(|e| PersonaError::CryptographicError(format!("Failed to serialize credential data: {}", e)))?;

        let encrypted_data = encryption_service.encrypt(&plaintext)
            .map_err(|e| PersonaError::CryptographicError(format!("Failed to encrypt credential data: {}", e)))?;

        let credential = Credential::new(
            identity_id,
            name,
            credential_type,
            security_level,
            encrypted_data,
        );

        let created = self.credential_repo.create(&credential).await?;
        self.log_audit(AuditAction::CredentialCreated, ResourceType::Credential, true, Some(created.id), Some(identity_id), None).await;
        Ok(created)
    }

    /// Get credentials for an identity
    pub async fn get_credentials_for_identity(&self, identity_id: &Uuid) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.credential_repo.find_by_identity(identity_id).await
    }

    /// Get a specific credential by ID
    pub async fn get_credential(&self, id: &Uuid) -> Result<Option<Credential>> {
        self.ensure_unlocked()?;
        self.credential_repo.find_by_id(id).await
    }

    /// Decrypt and get credential data
    pub async fn get_credential_data(&self, credential_id: &Uuid) -> Result<Option<CredentialData>> {
        self.ensure_unlocked()?;
        let encryption_service = self.get_encryption_service()?;

        let credential = match self.credential_repo.find_by_id(credential_id).await? {
            Some(cred) => cred,
            None => return Ok(None),
        };

        // Mark as accessed
        let mut credential = credential;
        credential.mark_accessed();
        self.credential_repo.update(&credential).await?;

        // Decrypt the data
        let plaintext = encryption_service.decrypt(&credential.encrypted_data)
            .map_err(|e| PersonaError::CryptographicError(format!("Failed to decrypt credential data: {}", e)))?;

        let credential_data = CredentialData::from_bytes(&plaintext)
            .map_err(|e| PersonaError::CryptographicError(format!("Failed to deserialize credential data: {}", e)))?;
        self.log_audit(AuditAction::CredentialDecrypted, ResourceType::Credential, true, Some(credential.id), Some(credential.identity_id), None).await;

        Ok(Some(credential_data))
    }

    /// Update a credential
    pub async fn update_credential(&self, credential: &Credential) -> Result<Credential> {
        self.ensure_unlocked()?;
        let updated = self.credential_repo.update(credential).await?;
        self.log_audit(AuditAction::CredentialUpdated, ResourceType::Credential, true, Some(updated.id), Some(updated.identity_id), None).await;
        Ok(updated)
    }

    /// Delete a credential
    pub async fn delete_credential(&self, id: &Uuid) -> Result<bool> {
        self.ensure_unlocked()?;
        let ok = self.credential_repo.delete(id).await?;
        self.log_audit(AuditAction::CredentialDeleted, ResourceType::Credential, ok, Some(*id), None, None).await;
        Ok(ok)
    }

    /// Search credentials by name
    pub async fn search_credentials(&self, query: &str) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.credential_repo.search_by_name(query).await
    }

    /// Get favorite credentials
    pub async fn get_favorite_credentials(&self) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.credential_repo.find_favorites().await
    }

    /// Get credentials by type
    pub async fn get_credentials_by_type(&self, credential_type: &CredentialType) -> Result<Vec<Credential>> {
        self.ensure_unlocked()?;
        self.credential_repo.find_by_type(credential_type).await
    }

    /// Get identities by type
    pub async fn get_identities_by_type(&self, identity_type: &IdentityType) -> Result<Vec<Identity>> {
        self.ensure_unlocked()?;
        self.identity_repo.find_by_type(identity_type).await
    }

    /// Generate a strong password
    pub fn generate_password(&self, length: usize, include_symbols: bool) -> String {
        use rand::{Rng, rngs::OsRng};

        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let numbers = "0123456789";
        let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        let mut charset = String::new();
        charset.push_str(lowercase);
        charset.push_str(uppercase);
        charset.push_str(numbers);

        if include_symbols {
            charset.push_str(symbols);
        }

        let charset_bytes = charset.as_bytes();
        let mut password = String::new();

        for _ in 0..length {
            let idx = OsRng.gen_range(0..charset_bytes.len());
            password.push(charset_bytes[idx] as char);
        }

        password
    }

    /// Generate salt for master key derivation
    pub fn generate_salt(&self) -> [u8; 32] {
        self.master_key_service.generate_salt()
    }

    /// Hash data using SHA-256
    pub fn hash_data(&self, data: &[u8]) -> [u8; 32] {
        Sha256Hasher::hash(data)
    }

    /// Export identity data (for backup)
    pub async fn export_identity(&self, identity_id: &Uuid) -> Result<IdentityExport> {
        self.ensure_unlocked()?;

        let identity = self.identity_repo.find_by_id(identity_id).await?
            .ok_or_else(|| PersonaError::IdentityNotFound(identity_id.to_string()))?;

        let credentials = self.credential_repo.find_by_identity(identity_id).await?;

        let export = IdentityExport {
            identity,
            credentials,
        };
        self.log_audit(AuditAction::BackupCreated, ResourceType::Identity, true, Some(*identity_id), None, None).await;
        Ok(export)
    }

    /// Get service statistics
    pub async fn get_statistics(&self) -> Result<PersonaStatistics> {
        self.ensure_unlocked()?;

        let identities = self.identity_repo.find_all().await?;
        let all_credentials = self.credential_repo.find_all().await?;

        let mut credential_types: HashMap<String, u32> = HashMap::new();
        let mut security_levels: HashMap<String, u32> = HashMap::new();

        for cred in &all_credentials {
            *credential_types.entry(cred.credential_type.to_string()).or_insert(0) += 1;
            *security_levels.entry(cred.security_level.to_string()).or_insert(0) += 1;
        }

        Ok(PersonaStatistics {
            total_identities: identities.len(),
            total_credentials: all_credentials.len(),
            active_credentials: all_credentials.iter().filter(|c| c.is_active).count(),
            favorite_credentials: all_credentials.iter().filter(|c| c.is_favorite).count(),
            credential_types,
            security_levels,
        })
    }

    /// Initialize first-time user with master password
    pub async fn initialize_user(&mut self, master_password: &str) -> Result<Uuid> {
        let user_id = Uuid::new_v4();
        let mut user_auth = UserAuth::new(user_id);
        // Set master password (this will generate and store salt inside the struct)
        user_auth.set_master_password(master_password)?;
        // Persist to DB
        self.user_auth_repo.create(&user_auth).await?;
        // Get the salt and unlock
        let salt = user_auth.get_master_key_salt()?;
        self.unlock(master_password, &salt)?;
        self.current_user = Some(user_id);
        self.log_audit(AuditAction::ConfigurationChanged, ResourceType::Configuration, true, None, None, None).await;
        Ok(user_id)
    }

    /// Check if any users exist in the database
    pub async fn has_users(&self) -> Result<bool> {
        self.user_auth_repo.has_any().await
    }

    /// Authenticate existing user
    pub async fn authenticate_user(&mut self, master_password: &str) -> Result<AuthResult> {
        // Load first user (single-user MVP)
        let mut user_auth = match self.user_auth_repo.get_first().await? {
            Some(ua) => ua,
            None => {
                // No user exists yet
                return Ok(AuthResult::InvalidCredentials);
            }
        };

        // Verify password
        let auth_result = self.auth_service.authenticate_password(&mut user_auth, master_password)?;
        // Persist updated auth state (failed attempts/lockout)
        self.user_auth_repo.update(&user_auth).await?;

        if auth_result == AuthResult::Success {
            // Unlock with stored salt
            let salt = user_auth.get_master_key_salt()?;
            self.unlock(master_password, &salt)?;
            self.current_user = Some(user_auth.user_id);
            self.log_audit(AuditAction::Login, ResourceType::User, true, None, None, None).await;
        } else {
            self.log_audit(AuditAction::LoginFailed, ResourceType::User, false, None, None, Some("invalid_credentials".to_string())).await;
        }

        Ok(auth_result)
    }

    // Private helper methods

    fn ensure_unlocked(&self) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PersonaError::AuthenticationFailed("Service is locked".to_string()).into());
        }
        Ok(())
    }

    fn get_encryption_service(&self) -> Result<&EncryptionService> {
        self.encryption_service.as_ref()
            .ok_or_else(|| PersonaError::AuthenticationFailed("Service is locked".to_string()).into())
    }

    async fn log_audit(
        &self,
        action: AuditAction,
        resource_type: ResourceType,
        success: bool,
        identity_or_cred: Option<Uuid>,
        identity_id: Option<Uuid>,
        error: Option<String>,
    ) {
        let mut log = AuditLog::new(action, resource_type, success)
            .with_user_id(self.current_user.map(|u| u.to_string()))
            .with_error_message(error);
        if let Some(id) = identity_or_cred {
            // If identity_id provided, treat id as credential_id; else treat id as identity_id
            if let Some(identity_id_val) = identity_id {
                log = log.with_identity_id(Some(identity_id_val)).with_credential_id(Some(id));
            } else {
                log = log.with_identity_id(Some(id));
            }
        }
        let _ = self.audit_repo.create(&log).await;
    }
}

/// Export data structure for backup
#[derive(Debug)]
pub struct IdentityExport {
    pub identity: Identity,
    pub credentials: Vec<Credential>,
}

/// Service usage statistics
#[derive(Debug)]
pub struct PersonaStatistics {
    pub total_identities: usize,
    pub total_credentials: usize,
    pub active_credentials: usize,
    pub favorite_credentials: usize,
    pub credential_types: HashMap<String, u32>,
    pub security_levels: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use crate::models::{PasswordCredentialData, CredentialData};

    #[tokio::test]
    async fn test_persona_service_basic_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let mut service = PersonaService::new(db).await.unwrap();
        let salt = service.generate_salt();

        // Test unlock/lock
        assert!(!service.is_unlocked());
        service.unlock("test_password", &salt).unwrap();
        assert!(service.is_unlocked());

        // Create identity
        let identity = service.create_identity(
            "Test Identity".to_string(),
            IdentityType::Personal,
        ).await.unwrap();

        // Create credential
        let password_data = CredentialData::Password(PasswordCredentialData {
            password: "secret123".to_string(),
            email: Some("test@example.com".to_string()),
            security_questions: vec![],
        });

        let credential = service.create_credential(
            identity.id,
            "Test Account".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &password_data,
        ).await.unwrap();

        // Retrieve and decrypt credential
        let retrieved_data = service.get_credential_data(&credential.id).await.unwrap();
        assert!(retrieved_data.is_some());

        if let Some(CredentialData::Password(pwd_data)) = retrieved_data {
            assert_eq!(pwd_data.password, "secret123");
            assert_eq!(pwd_data.email, Some("test@example.com".to_string()));
        } else {
            panic!("Expected password credential data");
        }
    }
}
