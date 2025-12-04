use crate::crypto::{EncryptionService, PasswordHasher};
use crate::{PersonaError, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Authentication factor types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthFactor {
    /// Master password
    MasterPassword,
    /// Biometric authentication (fingerprint, face, etc.)
    Biometric(BiometricType),
    /// Hardware security key
    HardwareKey,
    /// PIN code
    Pin,
    /// Pattern unlock
    Pattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BiometricType {
    Fingerprint,
    FaceId,
    TouchId,
    VoiceId,
    IrisId,
}

/// User authentication information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuth {
    /// User ID
    pub user_id: Uuid,

    /// Master password hash
    pub master_password_hash: Option<String>,

    /// Master key salt for key derivation
    pub master_key_salt: Option<String>,

    /// Enabled authentication factors
    pub enabled_factors: Vec<AuthFactor>,

    /// Failed authentication attempts
    pub failed_attempts: u32,

    /// Account lockout until this time
    pub locked_until: Option<SystemTime>,

    /// Last successful authentication
    pub last_auth: Option<SystemTime>,

    /// Password change required
    pub password_change_required: bool,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Last update timestamp
    pub updated_at: SystemTime,
}

impl UserAuth {
    /// Create new user authentication
    pub fn new(user_id: Uuid) -> Self {
        let now = SystemTime::now();
        Self {
            user_id,
            master_password_hash: None,
            master_key_salt: None,
            enabled_factors: Vec::new(),
            failed_attempts: 0,
            locked_until: None,
            last_auth: None,
            password_change_required: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set master password and generate salt if needed
    pub fn set_master_password(&mut self, password: &str) -> Result<()> {
        let hasher = PasswordHasher::new();
        let hash = hasher.hash_password(password)?;
        self.master_password_hash = Some(hash);

        // Generate salt if not already set
        if self.master_key_salt.is_none() {
            let master_key_service = MasterKeyService::new();
            let salt = master_key_service.generate_salt();
            self.master_key_salt = Some(hex::encode(salt));
        }

        self.enabled_factors.push(AuthFactor::MasterPassword);
        self.password_change_required = false;
        self.updated_at = SystemTime::now();
        Ok(())
    }

    /// Get the master key salt as bytes
    pub fn get_master_key_salt(&self) -> Result<[u8; 32]> {
        match &self.master_key_salt {
            Some(salt_hex) => {
                let salt_bytes = hex::decode(salt_hex).map_err(|e| {
                    PersonaError::CryptographicError(format!("Invalid salt format: {}", e))
                })?;
                if salt_bytes.len() != 32 {
                    return Err(PersonaError::CryptographicError(
                        "Invalid salt length".to_string(),
                    )
                    .into());
                }
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&salt_bytes);
                Ok(salt)
            }
            None => Err(PersonaError::AuthenticationFailed("No salt available".to_string()).into()),
        }
    }

    /// Verify master password
    pub fn verify_master_password(&self, password: &str) -> Result<bool> {
        match &self.master_password_hash {
            Some(hash) => {
                let hasher = PasswordHasher::new();
                hasher.verify_password(password, hash).map_err(Into::into)
            }
            None => Ok(false),
        }
    }

    /// Check if account is locked
    pub fn is_locked(&self) -> bool {
        match self.locked_until {
            Some(locked_until) => SystemTime::now() < locked_until,
            None => false,
        }
    }

    /// Add failed authentication attempt
    pub fn add_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        self.updated_at = SystemTime::now();

        // Lock account after 5 failed attempts
        if self.failed_attempts >= 5 {
            self.locked_until = Some(SystemTime::now() + Duration::from_secs(300));
            // 5 minutes
        }
    }

    /// Reset failed attempts (called on successful auth)
    pub fn reset_failed_attempts(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
        self.last_auth = Some(SystemTime::now());
        self.updated_at = SystemTime::now();
    }

    /// Enable authentication factor
    pub fn enable_factor(&mut self, factor: AuthFactor) {
        if !self.enabled_factors.contains(&factor) {
            self.enabled_factors.push(factor);
            self.updated_at = SystemTime::now();
        }
    }

    /// Disable authentication factor
    pub fn disable_factor(&mut self, factor: &AuthFactor) {
        self.enabled_factors.retain(|f| f != factor);
        self.updated_at = SystemTime::now();
    }

    /// Check if factor is enabled
    pub fn has_factor(&self, factor: &AuthFactor) -> bool {
        self.enabled_factors.contains(factor)
    }
}

/// Master key derivation service
pub struct MasterKeyService;

impl MasterKeyService {
    pub fn new() -> Self {
        Self
    }

    /// Derive master encryption key from password
    pub fn derive_master_key(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        use crate::crypto::KeyDerivation;
        KeyDerivation::derive_key_pbkdf2(password, salt, 100_000)
    }

    /// Create encryption service from master password
    pub fn create_encryption_service(&self, password: &str, salt: &[u8]) -> EncryptionService {
        let key = self.derive_master_key(password, salt);
        EncryptionService::new(&key)
    }

    /// Generate salt for master key derivation
    pub fn generate_salt(&self) -> [u8; 32] {
        use crate::crypto::KeyDerivation;
        let base_salt = KeyDerivation::generate_salt();
        let mut extended_salt = [0u8; 32];
        extended_salt[..16].copy_from_slice(&base_salt);
        // Add some additional entropy for the remaining bytes
        use rand::{rngs::OsRng, RngCore};
        OsRng.fill_bytes(&mut extended_salt[16..]);
        extended_salt
    }
}

impl Default for MasterKeyService {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication result
#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    Success,
    InvalidCredentials,
    AccountLocked,
    FactorRequired(AuthFactor),
    PasswordChangeRequired,
}

/// Main authentication service
pub struct AuthService {
    master_key_service: MasterKeyService,
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            master_key_service: MasterKeyService::new(),
        }
    }

    /// Authenticate user with master password
    pub fn authenticate_password(
        &mut self,
        user_auth: &mut UserAuth,
        password: &str,
    ) -> Result<AuthResult> {
        // Check if account is locked
        if user_auth.is_locked() {
            return Ok(AuthResult::AccountLocked);
        }

        // Check if password change is required
        if user_auth.password_change_required {
            return Ok(AuthResult::PasswordChangeRequired);
        }

        // Verify password
        let valid = user_auth.verify_master_password(password)?;

        if valid {
            user_auth.reset_failed_attempts();
            Ok(AuthResult::Success)
        } else {
            user_auth.add_failed_attempt();
            Ok(AuthResult::InvalidCredentials)
        }
    }

    /// Get master key service
    pub fn master_key_service(&self) -> &MasterKeyService {
        &self.master_key_service
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}
