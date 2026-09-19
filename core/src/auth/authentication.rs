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

    /// When the master password was last set (changed); drives opt-in expiry policy
    pub password_updated_at: Option<SystemTime>,

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
            password_updated_at: None,
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

        // Dedup: rotation re-sets the password on an auth row that already
        // carries the MasterPassword factor (initialize_user pushes into a
        // fresh vec).
        if !self.enabled_factors.contains(&AuthFactor::MasterPassword) {
            self.enabled_factors.push(AuthFactor::MasterPassword);
        }
        self.password_change_required = false;
        self.password_updated_at = Some(SystemTime::now());
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
        getrandom::fill(&mut extended_salt[16..]).expect("failed to generate random bytes");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_master_password_generates_salt_once() {
        let mut auth = UserAuth::new(Uuid::new_v4());
        assert!(auth.master_key_salt.is_none());

        auth.set_master_password("correct horse battery staple")
            .unwrap();
        assert!(auth.master_password_hash.is_some());
        assert!(auth.master_key_salt.is_some());
        assert!(auth.has_factor(&AuthFactor::MasterPassword));
        assert!(!auth.password_change_required);

        // Re-setting the password keeps the original salt (key stability).
        let salt = auth.master_key_salt.clone().unwrap();
        auth.set_master_password("new password").unwrap();
        assert_eq!(auth.master_key_salt.as_deref(), Some(salt.as_str()));
    }

    #[test]
    fn test_get_master_key_salt_variants() {
        let mut auth = UserAuth::new(Uuid::new_v4());

        // No salt at all.
        assert!(auth.get_master_key_salt().is_err());

        // Valid salt round-trips to 32 bytes.
        auth.master_key_salt = Some(hex::encode([7u8; 32]));
        assert_eq!(auth.get_master_key_salt().unwrap(), [7u8; 32]);

        // Not valid hex.
        auth.master_key_salt = Some("zz-not-hex".to_string());
        assert!(auth.get_master_key_salt().is_err());

        // Wrong length.
        auth.master_key_salt = Some(hex::encode([7u8; 16]));
        assert!(auth.get_master_key_salt().is_err());
    }

    #[test]
    fn test_verify_master_password() {
        let mut auth = UserAuth::new(Uuid::new_v4());
        // No hash stored -> never verifies.
        assert!(!auth.verify_master_password("anything").unwrap());

        auth.set_master_password("hunter2").unwrap();
        assert!(auth.verify_master_password("hunter2").unwrap());
        assert!(!auth.verify_master_password("hunter3").unwrap());
    }

    #[test]
    fn test_lock_after_failed_attempts() {
        let mut auth = UserAuth::new(Uuid::new_v4());
        assert!(!auth.is_locked());

        for _ in 0..4 {
            auth.add_failed_attempt();
        }
        assert!(!auth.is_locked());

        // 5th attempt triggers the 5-minute lockout.
        auth.add_failed_attempt();
        assert_eq!(auth.failed_attempts, 5);
        assert!(auth.is_locked());

        // A lockout already in the past does not count.
        auth.locked_until = Some(SystemTime::now() - Duration::from_secs(1));
        assert!(!auth.is_locked());
    }

    #[test]
    fn test_reset_failed_attempts() {
        let mut auth = UserAuth::new(Uuid::new_v4());
        for _ in 0..5 {
            auth.add_failed_attempt();
        }
        assert!(auth.is_locked());

        auth.reset_failed_attempts();
        assert_eq!(auth.failed_attempts, 0);
        assert!(auth.locked_until.is_none());
        assert!(auth.last_auth.is_some());
        assert!(!auth.is_locked());
    }

    #[test]
    fn test_factor_management() {
        let mut auth = UserAuth::new(Uuid::new_v4());

        let biometric = AuthFactor::Biometric(BiometricType::Fingerprint);
        auth.enable_factor(biometric.clone());
        auth.enable_factor(biometric.clone()); // duplicate is a no-op
        assert_eq!(auth.enabled_factors.len(), 1);
        assert!(auth.has_factor(&biometric));

        auth.enable_factor(AuthFactor::Pin);
        assert_eq!(auth.enabled_factors.len(), 2);

        auth.disable_factor(&biometric);
        assert!(!auth.has_factor(&biometric));
        assert!(auth.has_factor(&AuthFactor::Pin));
    }

    #[test]
    fn test_auth_factor_serde_round_trip() {
        let factors = vec![
            AuthFactor::MasterPassword,
            AuthFactor::Biometric(BiometricType::FaceId),
            AuthFactor::HardwareKey,
            AuthFactor::Pin,
            AuthFactor::Pattern,
        ];
        for f in factors {
            let json = serde_json::to_string(&f).unwrap();
            let restored: AuthFactor = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, f);
        }
    }

    #[test]
    fn test_master_key_service_deterministic() {
        let service = MasterKeyService::new();
        let salt = service.generate_salt();
        assert_eq!(salt.len(), 32);

        // Random salt every time.
        assert_ne!(service.generate_salt(), salt);

        // Same password+salt -> same key.
        let key1 = service.derive_master_key("pass", &salt);
        let key2 = service.derive_master_key("pass", &salt);
        assert_eq!(key1, key2);
        assert_ne!(service.derive_master_key("other", &salt), key1);

        let _default: MasterKeyService = Default::default();
    }

    #[test]
    fn test_create_encryption_service_round_trip() {
        let service = MasterKeyService::new();
        let salt = service.generate_salt();
        let enc = service.create_encryption_service("master-pass", &salt);

        let ciphertext = enc.encrypt(b"secret data").unwrap();
        assert_ne!(ciphertext, b"secret data");
        assert_eq!(enc.decrypt(&ciphertext).unwrap(), b"secret data");
    }

    #[test]
    fn test_authenticate_password_paths() {
        let mut service = AuthService::new();
        let _ = service.master_key_service();

        let mut auth = UserAuth::new(Uuid::new_v4());
        auth.set_master_password("hunter2").unwrap();

        // Wrong password counts as a failed attempt.
        assert_eq!(
            service.authenticate_password(&mut auth, "wrong").unwrap(),
            AuthResult::InvalidCredentials
        );

        // Correct password succeeds and resets the counter.
        assert_eq!(
            service.authenticate_password(&mut auth, "hunter2").unwrap(),
            AuthResult::Success
        );
        assert_eq!(auth.failed_attempts, 0);

        // Locked account short-circuits before password verification.
        auth.locked_until = Some(SystemTime::now() + Duration::from_secs(300));
        assert_eq!(
            service.authenticate_password(&mut auth, "hunter2").unwrap(),
            AuthResult::AccountLocked
        );
        auth.locked_until = None;

        // Forced password change short-circuits too.
        auth.password_change_required = true;
        assert_eq!(
            service.authenticate_password(&mut auth, "hunter2").unwrap(),
            AuthResult::PasswordChangeRequired
        );

        let _default: AuthService = Default::default();
    }
}
