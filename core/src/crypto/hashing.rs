use argon2::{Argon2, PasswordHasher as Argon2PasswordHasher, PasswordVerifier, password_hash::{PasswordHash, SaltString}};
use rand::rngs::OsRng;
use crate::Result;
use ring::digest::{Context, SHA256};

/// Password hashing service using Argon2
pub struct PasswordHasher {
    argon2: Argon2<'static>,
}

impl PasswordHasher {
    /// Create a new password hasher
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }
    
    /// Hash a password with a random salt
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2PasswordHasher::hash_password(&self.argon2, password.as_bytes(), &salt)
            .map_err(|e| Box::new(crate::PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync>)?;
        Ok(hash.to_string())
    }
    
    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| Box::new(crate::PersonaError::Io(e.to_string())) as Box<dyn std::error::Error + Send + Sync>)?;
        match self.argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(Box::new(crate::PersonaError::Io(e.to_string()))),
        }
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 hashing utilities
pub struct Sha256Hasher;

impl Sha256Hasher {
    /// Compute SHA-256 hash of data
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        result
    }
    
    /// Compute SHA-256 hash of a string
    pub fn hash_string(data: &str) -> [u8; 32] {
        Self::hash(data.as_bytes())
    }
    
    /// Compute SHA-256 hash and return as hex string
    pub fn hash_hex(data: &[u8]) -> String {
        let hash = Self::hash(data);
        hex::encode(hash)
    }
    
    /// Compute SHA-256 hash of string and return as hex string
    pub fn hash_string_hex(data: &str) -> String {
        Self::hash_hex(data.as_bytes())
    }
}

/// HMAC-SHA256 for message authentication
pub struct HmacSha256;

impl HmacSha256 {
    /// Compute HMAC-SHA256
    pub fn compute(key: &[u8], data: &[u8]) -> [u8; 32] {
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let signature = hmac::sign(&key, data);
        let mut result = [0u8; 32];
        result.copy_from_slice(signature.as_ref());
        result
    }
    
    /// Verify HMAC-SHA256
    pub fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&key, data, expected).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing() {
        let hasher = PasswordHasher::new();
        let password = "test_password";
        
        let hash = hasher.hash_password(password).unwrap();
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrong_password", &hash).unwrap());
    }
    
    #[test]
    fn test_sha256_hashing() {
        let data = b"Hello, World!";
        let hash1 = Sha256Hasher::hash(data);
        let hash2 = Sha256Hasher::hash(data);
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
    
    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"message";
        
        let mac = HmacSha256::compute(key, data);
        assert!(HmacSha256::verify(key, data, &mac));
        assert!(!HmacSha256::verify(b"wrong_key", data, &mac));
    }
}