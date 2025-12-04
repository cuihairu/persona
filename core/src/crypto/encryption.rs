use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, PasswordHash, PasswordVerifier};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

/// Encrypted data with metadata
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Encrypt data with password-derived key
pub fn encrypt_data(plaintext: &[u8], password: &[u8]) -> Result<EncryptedData, aes_gcm::Error> {
    // Generate random salt
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive key from password using Argon2
    let mut key = [0u8; 32];
    derive_key_from_password(password, &salt, &mut key);

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt
    let key_ref = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key_ref);
    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    // Zeroize the key
    key.zeroize();

    Ok(EncryptedData {
        ciphertext,
        salt,
        nonce: nonce_bytes.to_vec(),
    })
}

/// Decrypt data with password-derived key
pub fn decrypt_data(
    ciphertext: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    // Derive key from password
    let mut key = [0u8; 32];
    derive_key_from_password(password, salt, &mut key);

    // Create cipher and decrypt
    let key_ref = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key_ref);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    // Zeroize the key
    key.zeroize();

    Ok(plaintext)
}

/// Derive encryption key from password using Argon2
fn derive_key_from_password(password: &[u8], salt: &[u8], output: &mut [u8; 32]) {
    use argon2::Argon2;

    let argon2 = Argon2::default();

    // Use Argon2 to derive key
    argon2
        .hash_password_into(password, salt, output)
        .expect("Failed to derive key from password");
}

/// AES-256-GCM encryption service
pub struct EncryptionService {
    cipher: Aes256Gcm,
}

impl EncryptionService {
    /// Create a new encryption service with the given key
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    /// Generate a random 256-bit encryption key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt data with a random nonce
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data (nonce is expected to be prepended to ciphertext)
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        if encrypted_data.len() < 12 {
            return Err(aes_gcm::Error);
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher.decrypt(nonce, ciphertext)
    }
}

/// Secure string that automatically zeros memory on drop
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new secure string from a string
    pub fn from_string(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    /// Get the data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Convert to string (unsafe - use with caution)
    pub fn to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secure string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Zeroize for SecureString {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = EncryptionService::generate_key();
        let service = EncryptionService::new(&key);

        let plaintext = b"Hello, World!";
        let encrypted = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_secure_string() {
        let secure = SecureString::from_string("secret".to_string());
        assert_eq!(secure.len(), 6);
        assert_eq!(secure.to_string_lossy(), "secret");
    }
}
