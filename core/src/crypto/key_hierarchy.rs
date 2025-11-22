use zeroize::Zeroize;

use super::encryption::EncryptionService;
use crate::{PersonaError, Result};

/// Envelope containing an encrypted payload plus its wrapped item key
pub struct ItemKeyEnvelope {
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Implements per-item key hierarchy using the master encryption key to wrap item keys.
pub struct KeyHierarchy<'a> {
    master_encryption: &'a EncryptionService,
}

impl<'a> KeyHierarchy<'a> {
    pub fn new(master_encryption: &'a EncryptionService) -> Self {
        Self { master_encryption }
    }

    /// Encrypt plaintext with a randomly generated item key and wrap that key with the master key.
    pub fn encrypt_with_new_item_key(&self, plaintext: &[u8]) -> Result<ItemKeyEnvelope> {
        let mut item_key = EncryptionService::generate_key();
        let item_cipher = EncryptionService::new(&item_key);

        let ciphertext = item_cipher.encrypt(plaintext).map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to encrypt payload: {}", e))
        })?;

        let wrapped_key = self.master_encryption.encrypt(&item_key).map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to wrap item key: {}", e))
        })?;

        item_key.zeroize();

        Ok(ItemKeyEnvelope {
            wrapped_key,
            ciphertext,
        })
    }

    /// Decrypt payload that was encrypted with a wrapped item key.
    pub fn decrypt_with_wrapped_key(
        &self,
        wrapped_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let item_key_bytes = self.master_encryption.decrypt(wrapped_key).map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to unwrap item key: {}", e))
        })?;

        if item_key_bytes.len() != 32 {
            return Err(PersonaError::CryptographicError(
                "Unwrapped key has invalid length".to_string(),
            )
            .into());
        }

        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_bytes);
        let item_cipher = EncryptionService::new(&item_key);
        item_key.zeroize();

        item_cipher.decrypt(ciphertext).map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to decrypt payload: {}", e)).into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptionService;

    #[test]
    fn encrypt_and_decrypt_round_trip() {
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);
        let hierarchy = KeyHierarchy::new(&master);

        let plaintext = b"super secret data";
        let envelope = hierarchy.encrypt_with_new_item_key(plaintext).unwrap();
        assert!(!envelope.wrapped_key.is_empty());
        assert!(!envelope.ciphertext.is_empty());

        let decrypted = hierarchy
            .decrypt_with_wrapped_key(&envelope.wrapped_key, &envelope.ciphertext)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
