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
        let item_key = self.unwrap_item_key(wrapped_key)?;
        let item_cipher = EncryptionService::new(&item_key);

        item_cipher.decrypt(ciphertext).map_err(|e| {
            PersonaError::CryptographicError(format!("Failed to decrypt payload: {}", e)).into()
        })
    }

    /// Unwrap a per-item key without touching its payload (master-password
    /// rotation: re-wrap the same item key under the new master key).
    fn unwrap_item_key(&self, wrapped_key: &[u8]) -> Result<[u8; 32]> {
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
        Ok(item_key)
    }

    /// Re-wrap a per-item key under a new master key. The item key itself is
    /// unchanged, so the payload ciphertext needs no re-encryption. Used by
    /// master-password rotation (`PersonaService::change_master_password`).
    pub fn rewrap_wrapped_key(
        wrapped_key: &[u8],
        old_master: &EncryptionService,
        new_master: &EncryptionService,
    ) -> Result<Vec<u8>> {
        let old_hierarchy = KeyHierarchy::new(old_master);
        let item_key = old_hierarchy.unwrap_item_key(wrapped_key)?;

        let new_hierarchy = KeyHierarchy::new(new_master);
        let rewrapped = new_hierarchy
            .master_encryption
            .encrypt(&item_key)
            .map_err(|e| {
                PersonaError::CryptographicError(format!("Failed to wrap item key: {}", e))
            })?;

        let mut item_key = item_key;
        item_key.zeroize();
        Ok(rewrapped)
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

    #[test]
    fn wrong_master_key_cannot_unwrap() {
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);
        let hierarchy = KeyHierarchy::new(&master);

        let envelope = hierarchy.encrypt_with_new_item_key(b"data").unwrap();

        // A different master key fails the AEAD check while unwrapping.
        let other_key = EncryptionService::generate_key();
        let other = EncryptionService::new(&other_key);
        let other_hierarchy = KeyHierarchy::new(&other);
        let err = other_hierarchy
            .decrypt_with_wrapped_key(&envelope.wrapped_key, &envelope.ciphertext)
            .expect_err("foreign master key must not unwrap");
        assert!(err.to_string().contains("Failed to unwrap item key"));
    }

    #[test]
    fn wrapped_key_of_wrong_length_is_rejected() {
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);
        let hierarchy = KeyHierarchy::new(&master);

        // Valid AEAD payload, but the plaintext inside is not a 32-byte key.
        let bogus_wrapped = master.encrypt(b"not-a-32-byte-key").unwrap();
        let err = hierarchy
            .decrypt_with_wrapped_key(&bogus_wrapped, &[0u8; 16])
            .expect_err("non-32-byte unwrapped key must be rejected");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn tampered_ciphertext_fails_payload_decrypt() {
        let master_key = EncryptionService::generate_key();
        let master = EncryptionService::new(&master_key);
        let hierarchy = KeyHierarchy::new(&master);

        let envelope = hierarchy.encrypt_with_new_item_key(b"payload").unwrap();
        let mut tampered = envelope.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let err = hierarchy
            .decrypt_with_wrapped_key(&envelope.wrapped_key, &tampered)
            .expect_err("tampered payload must not decrypt");
        assert!(err.to_string().contains("Failed to decrypt payload"));
    }
}
