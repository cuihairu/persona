use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey as Ed25519VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

/// Ed25519 key pair for digital signatures
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        Self { signing_key }
    }

    /// Create from existing secret key bytes
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        if secret_bytes.len() != 32 {
            return Err(ed25519_dalek::SignatureError::new());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> Ed25519VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the secret key as bytes (use with caution)
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.signing_key.verifying_key().verify(message, signature)
    }
}

impl Drop for SigningKeyPair {
    fn drop(&mut self) {
        // Zeroize the signing key bytes
        self.signing_key.to_bytes().zeroize();
    }
}

/// Wrapper for public key verification
pub struct VerifyingKey {
    public_key: Ed25519VerifyingKey,
}

impl VerifyingKey {
    /// Create from public key bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        let public_key = Ed25519VerifyingKey::from_bytes(
            bytes
                .try_into()
                .map_err(|_| ed25519_dalek::SignatureError::new())?,
        )?;
        Ok(Self { public_key })
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.public_key.verify(message, signature)
    }
}

/// Key derivation utilities
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive key using PBKDF2 with SHA-256
    pub fn derive_key_pbkdf2(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        use ring::pbkdf2;
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).unwrap(),
            salt,
            password.as_bytes(),
            &mut key,
        );
        key
    }

    /// Generate a random salt
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive keys using HKDF with SHA-256
    pub fn derive_keys_hkdf(master_key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        use ring::hkdf;
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(master_key);
        let info_slice = [info];
        let okm = prk.expand(&info_slice, hkdf::HKDF_SHA256).unwrap();
        let mut output = vec![0u8; length];
        okm.fill(&mut output).unwrap();
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_keypair() {
        let keypair = SigningKeyPair::generate();
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());

        // Test with wrong message
        let wrong_message = b"wrong message";
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verifying_key() {
        let keypair = SigningKeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        let public_key_bytes = keypair.public_key_bytes();
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt = KeyDerivation::generate_salt();

        let key1 = KeyDerivation::derive_key_pbkdf2(password, &salt, 10000);
        let key2 = KeyDerivation::derive_key_pbkdf2(password, &salt, 10000);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
