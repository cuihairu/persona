use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey as Ed25519VerifyingKey};
use zeroize::Zeroize;

/// Ed25519 key pair for digital signatures
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("failed to generate random bytes");
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
        getrandom::fill(&mut salt).expect("failed to generate random salt");
        salt
    }

    /// Derive keys using HKDF with SHA-256 (RFC 5869) and an empty salt.
    ///
    /// Implemented directly over `ring::hmac` because `ring::hkdf`'s
    /// `Prk::expand` binds the OKM length to a `KeyType` (an `Algorithm`
    /// yields exactly one digest-width block), so it cannot serve arbitrary
    /// output lengths.
    pub fn derive_keys_hkdf(master_key: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        use ring::hmac;

        let max_len = 255 * ring::digest::SHA256_OUTPUT_LEN;
        assert!(
            length <= max_len,
            "HKDF-Expand length {length} exceeds the RFC 5869 maximum of {max_len}"
        );

        // Extract: PRK = HMAC-SHA256(salt = empty, IKM).
        let salt_key = hmac::Key::new(hmac::HMAC_SHA256, &[]);
        let prk = hmac::sign(&salt_key, master_key);

        // Expand: T(0) = empty; T(i) = HMAC-SHA256(PRK, T(i-1) || info || i);
        // OKM = first `length` bytes of T(1) || T(2) || ...
        let prk_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
        let mut okm = Vec::with_capacity(length);
        let mut prev_block: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while okm.len() < length {
            let mut ctx = hmac::Context::with_key(&prk_key);
            ctx.update(&prev_block);
            ctx.update(info);
            ctx.update(&[counter]);
            prev_block = ctx.sign().as_ref().to_vec();
            let take = (length - okm.len()).min(prev_block.len());
            okm.extend_from_slice(&prev_block[..take]);
            counter += 1;
        }
        okm
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

    #[test]
    fn test_from_secret_bytes_roundtrip() {
        let original = SigningKeyPair::generate();
        let secret = original.secret_key_bytes();

        let restored = SigningKeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(restored.public_key_bytes(), original.public_key_bytes());
        // A signature made by the restored key verifies under the original.
        let signature = restored.sign(b"roundtrip");
        assert!(original.verify(b"roundtrip", &signature).is_ok());
    }

    #[test]
    fn test_from_secret_bytes_rejects_wrong_length() {
        assert!(SigningKeyPair::from_secret_bytes(&[0u8; 31]).is_err());
        assert!(SigningKeyPair::from_secret_bytes(&[0u8; 33]).is_err());
        assert!(SigningKeyPair::from_secret_bytes(&[]).is_err());
    }

    #[test]
    fn test_public_key_accessor_matches_bytes() {
        let keypair = SigningKeyPair::generate();
        assert_eq!(keypair.public_key().to_bytes(), keypair.public_key_bytes());
    }

    #[test]
    fn test_verifying_key_from_bytes_rejects_wrong_length() {
        assert!(VerifyingKey::from_bytes(&[0u8; 0]).is_err());
        assert!(VerifyingKey::from_bytes(&[0u8; 31]).is_err());
        assert!(VerifyingKey::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_verifying_key_to_bytes_roundtrip() {
        let keypair = SigningKeyPair::generate();
        let verifying_key = VerifyingKey::from_bytes(&keypair.public_key_bytes()).unwrap();
        assert_eq!(verifying_key.to_bytes(), keypair.public_key_bytes());

        // The wrapper rejects signatures over a different message.
        let signature = keypair.sign(b"real");
        assert!(verifying_key.verify(b"real", &signature).is_ok());
        assert!(verifying_key.verify(b"forged", &signature).is_err());
    }

    #[test]
    fn test_pbkdf2_salt_and_iterations_change_output() {
        let salt_a = KeyDerivation::generate_salt();
        let mut salt_b = salt_a;
        salt_b[0] ^= 0xFF;

        let base = KeyDerivation::derive_key_pbkdf2("pw", &salt_a, 1000);
        assert_ne!(base, KeyDerivation::derive_key_pbkdf2("pw", &salt_b, 1000));
        assert_ne!(base, KeyDerivation::derive_key_pbkdf2("pw", &salt_a, 2000));
        assert_ne!(
            base,
            KeyDerivation::derive_key_pbkdf2("other", &salt_a, 1000)
        );
    }

    // RFC 5869 Test Case 3 (SHA-256, zero-length salt, zero-length info,
    // L = 42) — matches this function's fixed empty-salt semantics.
    #[test]
    fn test_hkdf_rfc5869_vector_3() {
        let ikm = [0x0bu8; 22];
        let okm = KeyDerivation::derive_keys_hkdf(&ikm, b"", 42);
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
                .replace(' ', "")
        );
    }

    #[test]
    fn test_hkdf_derive_keys_properties() {
        let ikm = [7u8; 32];

        let a = KeyDerivation::derive_keys_hkdf(&ikm, b"persona", 42);
        let b = KeyDerivation::derive_keys_hkdf(&ikm, b"persona", 42);
        assert_eq!(a, b);
        assert_eq!(a.len(), 42);

        // Different info must derive independent keys.
        assert_ne!(a, KeyDerivation::derive_keys_hkdf(&ikm, b"other", 42));
        // Different input key material must derive independent keys.
        assert_ne!(
            a,
            KeyDerivation::derive_keys_hkdf(&[8u8; 32], b"persona", 42)
        );
        // HKDF-Expand outputs are prefix-consistent across lengths.
        let short = KeyDerivation::derive_keys_hkdf(&ikm, b"persona", 32);
        assert_eq!(&a[..32], &short[..]);
    }

    #[test]
    fn test_generate_salt_is_random() {
        let a = KeyDerivation::generate_salt();
        let b = KeyDerivation::generate_salt();
        assert_ne!(a, b);
    }

    #[test]
    fn test_verifying_key_from_bytes_rejects_invalid_point() {
        // Not every 32-byte string decompresses to an Edwards curve point:
        // for a given y only half of the x candidates exist, so some uniform
        // byte patterns must be rejected.
        let rejected = (0u8..16).any(|byte| VerifyingKey::from_bytes(&[byte; 32]).is_err());
        assert!(
            rejected,
            "some uniform 32-byte encodings must be invalid points"
        );
    }
}
