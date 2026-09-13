use crate::{PersonaError, PersonaResult};
use argon2::{
    password_hash::{PasswordHash, SaltString},
    Argon2, PasswordHasher as Argon2PasswordHasher, PasswordVerifier,
};
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
    pub fn hash_password(&self, password: &str) -> PersonaResult<String> {
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes).expect("failed to generate random salt");
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| PersonaError::Crypto(format!("Failed to encode salt: {}", e)))?;
        let hash = Argon2PasswordHasher::hash_password(&self.argon2, password.as_bytes(), &salt)
            .map_err(|e| PersonaError::Crypto(format!("Hashing failed: {}", e)))?;
        Ok(hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> PersonaResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| PersonaError::Crypto(format!("Invalid hash format: {}", e)))?;
        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(PersonaError::Crypto(format!("Verification failed: {}", e))),
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

    #[test]
    fn test_default_hasher_matches_new() {
        let hasher = PasswordHasher::default();
        let hash = hasher.hash_password("default-check").unwrap();
        assert!(hasher.verify_password("default-check", &hash).unwrap());
    }

    #[test]
    fn test_verify_password_rejects_malformed_hash() {
        let hasher = PasswordHasher::new();
        let err = hasher
            .verify_password("pw", "not-an-argon2-hash")
            .expect_err("malformed hash must fail parsing");
        assert!(err.to_string().contains("Invalid hash format"));
    }

    #[test]
    fn test_verify_password_rejects_valid_phc_but_wrong_params() {
        // A syntactically valid PHC string that is not Argon2id must surface
        // a verification error rather than `false`.
        let result = hasher_verify_bad_phc();
        assert!(result.is_err());
    }

    fn hasher_verify_bad_phc() -> PersonaResult<bool> {
        let hasher = PasswordHasher::new();
        // argon2id header but truncated/invalid parameter section
        hasher.verify_password("pw", "$argon2id$v=19$m=64,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$")
    }

    // SHA-256("abc") per FIPS 180-4.
    #[test]
    fn test_sha256_known_vector() {
        let digest = Sha256Hasher::hash(b"abc");
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(Sha256Hasher::hash_string("abc")),
            hex::encode(digest)
        );
        assert_eq!(
            Sha256Hasher::hash_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Sha256Hasher::hash_string_hex("abc"),
            Sha256Hasher::hash_hex(b"abc")
        );
        // The empty input has its own well-known digest.
        assert_eq!(
            Sha256Hasher::hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // RFC 4231 test case 2: HMAC-SHA256 over the quick brown fox.
    #[test]
    fn test_hmac_known_vector() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let mac = HmacSha256::compute(key, data);
        assert_eq!(
            hex::encode(mac),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // Tampered MAC fails verification.
        let mut tampered = mac;
        tampered[0] ^= 0x01;
        assert!(!HmacSha256::verify(key, data, &tampered));
    }
}
