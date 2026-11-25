//! Sync group key and device identity keys (E2EE_SYNC_DESIGN DR-1 / DR-3).
//!
//! - **group key**: random 256 bits, one per workspace, never leaves the
//!   device in plaintext and never reaches the server in plaintext——on the
//!   server it exists only in the form of a "device envelope"
//!   ([`super::envelope`]). Rotating the master password does not touch it
//!   (the key to decoupling sync from the master password).
//! - **device key pair**: a one-shot X25519 keypair generated when each device
//!   joins sync; the private key is persisted by the host (OS keyring service
//!   `persona-device`, or in headless environments the explicit
//!   `--device-key-file` 0600 file fallback——core does not depend on keyring,
//!   it only offers generation and loading).

use rand::RngExt;
use zeroize::Zeroize;

use crate::PersonaError;

/// The sync group key. Zeroes memory on `Drop` (plaintext copies that never
/// reach the persistence layer should be as short-lived as possible).
#[derive(Clone, PartialEq, Eq, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GroupKey([u8; 32]);

impl core::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Key bytes never go into logs
        f.write_str("GroupKey(<32 bytes>)")
    }
}

impl GroupKey {
    /// Generate a new group key (once, when the group is created).
    pub fn generate() -> Result<Self, PersonaError> {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Ok(Self(bytes))
    }

    /// Load from bytes (used when opening an envelope / restoring from local
    /// storage).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Device identity keypair (X25519). The private key bytes only appear at
/// construction and when read out via `secret_bytes`——the host then stores
/// them in its own keyring/file.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKeyPair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl DeviceKeyPair {
    /// Generate a new device keypair (once, when joining sync).
    pub fn generate() -> Result<Self, PersonaError> {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        Ok(Self::from_secret(secret))
    }

    /// Restore from private key bytes (used when the host reads them back
    /// from keyring/file); the public key is derived immediately.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};
        let public = PublicKey::from(&StaticSecret::from(secret));
        Self {
            secret,
            public: public.to_bytes(),
        }
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Item key wrapping for the sync payload (`SyncPayload.wrapped_item_key`).
///
/// The oplog only holds ciphertext: the entry ciphertext is sealed with the
/// item key (the same scheme as the main DB), and the item key is in turn
/// symmetrically sealed with the group key——once a remote device opens the
/// group envelope and obtains the group key, it can recover the item key and
/// restore the entry; the server can read neither layer. The format reuses
/// `EncryptionService`'s "12B random nonce prefixed ‖ AES-256-GCM
/// ciphertext": for the same (group, item) pair every wrapping uses a fresh
/// nonce, so there is no reuse risk.
pub fn wrap_item_key_with_group(item_key: &[u8; 32], group_key: &GroupKey) -> Vec<u8> {
    crate::crypto::encryption::EncryptionService::new(group_key.as_bytes())
        .encrypt(item_key)
        .expect("AES-GCM with fresh random nonce cannot fail")
}

/// Unwrap the group wrapping to recover the item key. Failure means the group
/// key is wrong or the wrapping was tampered with (the cause is not
/// distinguished; fail-closed, same as [`super::envelope::open_group_key`]).
pub fn unwrap_item_key_with_group(
    wrapped: &[u8],
    group_key: &GroupKey,
) -> Result<[u8; 32], PersonaError> {
    let plaintext = crate::crypto::encryption::EncryptionService::new(group_key.as_bytes())
        .decrypt(wrapped)
        .map_err(|_| {
            PersonaError::CryptographicError("failed to unwrap item key with group key".to_string())
        })?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|_| {
        PersonaError::CryptographicError("unwrapped item key has wrong length".to_string())
    })?;
    Ok(bytes)
}

impl Drop for DeviceKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_key_generation_is_unique() {
        let a = GroupKey::generate().unwrap();
        let b = GroupKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Key bytes never reach Debug/log output.
    #[test]
    fn group_key_debug_never_leaks_bytes() {
        let key = GroupKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "GroupKey(<32 bytes>)");
    }

    #[test]
    fn group_key_round_trips_through_bytes() {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let key = GroupKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    /// Reject when the plaintext unwrapped by the group key is not a 32-byte
    /// item key (protocol invariant).
    #[test]
    fn unwrap_item_key_rejects_wrong_plaintext_length() {
        let group = GroupKey::generate().unwrap();
        let cipher = crate::crypto::encryption::EncryptionService::new(group.as_bytes())
            .encrypt(b"only 7")
            .unwrap();
        let err = unwrap_item_key_with_group(&cipher, &group).unwrap_err();
        assert!(err.to_string().contains("wrong length"), "{err}");
    }

    #[test]
    fn device_keypair_public_is_derived_from_secret() {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        let pair = DeviceKeyPair::from_secret(secret);
        let again = DeviceKeyPair::from_secret(secret);
        assert_eq!(pair.public_bytes(), again.public_bytes());

        // Matches deriving directly with dalek
        use x25519_dalek::{PublicKey, StaticSecret};
        let expected = PublicKey::from(&StaticSecret::from(secret));
        assert_eq!(pair.public_bytes(), &expected.to_bytes());
    }

    #[test]
    fn device_keypair_generation_is_unique() {
        let a = DeviceKeyPair::generate().unwrap();
        let b = DeviceKeyPair::generate().unwrap();
        assert_ne!(a.secret_bytes(), b.secret_bytes());
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn group_wrap_round_trips_item_key() {
        let group = GroupKey::generate().unwrap();
        let item_key = [7u8; 32];
        let wrapped = wrap_item_key_with_group(&item_key, &group);
        assert_ne!(wrapped[..32], item_key, "包裹必须是密文而非明文透传");
        let opened = unwrap_item_key_with_group(&wrapped, &group).unwrap();
        assert_eq!(opened, item_key);
    }

    #[test]
    fn group_wrap_is_randomized_per_call() {
        let group = GroupKey::generate().unwrap();
        let item_key = [9u8; 32];
        let a = wrap_item_key_with_group(&item_key, &group);
        let b = wrap_item_key_with_group(&item_key, &group);
        assert_ne!(a, b, "随机 nonce 使每次包裹字节不同");
        assert_eq!(
            unwrap_item_key_with_group(&a, &group).unwrap(),
            unwrap_item_key_with_group(&b, &group).unwrap()
        );
    }

    #[test]
    fn wrong_group_key_cannot_unwrap() {
        let group = GroupKey::generate().unwrap();
        let other = GroupKey::generate().unwrap();
        let wrapped = wrap_item_key_with_group(&[1u8; 32], &group);
        assert!(unwrap_item_key_with_group(&wrapped, &other).is_err());
        // Tampering with the wrapping also fails closed
        let mut tampered = wrapped.clone();
        tampered[20] ^= 0xff;
        assert!(unwrap_item_key_with_group(&tampered, &group).is_err());
        // Truncation/oversized input errors out rather than panicking
        assert!(unwrap_item_key_with_group(&wrapped[..16], &group).is_err());
    }
}
