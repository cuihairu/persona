//! Device envelope (E2EE_SYNC_DESIGN DR-1, format `persona-dev-env-1`).
//!
//! Byte layout: `ephemeral_pub(32B) ‖ AES-256-GCM ciphertext(incl. 16B tag)`,
//! total length [`ENVELOPE_LEN`]. Both the encryption key and the nonce are
//! expanded in one shot from the ephemeral DH via HKDF-SHA256 into 44B
//! (key 32 ‖ nonce 12): a fresh ephemeral is generated for every seal, the
//! same `(eph, device_pub)` pair never repeats, so the derived nonce carries
//! no reuse/collision risk.
//!
//! The server only stores the envelope (one per device)——opening it requires
//! the corresponding device private key, which is never uploaded.

use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::PersonaError;

/// HKDF info domain separator (named by DR-1).
pub const DEV_ENVELOPE_INFO: &[u8] = b"persona-dev-env-1";

const EPH_PUB_LEN: usize = 32;
const GROUP_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Total envelope length = eph_pub(32) + group_key(32) + tag(16).
pub const ENVELOPE_LEN: usize = EPH_PUB_LEN + GROUP_KEY_LEN + TAG_LEN;

/// Seal the group key with a device X25519 public key (called when creating a
/// group and when authorizing a new device). `device_public` comes from the
/// device record registered on the server and is untrusted input: if it is a
/// low-order point, the shared secret collapses to a public constant, and
/// anyone (including a malicious server) can open the envelope themselves and
/// swap out the group key——so sealing is refused (fail-closed, symmetric to
/// the same-named defense on the opening side of [`open_group_key`]).
pub fn seal_group_key(
    group_key: &[u8; GROUP_KEY_LEN],
    device_public: &[u8; 32],
) -> Result<Vec<u8>, PersonaError> {
    reject_low_order_public("device public key", device_public)?;
    let mut eph_secret_bytes = [0u8; 32];
    rand::rng().fill(&mut eph_secret_bytes);
    let eph_secret = StaticSecret::from(eph_secret_bytes);
    let eph_public = PublicKey::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&PublicKey::from(*device_public));
    if !shared.was_contributory() {
        return Err(PersonaError::CryptographicError(
            "device public key is a low-order point".to_string(),
        ));
    }
    let okm = derive_okm(&shared);

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let key_bytes: [u8; 32] = okm[..32].try_into().expect("HKDF-SHA256 输出定长");
    let nonce_bytes: [u8; NONCE_LEN] = okm[32..32 + NONCE_LEN]
        .try_into()
        .expect("HKDF-SHA256 输出定长");
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let ciphertext = cipher
        .encrypt((&nonce_bytes).into(), group_key.as_ref())
        .expect("AES-GCM encryption with freshly derived key cannot fail");

    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The device opens the envelope with its own private key. Failure = the
/// envelope was not wrapped for this private key (or was tampered with)——
/// the two causes are not distinguished
/// ([`PersonaError::CryptographicError`]); callers treat either as
/// "not authorized for this sync group" (fail-closed).
///
/// The envelope comes from the server and is untrusted input: if `eph_pub` is
/// a low-order point (e.g. all zeros), the X25519 shared secret collapses to
/// a public constant, and an attacker can recompute HKDF locally and craft a
/// "legitimate" envelope injecting a group key of their choosing——so
/// low-order points are rejected explicitly before AEAD (fail-closed).
pub fn open_group_key(
    envelope: &[u8],
    device_secret: &[u8; 32],
) -> Result<[u8; GROUP_KEY_LEN], PersonaError> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(PersonaError::InvalidInput(format!(
            "device envelope must be {ENVELOPE_LEN} bytes, got {}",
            envelope.len()
        )));
    }
    let eph_public_bytes: [u8; 32] = envelope[..EPH_PUB_LEN]
        .try_into()
        .expect("slice length checked above");
    reject_low_order_public("device envelope ephemeral key", &eph_public_bytes)?;
    let secret = StaticSecret::from(*device_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_public_bytes));
    if !shared.was_contributory() {
        return Err(PersonaError::CryptographicError(
            "device envelope ephemeral key is a low-order point".to_string(),
        ));
    }
    let okm = derive_okm(&shared);

    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    let key_bytes: [u8; 32] = okm[..32].try_into().expect("HKDF-SHA256 输出定长");
    let nonce_bytes: [u8; NONCE_LEN] = okm[32..32 + NONCE_LEN]
        .try_into()
        .expect("HKDF-SHA256 输出定长");
    let cipher = Aes256Gcm::new((&key_bytes).into());
    let plaintext = cipher
        .decrypt((&nonce_bytes).into(), &envelope[EPH_PUB_LEN..])
        .map_err(|_| {
            PersonaError::CryptographicError("device envelope failed authentication".to_string())
        })?;
    plaintext.try_into().map_err(|_| {
        PersonaError::CryptographicError("device envelope payload length mismatch".to_string())
    })
}

/// Explicitly reject all-zero public key bytes (the most common low-order
/// point): early rejection gives a precise error and leaves the DH
/// implementation a defense that does not depend on `was_contributory` in
/// case it is swapped out later. All remaining low-order points are caught by
/// `SharedSecret::was_contributory`——the X25519 output of a low-order point
/// is always all zeros ⇒ the shared secret is non-contributory ⇒ the other
/// side could recompute the derived key locally.
fn reject_low_order_public(what: &str, bytes: &[u8; 32]) -> Result<(), PersonaError> {
    if *bytes == [0u8; 32] {
        return Err(PersonaError::CryptographicError(format!(
            "{what} is an all-zero low-order point"
        )));
    }
    Ok(())
}

/// HKDF-SHA256: salt = None (zero salt), ikm = the ephemeral DH shared
/// secret, info = `persona-dev-env-1`, expanding key(32) ‖ nonce(12).
fn derive_okm(shared: &x25519_dalek::SharedSecret) -> [u8; 32 + NONCE_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32 + NONCE_LEN];
    hk.expand(DEV_ENVELOPE_INFO, &mut okm)
        .expect("44-byte OKM is valid for HKDF-SHA256");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::keys::DeviceKeyPair;

    fn keypair() -> DeviceKeyPair {
        DeviceKeyPair::generate().unwrap()
    }

    #[test]
    fn seal_open_round_trip() {
        let device = keypair();
        let group_key = [7u8; 32];
        let envelope = seal_group_key(&group_key, device.public_bytes()).unwrap();
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        let opened = open_group_key(&envelope, device.secret_bytes()).unwrap();
        assert_eq!(opened, group_key);
    }

    #[test]
    fn wrong_device_cannot_open() {
        let device = keypair();
        let outsider = keypair();
        let envelope = seal_group_key(&[1u8; 32], device.public_bytes()).unwrap();
        let err = open_group_key(&envelope, outsider.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("failed authentication"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let device = keypair();
        let mut envelope = seal_group_key(&[2u8; 32], device.public_bytes()).unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        assert!(open_group_key(&envelope, device.secret_bytes()).is_err());
    }

    #[test]
    fn tampered_ephemeral_public_is_rejected() {
        let device = keypair();
        let mut envelope = seal_group_key(&[3u8; 32], device.public_bytes()).unwrap();
        envelope[0] ^= 0xff;
        assert!(open_group_key(&envelope, device.secret_bytes()).is_err());
    }

    #[test]
    fn truncated_envelope_is_a_length_error() {
        let device = keypair();
        let err = open_group_key(&[0u8; 10], device.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("bytes, got 10"), "{err}");
    }

    #[test]
    fn sealing_twice_produces_unlinked_envelopes() {
        // The ephemeral is regenerated each time: sealing the same group key
        // twice produces different envelopes (unlinkability), and each can be
        // opened with the device private key
        let device = keypair();
        let group_key = [9u8; 32];
        let a = seal_group_key(&group_key, device.public_bytes()).unwrap();
        let b = seal_group_key(&group_key, device.public_bytes()).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            open_group_key(&a, device.secret_bytes()).unwrap(),
            group_key
        );
        assert_eq!(
            open_group_key(&b, device.secret_bytes()).unwrap(),
            group_key
        );
    }

    /// Regression (AUDIT-2026-11-05 P1-3): when a malicious server replaces
    /// the envelope's `eph_pub` with a low-order point (all zeros), the
    /// shared secret collapses to a public constant and an attacker could
    /// recompute the key locally and craft a "legitimate" envelope injecting
    /// a group key of their choosing——must be rejected before AEAD, and the
    /// error must name the low-order point (rather than a vague
    /// authentication failed).
    #[test]
    fn open_rejects_all_zero_ephemeral_public() {
        let device = keypair();
        let mut envelope = seal_group_key(&[4u8; 32], device.public_bytes()).unwrap();
        envelope[..EPH_PUB_LEN].fill(0);
        let err = open_group_key(&envelope, device.secret_bytes()).unwrap_err();
        assert!(err.to_string().contains("low-order"), "{err}");
    }

    /// The sealing side of the same defense: if the device public key
    /// registered on the server is a low-order point, the sealed envelope is
    /// transparent to the attacker——refuse to seal rather than producing an
    /// envelope that can be opened.
    #[test]
    fn seal_rejects_all_zero_device_public() {
        let err = seal_group_key(&[5u8; 32], &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("low-order"), "{err}");
    }
}
