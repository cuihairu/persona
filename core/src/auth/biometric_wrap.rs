//! Hardware-bound key wrapping layer (biometric key wrapping).
//!
//! See `docs/biometric-unlock-design.md` for the full design. Unlike the gate
//! layer in [`super::biometric`] (OS prompt + keyring-managed master
//! password), this layer **encrypts and wraps** the vault master key with a
//! platform hardware key (Secure Enclave / TPM / Android Keystore) —
//! biometrics are enforced by the hardware at the moment of decryption, the
//! private key is never exported, and the keyring only stores an unwrappable
//! wrapped blob.
//!
//! The platform-independent parts (envelope encoding/decoding, enrollment
//! fingerprint comparison, trait contract) live in core; the platform-private
//! ciphertext (payload) is entirely up to the [`BiometricKeyWrapper`]
//! implementation, and intermediate values are always wrapped in `Zeroizing`.
//! Unimplemented platforms return [`BiometricWrapError::Unsupported`] instead
//! of panicking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::PersonaError;

/// Wrap envelope magic + version (BIOWRAP1; bump the trailing digit when the format changes)
const WRAP_MAGIC: &[u8; 8] = b"BIOWRAP1";

/// Fixed header length: `magic(8) | platform_tag(1) | enrollment_fp(32) | payload_len(4)`
const WRAP_HEADER_LEN: usize = 8 + 1 + 32 + 4;

/// Platform identifier (envelope header field; a tag mismatch on unwrap = the blob was not produced on this platform)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WrapPlatform {
    /// Test/CI mock
    Mock = 0,
    /// macOS Secure Enclave (route B', see design doc §5)
    MacSecureEnclave = 1,
    /// Windows TPM / Passport Key (planned, design doc §6)
    WindowsTpm = 2,
    /// Linux (reserved — currently pinned to the OsGateOnly tier, design doc §7.1)
    Linux = 3,
}

impl WrapPlatform {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Mock),
            1 => Some(Self::MacSecureEnclave),
            2 => Some(Self::WindowsTpm),
            3 => Some(Self::Linux),
            _ => None,
        }
    }

    /// `u8` encoding used in the envelope (inverse of `from_u8`; the enum value is the wire format)
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Capability tiers for biometric unlock (three tiers, design doc §1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricWrapCapability {
    /// Hardware-bound: the private key cannot be exported and decryption forces user authentication in hardware
    HardwareBound,
    /// OS gate only: keyring-managed + OS prompt (Linux today / platforms without the hardware layer enabled)
    OsGateOnly,
    /// No biometric hardware or system authentication stack; the feature is hidden entirely
    Unsupported,
}

/// Structured errors of the wrap layer (the desktop branches its fallback chain on these, design doc §3.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricWrapError {
    /// The platform/hardware does not support the hardware-bound tier
    Unsupported,
    /// Hardware or biometric enrollment is currently unavailable
    NotAvailable,
    /// The user cancelled the OS prompt (silently return to the unlock screen)
    UserCancelled,
    /// The biometric enrollment set has changed (a different fingerprint, etc.), permanently invalidating the wrap -> fall back to the master password automatically
    EnrollmentChanged,
    /// The wrap blob is corrupted / was replaced / was not produced on this platform
    WrapInvalid,
    /// Platform implementation error (OSStatus / HRESULT and the like go into the string verbatim)
    Platform(String),
}

impl BiometricWrapError {
    /// Map into PersonaError (service-layer signatures uniformly use crate::Result)
    pub fn to_persona_error(&self) -> PersonaError {
        PersonaError::AuthenticationFailed(self.to_string())
    }
}

impl std::fmt::Display for BiometricWrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "biometric key wrapping is not supported on this platform"
            ),
            Self::NotAvailable => write!(f, "biometric hardware is not currently available"),
            Self::UserCancelled => write!(f, "biometric prompt was cancelled by the user"),
            Self::EnrollmentChanged => write!(
                f,
                "biometric enrollment changed since the key was wrapped; the wrap is invalid"
            ),
            Self::WrapInvalid => write!(f, "biometric wrap blob is invalid or corrupted"),
            Self::Platform(msg) => write!(f, "biometric platform error: {msg}"),
        }
    }
}

/// Platform hardware wrapper (platforms implement the payload ciphertext;
/// the envelope and fingerprint comparison live in core).
///
/// Implementor contract:
/// - `wrap_payload`/`unwrap_payload` are the only two methods that touch the
///   plaintext key; the platform should encrypt/decrypt in place after
///   hardware authentication succeeds, and the private key never leaves
///   memory anywhere else;
/// - `enrollment_fingerprint` returns a stable fingerprint of the current
///   biometric enrollment set (platforms where the hardware already enforces
///   biometryCurrentSet may return a fixed placeholder value);
/// - unsupported platforms implement the same as [`MockKeyWrapper`]:
///   capability reports `Unsupported`, and methods return
///   [`BiometricWrapError::Unsupported`].
pub trait BiometricKeyWrapper: Send + Sync {
    fn capability(&self) -> BiometricWrapCapability;

    /// Whether hardware/biometric enrollment is currently available (probe failure fail-closes to false)
    fn is_available(&self) -> bool;

    fn platform(&self) -> WrapPlatform;

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError>;

    /// Wrap the master key (the payload ciphertext; core adds the envelope header)
    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError>;

    /// Unwrap the payload (the hardware enforces biometrics at this moment; returns the key wrapped in Zeroizing)
    fn unwrap_payload(
        &self,
        payload: &[u8],
        prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError>;

    /// Delete the key/credential persisted on the hardware side (called when
    /// disabling and during invalidation self-healing; best-effort, return Ok
    /// when the platform has nothing persisted)
    fn delete_wrap_payload(&self, payload: &[u8]) -> std::result::Result<(), BiometricWrapError>;
}

/// Assemble the complete wrap envelope
/// (`BIOWRAP1 | tag | enrollment_fp | payload_len | payload`).
///
/// Called by the host on enable: capability probe -> fingerprint -> payload
/// -> envelope. Any wrapper that is not HardwareBound returns `Unsupported`
/// (configuration operations must not silently downgrade to a weaker tier —
/// whether to downgrade is a user-visible explicit decision, see design doc
/// §4).
pub fn wrap_master_key(
    wrapper: &dyn BiometricKeyWrapper,
    master_key: &[u8; 32],
    prompt: &str,
) -> std::result::Result<Vec<u8>, BiometricWrapError> {
    if wrapper.capability() != BiometricWrapCapability::HardwareBound {
        return Err(BiometricWrapError::Unsupported);
    }
    if !wrapper.is_available() {
        return Err(BiometricWrapError::NotAvailable);
    }
    let enrollment_fp = wrapper.enrollment_fingerprint()?;
    let payload = wrapper.wrap_payload(master_key, prompt)?;
    let payload_len = envelope_payload_len(payload.len())?;
    let mut out = Vec::with_capacity(WRAP_HEADER_LEN + payload.len());
    out.extend_from_slice(WRAP_MAGIC);
    out.push(wrapper.platform().as_u8());
    out.extend_from_slice(&enrollment_fp);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Payload byte count -> the `u32` length field in the envelope. A payload
/// larger than `u32::MAX` cannot be encoded into the fixed header and is
/// treated as a platform implementation error (report `Platform` so the host
/// fails explicitly; never silently truncate the length — truncation would
/// make the unwrapping side read out-of-bounds ciphertext).
fn envelope_payload_len(len: usize) -> std::result::Result<u32, BiometricWrapError> {
    u32::try_from(len).map_err(|_| {
        BiometricWrapError::Platform(format!(
            "wrap payload of {len} bytes exceeds envelope limit"
        ))
    })
}

/// Unwrap the complete wrap envelope: verify magic/platform -> compare the
/// enrollment fingerprint -> hand the payload to the platform to unwrap (the
/// hardware pops the biometric prompt at this moment).
///
/// The fingerprint comparison is the second defense-in-depth line: even if
/// the platform layer fails to intercept enrollment drift (missing
/// `biometryCurrentSet` semantics), this still rejects with
/// [`BiometricWrapError::EnrollmentChanged`], on which the host deletes the
/// blob automatically and falls back to the master password.
pub fn unwrap_master_key(
    wrapper: &dyn BiometricKeyWrapper,
    envelope: &[u8],
    prompt: &str,
) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
    if wrapper.capability() != BiometricWrapCapability::HardwareBound {
        return Err(BiometricWrapError::Unsupported);
    }
    if !wrapper.is_available() {
        return Err(BiometricWrapError::NotAvailable);
    }
    let (tag, enrollment_fp, payload) = parse_wrap_envelope(envelope)?;
    if tag != wrapper.platform() {
        return Err(BiometricWrapError::WrapInvalid);
    }
    if wrapper.enrollment_fingerprint()? != enrollment_fp {
        return Err(BiometricWrapError::EnrollmentChanged);
    }
    wrapper.unwrap_payload(payload, prompt)
}

/// Parse the envelope header and return (platform, fingerprint, payload
/// slice). Any shape mismatch is [`BiometricWrapError::WrapInvalid`].
///
/// `payload_len` and the actual remaining bytes must be **exactly equal**: a
/// mismatch means the blob was truncated or has trailing garbage appended,
/// and both are rejected — any bytes after the platform payload ciphertext
/// are evidence of tampering.
pub fn parse_wrap_envelope(
    envelope: &[u8],
) -> std::result::Result<(WrapPlatform, [u8; 32], &[u8]), BiometricWrapError> {
    if envelope.len() < WRAP_HEADER_LEN {
        return Err(BiometricWrapError::WrapInvalid);
    }
    if &envelope[..WRAP_MAGIC.len()] != WRAP_MAGIC {
        return Err(BiometricWrapError::WrapInvalid);
    }
    let tag =
        WrapPlatform::from_u8(envelope[WRAP_MAGIC.len()]).ok_or(BiometricWrapError::WrapInvalid)?;
    let fp_start = WRAP_MAGIC.len() + 1;
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&envelope[fp_start..fp_start + 32]);
    let len_start = fp_start + 32;
    let declared_len = u32::from_le_bytes(
        envelope[len_start..len_start + 4]
            .try_into()
            .map_err(|_| BiometricWrapError::WrapInvalid)?,
    ) as usize;
    let payload = &envelope[WRAP_HEADER_LEN..];
    if declared_len == 0 || declared_len != payload.len() {
        return Err(BiometricWrapError::WrapInvalid);
    }
    Ok((tag, fp, payload))
}

// ---------------------------------------------------------------------------
// Mock implementation (CI / tests / the placeholder behavior baseline for non-HardwareBound platforms)
// ---------------------------------------------------------------------------

/// In-memory mock: payload = 16 random bytes as an id, with the wrap table
/// held in process memory. The failure-injection toggles cover every branch
/// of the fallback chain (design doc §3.4).
#[derive(Default)]
struct MockInner {
    available: bool,
    fail_wrap: bool,
    fail_unwrap: bool,
    fail_delete: bool,
    user_cancelled: bool,
    enrollment: [u8; 32],
    wraps: HashMap<[u8; 16], Zeroizing<[u8; 32]>>,
}

/// Hardware-bound mock wrapper (used by core/service tests and CI; production
/// platforms implement their own backends).
pub struct MockKeyWrapper {
    inner: Mutex<MockInner>,
}

impl Default for MockKeyWrapper {
    fn default() -> Self {
        let mut enrollment = [0u8; 32];
        getrandom::fill(&mut enrollment).expect("failed to generate mock enrollment fingerprint");
        Self {
            inner: Mutex::new(MockInner {
                available: true,
                enrollment,
                ..MockInner::default()
            }),
        }
    }
}

impl MockKeyWrapper {
    /// Simulate the user deleting/adding a fingerprint in biometric enrollment: all existing wraps become invalid
    pub fn rotate_enrollment(&self) {
        let mut inner = self.inner.lock().unwrap();
        getrandom::fill(&mut inner.enrollment).expect("failed to rotate mock enrollment");
    }

    /// Simulate the user tapping cancel on the OS prompt
    pub fn set_user_cancelled(&self, cancelled: bool) {
        self.inner.lock().unwrap().user_cancelled = cancelled;
    }

    /// Inject hardware errors (in the wrap / unwrap / delete directions)
    pub fn set_fail(&self, target: MockFailTarget, fail: bool) {
        let mut inner = self.inner.lock().unwrap();
        match target {
            MockFailTarget::Wrap => inner.fail_wrap = fail,
            MockFailTarget::Unwrap => inner.fail_unwrap = fail,
            MockFailTarget::Delete => inner.fail_delete = fail,
        }
    }

    /// Simulate hardware being unavailable (an old Mac without a SE / a wiped biometric enrollment)
    pub fn set_available(&self, available: bool) {
        self.inner.lock().unwrap().available = available;
    }

    /// Break the integrity of a wrap payload (simulate the blob being tampered with or moved to another platform)
    pub fn corrupt(&self, envelope: &mut [u8]) {
        let last = envelope.len() - 1;
        envelope[last] = envelope[last].wrapping_add(1);
    }
}

/// Injection direction for [`MockKeyWrapper::set_fail`]
#[derive(Debug, Clone, Copy)]
pub enum MockFailTarget {
    Wrap,
    Unwrap,
    Delete,
}

impl BiometricKeyWrapper for MockKeyWrapper {
    fn capability(&self) -> BiometricWrapCapability {
        BiometricWrapCapability::HardwareBound
    }

    fn is_available(&self) -> bool {
        self.inner.lock().unwrap().available
    }

    fn platform(&self) -> WrapPlatform {
        WrapPlatform::Mock
    }

    fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
        Ok(self.inner.lock().unwrap().enrollment)
    }

    fn wrap_payload(
        &self,
        master_key: &[u8; 32],
        _prompt: &str,
    ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_wrap {
            return Err(BiometricWrapError::Platform("mock wrap failure".into()));
        }
        if inner.user_cancelled {
            return Err(BiometricWrapError::UserCancelled);
        }
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("failed to generate mock wrap id");
        inner.wraps.insert(id, Zeroizing::new(*master_key));
        Ok(id.to_vec())
    }

    fn unwrap_payload(
        &self,
        payload: &[u8],
        _prompt: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
        let inner = self.inner.lock().unwrap();
        if inner.fail_unwrap {
            return Err(BiometricWrapError::Platform("mock unwrap failure".into()));
        }
        if inner.user_cancelled {
            return Err(BiometricWrapError::UserCancelled);
        }
        if payload.len() != 16 {
            return Err(BiometricWrapError::WrapInvalid);
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(payload);
        inner
            .wraps
            .get(&id)
            .cloned()
            .ok_or(BiometricWrapError::WrapInvalid)
    }

    fn delete_wrap_payload(&self, payload: &[u8]) -> std::result::Result<(), BiometricWrapError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_delete {
            return Err(BiometricWrapError::Platform("mock delete failure".into()));
        }
        if payload.len() == 16 {
            let mut id = [0u8; 16];
            id.copy_from_slice(payload);
            inner.wraps.remove(&id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn wrap_and_unwrap_roundtrip() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(7), "enable").unwrap();
        let unlocked = unwrap_master_key(&wrapper, &envelope, "unlock").unwrap();
        assert_eq!(*unlocked, key(7));
    }

    #[test]
    fn envelope_layout_is_stable() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();
        // magic + tag + fp + payload_len(4) + 16B mock id
        assert_eq!(envelope.len(), WRAP_HEADER_LEN + 16);
        assert_eq!(&envelope[..8], b"BIOWRAP1");
        assert_eq!(envelope[8], 0);
        // payload_len is written as u32le after the fp
        assert_eq!(&envelope[41..45], &16u32.to_le_bytes());
        // Header length matches the field table in design doc §3.3
        assert_eq!(WRAP_HEADER_LEN, 8 + 1 + 32 + 4);
    }

    #[test]
    fn payload_len_mismatch_is_rejected() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(9), "enable").unwrap();

        // Truncated: the actual payload is shorter than declared
        let mut truncated = envelope.clone();
        truncated.truncate(truncated.len() - 1);
        assert_eq!(
            parse_wrap_envelope(&truncated).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // Trailing garbage: the actual payload is longer than declared
        let mut extended = envelope.clone();
        extended.push(0xAB);
        assert_eq!(
            parse_wrap_envelope(&extended).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // Declared length is zero
        let mut zero_len = envelope.clone();
        zero_len[41..45].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&zero_len).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // Declared length overflows (u32::MAX, actual 16 bytes)
        let mut overflow = envelope.clone();
        overflow[41..45].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&overflow).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );

        // An untouched envelope still unwraps (confirming the constructions above did not cause collateral damage)
        assert!(parse_wrap_envelope(&envelope).is_ok());
    }

    #[test]
    fn parse_rejects_malformed_envelopes() {
        // Too short
        assert_eq!(
            parse_wrap_envelope(&[0u8; 10]).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // Wrong magic number
        let mut bad = vec![b'X'; 8 + 1 + 32 + 4];
        assert_eq!(
            parse_wrap_envelope(&bad).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // Unknown platform tag
        bad[..8].copy_from_slice(WRAP_MAGIC);
        bad[8] = 99;
        assert_eq!(
            parse_wrap_envelope(&bad).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        // Empty payload: the header is complete but payload_len = 0
        let mut empty_payload = vec![0u8; WRAP_HEADER_LEN];
        empty_payload[..8].copy_from_slice(WRAP_MAGIC);
        empty_payload[8] = 0;
        empty_payload[41..45].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_wrap_envelope(&empty_payload).unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn wrap_rejects_non_hardware_bound_capability() {
        struct GateOnly;
        impl BiometricKeyWrapper for GateOnly {
            fn capability(&self) -> BiometricWrapCapability {
                BiometricWrapCapability::OsGateOnly
            }
            fn is_available(&self) -> bool {
                true
            }
            fn platform(&self) -> WrapPlatform {
                WrapPlatform::Linux
            }
            fn enrollment_fingerprint(&self) -> std::result::Result<[u8; 32], BiometricWrapError> {
                Ok([0; 32])
            }
            fn wrap_payload(
                &self,
                _k: &[u8; 32],
                _p: &str,
            ) -> std::result::Result<Vec<u8>, BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
            fn unwrap_payload(
                &self,
                _p: &[u8],
                _prompt: &str,
            ) -> std::result::Result<Zeroizing<[u8; 32]>, BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
            fn delete_wrap_payload(
                &self,
                _p: &[u8],
            ) -> std::result::Result<(), BiometricWrapError> {
                Err(BiometricWrapError::Unsupported)
            }
        }

        let gate = GateOnly;
        // Configuration surface: non-HardwareBound reports Unsupported explicitly (no silent downgrade)
        assert_eq!(
            wrap_master_key(&gate, &key(1), "enable").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            unwrap_master_key(&gate, &[0u8; 64], "unlock").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        // The gate tier's metadata remains readable (the front end needs to
        // display the "current tier"), it just has no hardware capability to
        // speak of
        assert_eq!(gate.capability(), BiometricWrapCapability::OsGateOnly);
        assert!(gate.is_available(), "gate-only stubs report their own axis");
        assert_eq!(gate.platform(), WrapPlatform::Linux);
        assert_eq!(gate.enrollment_fingerprint().unwrap(), [0u8; 32]);
        // Every primitive of a gate-tier wrapper is itself Unsupported — if
        // the host bypasses the capability check and calls directly, it still
        // gets no key (fail-closed down to the method level)
        assert_eq!(
            gate.wrap_payload(&key(1), "p").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            gate.unwrap_payload(&[0u8; 4], "p").unwrap_err(),
            BiometricWrapError::Unsupported
        );
        assert_eq!(
            gate.delete_wrap_payload(&[0u8; 4]).unwrap_err(),
            BiometricWrapError::Unsupported
        );
    }

    /// The envelope header's length field is a `u32`: a payload larger than
    /// `u32::MAX` cannot be encoded and must error explicitly (rather than
    /// truncate — truncation would make the unwrapping side read out-of-bounds
    /// ciphertext).
    #[test]
    fn oversized_payload_is_rejected_before_encoding() {
        assert_eq!(envelope_payload_len(0).unwrap(), 0);
        assert_eq!(envelope_payload_len(u32::MAX as usize).unwrap(), u32::MAX);
        let err = envelope_payload_len(u32::MAX as usize + 1).unwrap_err();
        assert!(
            matches!(&err, BiometricWrapError::Platform(msg) if msg.contains("exceeds envelope limit")),
            "unexpected error: {err:?}"
        );
    }

    /// Every platform tag is recognized back by `parse_wrap_envelope` (wire
    /// format round-trip: the enum value is the tag, so `from_u8`/`as_u8` must
    /// not drift).
    #[test]
    fn platform_tags_round_trip() {
        for (tag, expected) in [
            (0u8, WrapPlatform::Mock),
            (1, WrapPlatform::MacSecureEnclave),
            (2, WrapPlatform::WindowsTpm),
            (3, WrapPlatform::Linux),
        ] {
            assert_eq!(expected.as_u8(), tag);
            let mut envelope = vec![0u8; WRAP_HEADER_LEN + 4];
            envelope[..8].copy_from_slice(WRAP_MAGIC);
            envelope[8] = tag;
            envelope[41..45].copy_from_slice(&4u32.to_le_bytes());
            let (parsed, _, payload) = parse_wrap_envelope(&envelope).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(payload.len(), 4);
        }
    }

    /// The mock backend's own `unwrap_payload` must also reject payloads whose
    /// length does not match (even when the envelope header claims a correct
    /// length — the platform backend is the last line and makes no assumptions).
    #[test]
    fn mock_unwrap_rejects_wrong_length_payload() {
        let wrapper = MockKeyWrapper::default();
        assert_eq!(
            wrapper.unwrap_payload(&[0u8; 15], "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
        assert_eq!(
            wrapper.unwrap_payload(&[0u8; 17], "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    /// `delete_wrap_payload` is idempotent: a misshapen payload does not error
    /// either (disable operations must always succeed; a shape mismatch merely
    /// means "there is nothing to delete").
    #[test]
    fn mock_delete_ignores_unparsable_payload() {
        let wrapper = MockKeyWrapper::default();
        assert!(wrapper.delete_wrap_payload(&[0u8; 3]).is_ok());
        assert!(wrapper.delete_wrap_payload(&[]).is_ok());
    }

    #[test]
    fn wrap_fails_when_unavailable() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_available(false);
        assert_eq!(
            wrap_master_key(&wrapper, &key(1), "enable").unwrap_err(),
            BiometricWrapError::NotAvailable
        );
        let envelope = {
            wrapper.set_available(true);
            wrap_master_key(&wrapper, &key(1), "enable").unwrap()
        };
        wrapper.set_available(false);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::NotAvailable
        );
    }

    #[test]
    fn enrollment_rotation_invalidates_wrap() {
        let wrapper = MockKeyWrapper::default();
        let envelope = wrap_master_key(&wrapper, &key(2), "enable").unwrap();
        wrapper.rotate_enrollment();
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::EnrollmentChanged
        );
    }

    #[test]
    fn platform_tag_mismatch_is_wrap_invalid() {
        let wrapper = MockKeyWrapper::default();
        let mut envelope = wrap_master_key(&wrapper, &key(3), "enable").unwrap();
        envelope[8] = WrapPlatform::MacSecureEnclave as u8; // Impersonate output from another platform
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn corrupted_payload_is_wrap_invalid() {
        let wrapper = MockKeyWrapper::default();
        let mut envelope = wrap_master_key(&wrapper, &key(4), "enable").unwrap();
        wrapper.corrupt(&mut envelope);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    #[test]
    fn user_cancellation_propagates_from_both_directions() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_user_cancelled(true);
        assert_eq!(
            wrap_master_key(&wrapper, &key(1), "enable").unwrap_err(),
            BiometricWrapError::UserCancelled
        );
        // Cancel on the unwrap direction: first turn off the enable-direction cancel injection and obtain a valid envelope
        wrapper.set_user_cancelled(false);
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();
        wrapper.set_user_cancelled(true);
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::UserCancelled
        );
    }

    #[test]
    fn injected_hardware_failures_propagate() {
        let wrapper = MockKeyWrapper::default();
        wrapper.set_fail(MockFailTarget::Wrap, true);
        assert_matches_platform(
            &wrap_master_key(&wrapper, &key(1), "enable"),
            "mock wrap failure",
        );

        wrapper.set_fail(MockFailTarget::Wrap, false);
        let envelope = wrap_master_key(&wrapper, &key(1), "enable").unwrap();

        wrapper.set_fail(MockFailTarget::Unwrap, true);
        assert_matches_platform(
            &unwrap_master_key(&wrapper, &envelope, "unlock"),
            "mock unwrap failure",
        );
        wrapper.set_fail(MockFailTarget::Unwrap, false);

        let (.., payload) = parse_wrap_envelope(&envelope).unwrap();
        wrapper.set_fail(MockFailTarget::Delete, true);
        assert_matches_platform(&wrapper.delete_wrap_payload(payload), "mock delete failure");
        wrapper.set_fail(MockFailTarget::Delete, false);
        assert!(wrapper.delete_wrap_payload(payload).is_ok());
        // Unwrap after deletion -> WrapInvalid
        assert_eq!(
            unwrap_master_key(&wrapper, &envelope, "unlock").unwrap_err(),
            BiometricWrapError::WrapInvalid
        );
    }

    fn assert_matches_platform(
        result: &std::result::Result<impl std::fmt::Debug, BiometricWrapError>,
        needle: &str,
    ) {
        match result {
            Err(BiometricWrapError::Platform(msg)) => assert!(msg.contains(needle)),
            other => panic!("expected Platform error containing {needle}, got {other:?}"),
        }
    }

    #[test]
    fn error_display_and_persona_conversion() {
        // Every variant needs human-readable text (errors surface directly in
        // front-end prompts), and all of them map to AuthenticationFailed
        // (service-layer signatures uniformly use crate::Result)
        for (err, needle) in [
            (BiometricWrapError::Unsupported, "not supported"),
            (BiometricWrapError::NotAvailable, "not currently available"),
            (BiometricWrapError::UserCancelled, "cancelled"),
            (BiometricWrapError::EnrollmentChanged, "enrollment changed"),
            (BiometricWrapError::WrapInvalid, "invalid or corrupted"),
            (
                BiometricWrapError::Platform("os_status=-34018".into()),
                "os_status=-34018",
            ),
        ] {
            let text = err.to_string();
            assert!(
                text.contains(needle),
                "{err:?} should mention {needle:?}, got {text:?}"
            );
            let persona = err.to_persona_error();
            assert!(persona.to_string().contains("Authentication failed"));
        }
    }

    /// Assertion helpers like `assert_matches_platform` need asserting too:
    /// feeding them a non-Platform error must panic rather than pass silently.
    #[test]
    #[should_panic(expected = "expected Platform error")]
    fn assert_matches_platform_rejects_other_variants() {
        assert_matches_platform(&Err::<(), _>(BiometricWrapError::WrapInvalid), "boom");
    }
}
