//! Host-persisted records of a device identity (E2EE_SYNC_DESIGN DR-1/DR-3).
//!
//! The host stores the device private key in the OS keyring (service
//! `persona-device`, desktop) or in a 0600 file (headless `--device-key-file`,
//! CLI)——core does not depend on keyring and only defines the record format:
//! a single JSON document with the private key b64-encoded. Desktop and CLI
//! share the same format; where the record text is stored and how it is
//! protected are up to the host (per the core documentation stance:
//! persistence is the host's responsibility).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::keys::DeviceKeyPair;
use crate::{PersonaError, Result};

/// The identity of a device after it joins sync: the server-assigned
/// `device_id`, the registered name, and the keypair. The private key bytes
/// live only inside [`DeviceKeyPair`] (zeroed on Drop); this struct keeps no
/// additional copies.
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub device_name: String,
    pub key_pair: DeviceKeyPair,
}

impl DeviceIdentity {
    /// Generate a fresh device identity (random X25519 keypair; device_id is
    /// assigned by the server at registration time, then filled back in with
    /// [`Self::with_device_id`]).
    pub fn generate(device_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            device_id: Uuid::nil(),
            device_name: device_name.into(),
            key_pair: DeviceKeyPair::generate()?,
        })
    }

    /// Fill back in the server-assigned device_id after successful registration.
    pub fn with_device_id(mut self, device_id: Uuid) -> Self {
        self.device_id = device_id;
        self
    }

    /// Storage text (one JSON: the b64 private key). This is exactly the
    /// string the host writes to the keyring/file——the format is stable and
    /// interchangeable across platforms (desktop/CLI).
    pub fn to_stored_json(&self) -> String {
        serde_json::json!({
            "device_id": self.device_id.to_string(),
            "device_name": self.device_name,
            "secret_key": B64.encode(self.key_pair.secret_bytes()),
        })
        .to_string()
    }

    /// Restore from storage text. If any part fails to parse (bad JSON / bad
    /// UUID / bad b64 / wrong length) the result is Err——fail-closed: on a
    /// corrupt record it is better to have the user re-join than to guess or
    /// run while sick.
    pub fn from_stored_json(raw: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|_| PersonaError::InvalidInput("malformed device record JSON".to_string()))?;
        let device_id = Uuid::parse_str(
            value
                .get("device_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PersonaError::InvalidInput("device record missing device_id".to_string())
                })?,
        )
        .map_err(|_| PersonaError::InvalidInput("malformed device_id in record".to_string()))?;
        let device_name = value
            .get("device_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PersonaError::InvalidInput("device record missing device_name".to_string())
            })?
            .to_string();
        let secret_b64 = value
            .get("secret_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PersonaError::InvalidInput("device record missing secret_key".to_string())
            })?;
        let secret: [u8; 32] = B64
            .decode(secret_b64)
            .map_err(|_| PersonaError::InvalidInput("malformed secret_key base64".to_string()))?
            .try_into()
            .map_err(|_| PersonaError::InvalidInput("secret_key must be 32 bytes".to_string()))?;
        Ok(Self {
            device_id,
            device_name,
            key_pair: DeviceKeyPair::from_secret(secret),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_json_round_trips_identity() {
        let identity = DeviceIdentity::generate("laptop")
            .unwrap()
            .with_device_id(Uuid::new_v4());
        let restored = DeviceIdentity::from_stored_json(&identity.to_stored_json()).unwrap();
        assert_eq!(restored.device_id, identity.device_id);
        assert_eq!(restored.device_name, "laptop");
        assert_eq!(
            restored.key_pair.public_bytes(),
            identity.key_pair.public_bytes()
        );
    }

    #[test]
    fn generate_produces_distinct_keypairs() {
        let a = DeviceIdentity::generate("a").unwrap();
        let b = DeviceIdentity::generate("b").unwrap();
        assert_ne!(a.key_pair.public_bytes(), b.key_pair.public_bytes());
    }

    #[test]
    fn stored_json_rejects_malformed_records() {
        assert!(DeviceIdentity::from_stored_json("not json").is_err());
        // Missing field
        assert!(DeviceIdentity::from_stored_json("{\"device_id\":\"x\"}").is_err());
        // Bad UUID
        assert!(DeviceIdentity::from_stored_json(
            "{\"device_id\":\"nope\",\"device_name\":\"d\",\"secret_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"
        )
        .is_err());
        // Wrong private key length (31B / 33B)
        for bad_len in [&[0u8; 31][..], &[0u8; 33][..]] {
            let record = serde_json::json!({
                "device_id": "00000000-0000-0000-0000-000000000000",
                "device_name": "d",
                "secret_key": B64.encode(bad_len),
            });
            assert!(DeviceIdentity::from_stored_json(&record.to_string()).is_err());
        }
    }

    /// Each of the three fields missing entirely (not a bad value) gets its
    /// own dedicated error; fail-closed, no guessing.
    #[test]
    fn stored_json_rejects_missing_fields_individually() {
        let id = "00000000-0000-0000-0000-000000000000";
        let must_reject = |raw: String, needle: &str| match DeviceIdentity::from_stored_json(&raw) {
            Err(e) => assert!(e.to_string().contains(needle), "{e}"),
            Ok(_) => panic!("record must be rejected: missing {needle}"),
        };
        must_reject("{}".to_string(), "missing device_id");
        must_reject(format!(r#"{{"device_id":"{id}"}}"#), "missing device_name");
        must_reject(
            format!(r#"{{"device_id":"{id}","device_name":"d"}}"#),
            "missing secret_key",
        );
    }
}
