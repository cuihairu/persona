//! Structured custom fields (1Password parity).
//!
//! 1Password lets an item carry typed custom fields (text / concealed /
//! date, optionally grouped into sections). Persona stores them as a
//! single sealed blob inside the credential's `metadata` map under
//! [`CUSTOM_FIELDS_METADATA_KEY`]: the field list is serialized to JSON
//! and encrypted with the credential's **per-item key**, so secrets
//! (concealed values, labels alike) are ciphertext at rest and the blob
//! rides the existing sync snapshot (metadata is part of
//! `SyncItemSnapshot`) and item history for free.
//!
//! The credential payload (`CredentialData`) is deliberately untouched:
//! bincode is not self-describing, so appending fields to any variant
//! breaks old ciphertexts (see the GameToken legacy-tolerant reader for
//! what that costs). The metadata map is an additive, self-contained
//! substrate instead.

use crate::crypto::encryption::EncryptionService;
use crate::models::credential::{CustomField, CustomFieldType};
use crate::{PersonaError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

/// `credential.metadata` key holding the sealed custom-fields blob.
pub const CUSTOM_FIELDS_METADATA_KEY: &str = "persona:custom_fields";

/// A new field with a fresh id.
pub fn new_custom_field(
    label: impl Into<String>,
    value: impl Into<String>,
    field_type: CustomFieldType,
) -> CustomField {
    CustomField {
        id: Uuid::new_v4().to_string(),
        label: label.into(),
        value: value.into(),
        field_type,
        section: None,
    }
}

/// Seal the field list under the credential's per-item key and encode the
/// envelope as a base64 string for the metadata map.
pub fn encode_custom_fields(fields: &[CustomField], item_key: &[u8; 32]) -> Result<String> {
    let plaintext = serde_json::to_vec(fields)
        .map_err(|e| PersonaError::Validation(format!("custom fields serialize: {e}")))?;
    let sealed = EncryptionService::new(item_key)
        .encrypt(&plaintext)
        .map_err(|e| PersonaError::CryptographicError(format!("custom fields seal: {e}")))?;
    Ok(B64.encode(sealed))
}

/// Open the sealed blob. Ciphertext tampering or a stale key fails closed.
pub fn decode_custom_fields(blob: &str, item_key: &[u8; 32]) -> Result<Vec<CustomField>> {
    let sealed = B64
        .decode(blob)
        .map_err(|e| PersonaError::Validation(format!("custom fields blob decode: {e}")))?;
    let plaintext = EncryptionService::new(item_key)
        .decrypt(&sealed)
        .map_err(|_| {
            PersonaError::CryptographicError(
                "failed to open custom fields blob (wrong item key or tampered ciphertext)"
                    .to_string(),
            )
        })?;
    Ok(serde_json::from_slice(&plaintext)
        .map_err(|e| PersonaError::Validation(format!("custom fields parse: {e}")))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(label: &str, value: &str, t: CustomFieldType) -> CustomField {
        new_custom_field(label, value, t)
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let fields = vec![
            field("Server", "db.internal:5432", CustomFieldType::Text),
            field("Recovery code", "abcd-efgh", CustomFieldType::Concealed),
            field("Expires", "2027-01-31", CustomFieldType::Date),
        ];
        let key = [7u8; 32];
        let blob = encode_custom_fields(&fields, &key).unwrap();
        let decoded = decode_custom_fields(&blob, &key).unwrap();
        assert_eq!(decoded, fields);
    }

    #[test]
    fn blob_is_ciphertext_not_plaintext() {
        let fields = vec![field("Secret", "hunter2", CustomFieldType::Concealed)];
        let blob = encode_custom_fields(&fields, &[9u8; 32]).unwrap();
        assert!(!blob.contains("hunter2"));
        assert!(!blob.contains("Secret"));
        // metadata value is plain base64 (no JSON braces)
        assert!(!blob.contains('{'));
    }

    #[test]
    fn wrong_item_key_fails_closed() {
        let fields = vec![field("K", "V", CustomFieldType::Text)];
        let blob = encode_custom_fields(&fields, &[1u8; 32]).unwrap();
        assert!(decode_custom_fields(&blob, &[2u8; 32]).is_err());
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let fields = vec![field("K", "V", CustomFieldType::Text)];
        let mut blob = encode_custom_fields(&fields, &[1u8; 32]).unwrap();
        // flip a byte inside the base64 payload
        let mut raw = B64.decode(&blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        blob = B64.encode(&raw);
        assert!(decode_custom_fields(&blob, &[1u8; 32]).is_err());
    }

    #[test]
    fn garbage_blob_is_a_serialization_error_not_panic() {
        assert!(decode_custom_fields("not-base64!!", &[1u8; 32]).is_err());
    }

    #[test]
    fn empty_list_roundtrips() {
        let key = [3u8; 32];
        let blob = encode_custom_fields(&[], &key).unwrap();
        assert!(decode_custom_fields(&blob, &key).unwrap().is_empty());
    }

    #[test]
    fn new_field_has_unique_ids() {
        let a = new_custom_field("a", "b", CustomFieldType::Text);
        let b = new_custom_field("a", "b", CustomFieldType::Text);
        assert_ne!(a.id, b.id);
        assert_eq!(a.section, None);
    }

    #[test]
    fn field_type_serde_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&CustomFieldType::Concealed).unwrap(),
            "\"concealed\""
        );
    }
}
