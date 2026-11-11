use crate::{PersonaError, PersonaResult};
use coset::cbor::value::Value;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::client_data::parse_client_data;
use super::rp::{validate_origin_matches_rp_id, validate_rp_id};
use super::seed::random_bytes32;
use super::CLIENT_DATA_TYPE_CREATE;
use super::{FLAG_AT, FLAG_BS, FLAG_UP};

/// Generate a fresh ES256 signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("failed to generate random bytes");
    let key = SigningKey::from_slice(&bytes).expect("32 random bytes are a valid P-256 scalar");
    bytes.fill(0);
    key
}

/// Encode a P-256 public key as a WebAuthn COSE_Key (EC2 + P-256 + ES256).
pub fn cose_public_key(verifying_key: &VerifyingKey) -> PersonaResult<Vec<u8>> {
    let point = verifying_key.to_sec1_point(false);
    let x = point
        .x()
        .ok_or_else(|| PersonaError::CryptographicError("Missing x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| PersonaError::CryptographicError("Missing y coordinate".to_string()))?;

    let key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        x.as_slice().to_vec(),
        y.as_slice().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build();

    key.to_vec()
        .map_err(|e| PersonaError::CryptographicError(format!("COSE encoding failed: {e}")))
}

/// Self-check helper (no RP involved): reconstruct the verifying key from a
/// COSE public key and verify an assertion the same way an RP would.
pub fn verify_assertion(
    public_key_cose: &[u8],
    rp_id: &str,
    client_data_json: &[u8],
    authenticator_data_bytes: &[u8],
    signature_der: &[u8],
) -> PersonaResult<()> {
    let verifying_key = verifying_key_from_cose(public_key_cose)?;

    // rpIdHash prefix must match, user presence must be set.
    let rp_id = validate_rp_id(rp_id)?;
    let expected_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if authenticator_data_bytes.len() < 37 || authenticator_data_bytes[..32] != expected_hash {
        return Err(PersonaError::InvalidInput(
            "authenticator data rpIdHash mismatch".to_string(),
        ));
    }
    if authenticator_data_bytes[32] & FLAG_UP == 0 {
        return Err(PersonaError::InvalidInput(
            "user presence flag not set".to_string(),
        ));
    }

    let mut message = Vec::with_capacity(authenticator_data_bytes.len() + 32);
    message.extend_from_slice(authenticator_data_bytes);
    message.extend_from_slice(Sha256::digest(client_data_json).as_slice());

    let signature = Signature::from_der(signature_der)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid DER signature: {e}")))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| PersonaError::CryptographicError("Assertion signature invalid".to_string()))
}

/// Verified RP-side registration output: everything an RP persists for a
/// newly attested credential.
#[derive(Debug)]
pub struct VerifiedRegistration {
    /// COSE_Key (EC2/P-256/ES256) to persist as the credential's public key.
    pub public_key_cose: Vec<u8>,
    /// Credential id as attested in the authenticator data.
    pub credential_id: Vec<u8>,
    /// Authenticator signature counter (clone detection at assertion time).
    pub sign_count: u32,
    /// AAGUID from the attested credential data.
    pub aaguid: [u8; 16],
    /// BS flag: the credential currently backs up to a cloud sync service.
    pub backed_up: bool,
}

/// RP-side registration verification: validate the client data against the
/// origin/rp_id and the issued challenge, then parse the `none`-format
/// attestation object — checking rpIdHash and flags, and extracting the
/// attested credential (COSE key, credential id, AAGUID, sign count).
///
/// Only `fmt: "none"` is accepted: the creation options issued by this
/// project request `attestation: "none"`, and other formats carry
/// authenticator attestation statements this verifier does not implement.
pub fn verify_attestation(
    attestation_object: &[u8],
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    expected_challenge: &str,
) -> PersonaResult<VerifiedRegistration> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    let parsed = parse_client_data(client_data_json, CLIENT_DATA_TYPE_CREATE, origin)?;
    if parsed.challenge != expected_challenge {
        return Err(PersonaError::InvalidInput(
            "clientDataJSON challenge does not match the issued challenge".to_string(),
        ));
    }
    let rp_id = validate_rp_id(rp_id)?;

    let value: coset::cbor::value::Value = coset::cbor::de::from_reader(attestation_object)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid attestation object: {e}")))?;
    let coset::cbor::value::Value::Map(entries) = value else {
        return Err(PersonaError::InvalidInput(
            "attestation object must be a CBOR map".to_string(),
        ));
    };

    let fmt = match att_map_get(&entries, "fmt") {
        Some(coset::cbor::value::Value::Text(t)) => t.as_str(),
        _ => {
            return Err(PersonaError::InvalidInput(
                "attestation object missing fmt".to_string(),
            ))
        }
    };
    if fmt != "none" {
        return Err(PersonaError::InvalidInput(format!(
            "unsupported attestation format: {fmt}"
        )));
    }
    match att_map_get(&entries, "attStmt") {
        Some(coset::cbor::value::Value::Map(m)) if m.is_empty() => {}
        _ => {
            return Err(PersonaError::InvalidInput(
                "attStmt must be an empty map for fmt \"none\"".to_string(),
            ))
        }
    }
    let auth_data = match att_map_get(&entries, "authData") {
        Some(coset::cbor::value::Value::Bytes(b)) => b,
        _ => {
            return Err(PersonaError::InvalidInput(
                "attestation object missing authData".to_string(),
            ))
        }
    };

    // rpIdHash ‖ flags ‖ signCount ‖ attested credential data (AT set).
    if auth_data.len() < 55 {
        return Err(PersonaError::InvalidInput(
            "authenticator data too short".to_string(),
        ));
    }
    let expected_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth_data[..32] != expected_hash {
        return Err(PersonaError::InvalidInput(
            "authenticator data rpIdHash mismatch".to_string(),
        ));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err(PersonaError::InvalidInput(
            "user presence flag not set".to_string(),
        ));
    }
    if flags & FLAG_AT == 0 {
        return Err(PersonaError::InvalidInput(
            "attested credential data missing".to_string(),
        ));
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let aaguid: [u8; 16] = auth_data[37..53]
        .try_into()
        .expect("slice length checked above");
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len == 0 || cred_len > 1023 {
        return Err(PersonaError::InvalidInput(
            "invalid credential id length".to_string(),
        ));
    }
    let cred_end = 55 + cred_len;
    if auth_data.len() <= cred_end {
        return Err(PersonaError::InvalidInput(
            "attested credential data truncated".to_string(),
        ));
    }
    let credential_id = auth_data[55..cred_end].to_vec();
    let cose = &auth_data[cred_end..];

    // Structural checks on the attested key: EC2/P-256/ES256 only, and the
    // point must decode (verifying_key_from_cose rejects off-curve points).
    let key = CoseKey::from_slice(cose)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid COSE key: {e}")))?;
    if key.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
        return Err(PersonaError::InvalidInput(
            "attested key must be EC2".to_string(),
        ));
    }
    if key.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) {
        return Err(PersonaError::InvalidInput(
            "attested key must be ES256".to_string(),
        ));
    }
    // Curve is pinned by the decode below: P-256 x/y are 32-byte coordinates,
    // so a point on any other curve fails Sec1 decoding.
    verifying_key_from_cose(cose)?;

    Ok(VerifiedRegistration {
        public_key_cose: cose.to_vec(),
        credential_id,
        sign_count,
        aaguid,
        backed_up: flags & FLAG_BS != 0,
    })
}

/// Look up a text key in a CBOR map.
pub(super) fn att_map_get<'a>(
    entries: &'a [(coset::cbor::value::Value, coset::cbor::value::Value)],
    key: &str,
) -> Option<&'a coset::cbor::value::Value> {
    entries.iter().find_map(|(k, v)| match k {
        coset::cbor::value::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

/// Reconstruct a `VerifyingKey` from a Persona-produced COSE_Key (EC2/P-256).
fn verifying_key_from_cose(cose: &[u8]) -> PersonaResult<VerifyingKey> {
    let key = CoseKey::from_slice(cose)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid COSE key: {e}")))?;

    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    for (label, value) in &key.params {
        match (label, value) {
            (coset::Label::Int(-2), Value::Bytes(b)) => x = Some(b),
            (coset::Label::Int(-3), Value::Bytes(b)) => y = Some(b),
            _ => {}
        }
    }
    let x = x.ok_or_else(|| PersonaError::InvalidInput("COSE key missing x".to_string()))?;
    let y = y.ok_or_else(|| PersonaError::InvalidInput("COSE key missing y".to_string()))?;

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| PersonaError::InvalidInput(format!("Invalid P-256 point: {e}")))
}

/// 32 random bytes for credential IDs (software authenticator convention).
pub(super) fn random_credential_id() -> Vec<u8> {
    random_bytes32().to_vec()
}
