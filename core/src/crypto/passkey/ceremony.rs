use crate::{PersonaError, PersonaResult};
use coset::cbor::value::Value;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

use super::client_data::parse_client_data;
use super::rp::{validate_origin_matches_rp_id, validate_rp_id};
use super::seed::aaguid;
use super::verify::{cose_public_key, generate_signing_key, random_credential_id};
use super::{CLIENT_DATA_TYPE_CREATE, CLIENT_DATA_TYPE_GET, FLAG_AT, FLAG_UP, FLAG_UV};

/// Successful registration: everything an RP needs plus the key to persist.
#[derive(Debug)]
pub struct RegistrationOutput {
    /// Newly generated private key (caller encrypts and stores it)
    pub signing_key: SigningKey,
    /// Random 32-byte credential ID
    pub credential_id: Vec<u8>,
    /// Public key in COSE_Key form (goes into attested credential data)
    pub public_key_cose: Vec<u8>,
    /// Complete `none`-format attestation object
    pub attestation_object: Vec<u8>,
}

/// Successful assertion: the two byte strings an RP verifies.
#[derive(Debug)]
pub struct AssertionOutput {
    /// authenticator data (rpIdHash ‖ flags ‖ signCount)
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ES256 signature over `authenticator_data ‖ SHA256(clientDataJSON)`
    pub signature_der: Vec<u8>,
}

/// authenticator data: `rpIdHash ‖ flags ‖ signCount` plus, for registration,
/// the attested credential data (AAGUID ‖ credIdLen ‖ credId ‖ COSE key).
fn authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_credential: Option<(&[u8], &[u8])>,
) -> PersonaResult<Vec<u8>> {
    let rp_id = validate_rp_id(rp_id)?;
    let mut data = Vec::with_capacity(37 + attested_credential.map_or(0, |(id, _)| 18 + id.len()));
    data.extend_from_slice(Sha256::digest(rp_id.as_bytes()).as_slice());
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested_credential {
        data.extend_from_slice(&aaguid());
        let len = u16::try_from(credential_id.len())
            .map_err(|_| PersonaError::InvalidInput("credential_id too long".to_string()))?;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose_key);
    }
    Ok(data)
}

/// `none`-format attestation object: `{fmt: "none", attStmt: {}, authData}`.
fn attestation_object(auth_data: &[u8]) -> PersonaResult<Vec<u8>> {
    // Canonical CTAP2 ordering: "fmt" < "attStmt" < "authData".
    let map = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    coset::cbor::ser::into_writer(&map, &mut buf)
        .map_err(|e| PersonaError::CryptographicError(format!("CBOR encoding failed: {e}")))?;
    Ok(buf)
}

/// Run a registration ceremony: validates the client data against the origin
/// and rp_id, generates a fresh key pair and returns the attestation plus the
/// key material the caller must persist (encrypted).
pub fn register_passkey(
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    user_verification: bool,
) -> PersonaResult<RegistrationOutput> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    parse_client_data(client_data_json, CLIENT_DATA_TYPE_CREATE, origin)?;
    let rp_id = validate_rp_id(rp_id)?;

    let signing_key = generate_signing_key();
    let public_key_cose = cose_public_key(signing_key.verifying_key())?;
    let credential_id = random_credential_id();

    let mut flags = FLAG_UP | FLAG_AT;
    if user_verification {
        flags |= FLAG_UV;
    }
    let auth_data = authenticator_data(
        &rp_id,
        flags,
        0,
        Some((&credential_id, public_key_cose.as_slice())),
    )?;
    let attestation_object = attestation_object(&auth_data)?;

    Ok(RegistrationOutput {
        signing_key,
        credential_id,
        public_key_cose,
        attestation_object,
    })
}

/// Run an assertion ceremony: signs `authenticator_data ‖ SHA256(clientDataJSON)`
/// with the stored key after re-validating origin ↔ rp_id.
pub fn assert_passkey(
    rp_id: &str,
    origin: &str,
    client_data_json: &[u8],
    signing_key: &SigningKey,
    user_verification: bool,
) -> PersonaResult<AssertionOutput> {
    validate_origin_matches_rp_id(origin, rp_id)?;
    parse_client_data(client_data_json, CLIENT_DATA_TYPE_GET, origin)?;
    let rp_id = validate_rp_id(rp_id)?;

    let mut flags = FLAG_UP;
    if user_verification {
        flags |= FLAG_UV;
    }
    let auth_data = authenticator_data(&rp_id, flags, 0, None)?;

    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(Sha256::digest(client_data_json).as_slice());
    let signature: Signature = signing_key.sign(&message);

    Ok(AssertionOutput {
        authenticator_data: auth_data,
        signature_der: signature.to_der().as_bytes().to_vec(),
    })
}
