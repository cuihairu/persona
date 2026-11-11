use super::*;
use crate::models::passkey::PasskeyItem;
use crate::{PersonaError, PersonaResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::cbor::value::Value;
use coset::iana;
use coset::{CborSerializable, CoseKey};
use sha2::{Digest, Sha256};

mod ceremony;
mod client_data;
mod fuzz;
mod options;
mod rp;
mod verify;

fn client_data(create: bool, challenge: &str, origin: &str) -> Vec<u8> {
    let t = if create {
        CLIENT_DATA_TYPE_CREATE
    } else {
        CLIENT_DATA_TYPE_GET
    };
    format!(r#"{{"type":"{t}","challenge":"{challenge}","origin":"{origin}"}}"#).into_bytes()
}

#[test]
fn registration_round_trip_self_verify() {
    let rp = "example.com";
    let cd = client_data(true, "Y2hhbGxlbmdl", "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();

    // attestation structure: fmt/attStmt/authData, flags UP|AT, signCount 0
    assert_eq!(reg.credential_id.len(), 32);
    let verify = verify_attestation_structure(rp, &reg, &cd);
    assert!(verify.is_ok(), "{verify:?}");

    // assertion + self verification
    let get_cd = client_data(false, "YW5vdGhlcg", "https://example.com");
    let out = assert_passkey(rp, "https://example.com", &get_cd, &reg.signing_key, false).unwrap();
    verify_assertion(
        &reg.public_key_cose,
        rp,
        &get_cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .unwrap();
}

fn verify_attestation_structure(
    rp: &str,
    reg: &RegistrationOutput,
    cd: &[u8],
) -> Result<(), PersonaError> {
    let cose = CoseKey::from_slice(&reg.public_key_cose)
        .map_err(|e| PersonaError::InvalidInput(format!("bad cose: {e}")))?;
    assert_eq!(
        cose.alg,
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
    );

    // decode attestation object
    let value: coset::cbor::value::Value =
        coset::cbor::de::from_reader(reg.attestation_object.as_slice())
            .map_err(|e| PersonaError::InvalidInput(format!("bad cbor: {e}")))?;
    let coset::cbor::value::Value::Map(entries) = value else {
        panic!("attestation must be a map")
    };
    let get = |k: &str| {
        entries
            .iter()
            .find_map(|(key, v)| match key {
                coset::cbor::value::Value::Text(t) if t == k => Some(v.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing key {k}"))
    };
    let coset::cbor::value::Value::Text(fmt) = get("fmt") else {
        panic!("fmt must be text")
    };
    assert_eq!(fmt, "none");
    let coset::cbor::value::Value::Map(att_stmt) = get("attStmt") else {
        panic!("attStmt must be a map")
    };
    assert!(att_stmt.is_empty());
    let coset::cbor::value::Value::Bytes(auth_data) = get("authData") else {
        panic!("authData must be bytes")
    };

    // rpIdHash, flags UP|AT, signCount 0, AAGUID, credIdLen 32
    let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    assert_eq!(&auth_data[..32], &rp_hash);
    assert_eq!(auth_data[32], FLAG_UP | FLAG_AT);
    assert_eq!(&auth_data[33..37], &[0, 0, 0, 0]);
    assert_eq!(&auth_data[37..53], &aaguid());
    assert_eq!(&auth_data[53..55], &[0, 32]);
    assert_eq!(&auth_data[55..87], &reg.credential_id[..]);
    // COSE key embedded at the tail
    assert_eq!(auth_data.len(), 87 + reg.public_key_cose.len());
    assert_eq!(&auth_data[87..], &reg.public_key_cose[..]);

    // client data echo checks still pass
    parse_client_data(cd, CLIENT_DATA_TYPE_CREATE, "https://example.com")?;
    Ok(())
}

fn es256_options(rp_id: Option<&str>, user_id: Option<&str>) -> serde_json::Value {
    let mut options = serde_json::json!({
        "user": { "id": user_id, "name": "alice@example.com", "displayName": "Alice" },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    });
    if let Some(id) = rp_id {
        options["rp"] = serde_json::json!({ "id": id, "name": "Example" });
    }
    options
}
