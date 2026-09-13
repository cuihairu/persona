//! RP-side regression for Persona's software authenticator.
//!
//! `webauthn-rs` acts as a real relying party and verifies our registration
//! (attestation) and authentication (assertion) outputs end to end — the same
//! philosophy as the wallet's official BIP/EIP test vectors: our
//! authenticator-side implementation is small, another audited implementation
//! is the judge.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use persona_core::crypto::passkey::{assert_passkey, register_passkey};
use url::Url;
use webauthn_rs::prelude::*;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

/// `Base64UrlSafeData` serializes as a base64url string — use that to pull
/// the challenge out of the RP's request.
fn challenge_string(challenge: &Base64UrlSafeData) -> String {
    serde_json::to_value(challenge)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn client_data_json(ceremony: &str, challenge_b64: &str) -> Vec<u8> {
    format!(r#"{{"type":"{ceremony}","challenge":"{challenge_b64}","origin":"{ORIGIN}"}}"#)
        .into_bytes()
}

#[test]
fn full_passkey_lifecycle_against_webauthn_rs() {
    let rp_origin = Url::parse(ORIGIN).unwrap();
    let webauthn = WebauthnBuilder::new(RP_ID, &rp_origin)
        .unwrap()
        .build()
        .unwrap();

    // ---- registration: RP starts, we produce an attestation ----
    let user_uuid = uuid::Uuid::new_v4();
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_uuid, "alice@example.com", "Alice", None)
        .unwrap();
    let challenge = challenge_string(&ccr.public_key.challenge);
    let client_data = client_data_json("webauthn.create", &challenge);

    let reg = register_passkey(RP_ID, ORIGIN, &client_data, true).unwrap();

    let register_response = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode(&reg.credential_id),
        "rawId": URL_SAFE_NO_PAD.encode(&reg.credential_id),
        "type": "public-key",
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode(&reg.attestation_object),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    });
    let register_credential: RegisterPublicKeyCredential =
        serde_json::from_value(register_response).unwrap();
    let passkey = webauthn
        .finish_passkey_registration(&register_credential, &reg_state)
        .unwrap();

    // ---- authentication: RP starts, we produce an assertion ----
    let (rcr, auth_state) = webauthn.start_passkey_authentication(&[passkey]).unwrap();
    let auth_challenge = challenge_string(&rcr.public_key.challenge);
    let get_client_data = client_data_json("webauthn.get", &auth_challenge);

    let assertion =
        assert_passkey(RP_ID, ORIGIN, &get_client_data, &reg.signing_key, true).unwrap();

    let auth_response = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode(&reg.credential_id),
        "rawId": URL_SAFE_NO_PAD.encode(&reg.credential_id),
        "type": "public-key",
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(&get_client_data),
            "signature": URL_SAFE_NO_PAD.encode(&assertion.signature_der),
            "userHandle": URL_SAFE_NO_PAD.encode(user_uuid.as_bytes()),
        },
        "clientExtensionResults": {},
    });
    let public_key_credential: PublicKeyCredential = serde_json::from_value(auth_response).unwrap();
    let result = webauthn
        .finish_passkey_authentication(&public_key_credential, &auth_state)
        .unwrap();

    assert!(
        result.user_verified(),
        "RP must observe user verification (UV flag)"
    );
}

#[test]
fn webauthn_rs_rejects_wrong_origin_attestation() {
    let rp_origin = Url::parse(ORIGIN).unwrap();
    let webauthn = WebauthnBuilder::new(RP_ID, &rp_origin)
        .unwrap()
        .build()
        .unwrap();

    let user_uuid = uuid::Uuid::new_v4();
    let (ccr, _reg_state) = webauthn
        .start_passkey_registration(user_uuid, "alice@example.com", "Alice", None)
        .unwrap();
    let challenge = challenge_string(&ccr.public_key.challenge);

    // client data claims a different origin than the RP's registered one
    let evil_client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://evil.example"}}"#
    );
    assert!(
        register_passkey(RP_ID, ORIGIN, evil_client_data.as_bytes(), true).is_err(),
        "authenticator must refuse mismatched client data origin"
    );

    // and a mismatched rp_id is refused just as well
    assert!(
        register_passkey("evil.example", ORIGIN, evil_client_data.as_bytes(), true).is_err(),
        "authenticator must refuse mismatched rp_id"
    );
}
