use super::*;

#[test]
fn rejects_origin_rp_mismatch() {
    let cd = client_data(true, "Y2hhbGxlbmdl", "https://evil.example");
    let err = register_passkey("example.com", "https://evil.example", &cd, false)
        .expect_err("must reject");
    assert!(matches!(err, PersonaError::InvalidInput(_)));
}

#[test]
fn rejects_client_data_origin_mismatch() {
    // Request origin ok, but the clientDataJSON claims a different origin.
    let cd = client_data(true, "Y2hhbGxlbmdl", "https://evil.example");
    let err = register_passkey("example.com", "https://example.com", &cd, false)
        .expect_err("must reject");
    assert!(err.to_string().contains("does not match request origin"));
}

#[test]
fn rejects_wrong_ceremony_type() {
    let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
    let err = register_passkey("example.com", "https://example.com", &cd, false)
        .expect_err("must reject");
    assert!(err.to_string().contains("type mismatch"));
}

#[test]
fn rejects_subdomain_spoof() {
    assert!(validate_origin_matches_rp_id("https://evil-github.com", "github.com").is_err());
    assert!(validate_origin_matches_rp_id("https://evilstill.github.com", "github.com").is_ok());
}

#[test]
fn rejects_public_suffix_rp_id() {
    assert!(validate_rp_id("com").is_err());
    assert!(validate_rp_id("github.com").is_ok());
    assert!(validate_rp_id("localhost").is_ok());
}

// ============ additional coverage: helpers, UV flag, error paths ========

#[test]
fn local_client_data_helpers_produce_parseable_json() {
    let cd = local_client_data(CLIENT_DATA_TYPE_CREATE, "https://example.com").unwrap();
    let parsed = parse_client_data(&cd, CLIENT_DATA_TYPE_CREATE, "https://example.com")
        .expect("locally built client data must parse");
    // The challenge is random 32 bytes of base64url (43 chars).
    assert_eq!(URL_SAFE_NO_PAD.decode(&parsed.challenge).unwrap().len(), 32);

    let self_test = self_test_client_data("https://example.com").unwrap();
    parse_client_data(&self_test, CLIENT_DATA_TYPE_GET, "https://example.com")
        .expect("self-test client data must use the GET ceremony type");
}

#[test]
fn aaguid_and_random_bytes_are_distinct() {
    // The AAGUID is a fixed 16-byte identifier for the software
    // authenticator.
    assert_eq!(aaguid().len(), 16);
    assert_eq!(aaguid(), PasskeyItem::aaguid());

    let a = random_bytes32();
    let b = random_bytes32();
    assert_ne!(a, b);
}

#[test]
fn user_verification_flag_is_carried_into_authenticator_data() {
    let rp = "example.com";
    let origin = "https://example.com";
    let cd_create = client_data(true, "dXZmbGFn", origin);
    let reg = register_passkey(rp, origin, &cd_create, true).unwrap();

    // Registration authData flags must include UP | AT | UV.
    let value: coset::cbor::value::Value =
        coset::cbor::de::from_reader(reg.attestation_object.as_slice()).unwrap();
    let coset::cbor::value::Value::Map(entries) = value else {
        panic!("attestation must be a map")
    };
    let auth_data = entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (coset::cbor::value::Value::Text(t), coset::cbor::value::Value::Bytes(b))
                if t == "authData" =>
            {
                Some(b.clone())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(auth_data[32], FLAG_UP | FLAG_AT | FLAG_UV);

    // Assertion with UV also sets the flag and still verifies.
    let cd_get = client_data(false, "dXZmbGFn", origin);
    let out = assert_passkey(rp, origin, &cd_get, &reg.signing_key, true).unwrap();
    assert_eq!(out.authenticator_data[32], FLAG_UP | FLAG_UV);
    verify_assertion(
        &reg.public_key_cose,
        rp,
        &cd_get,
        &out.authenticator_data,
        &out.signature_der,
    )
    .unwrap();
}
