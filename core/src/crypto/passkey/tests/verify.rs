use super::*;

#[test]
fn rejects_client_data_without_challenge() {
    let cd = br#"{"type":"webauthn.create","origin":"https://example.com"}"#;
    let err = register_passkey("example.com", "https://example.com", cd, false)
        .expect_err("clientDataJSON without challenge must be rejected");
    assert!(err.to_string().contains("missing challenge"));
}

#[test]
fn verify_rejects_tampered_authenticator_data() {
    let rp = "example.com";
    let reg = register_passkey(
        rp,
        "https://example.com",
        &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
        false,
    )
    .unwrap();
    let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
    let out = assert_passkey(rp, "https://example.com", &cd, &reg.signing_key, false).unwrap();

    // rpIdHash no longer matches the rp_id
    let mut bad_hash = out.authenticator_data.clone();
    bad_hash[0] ^= 0xFF;
    let err = verify_assertion(&reg.public_key_cose, rp, &cd, &bad_hash, &out.signature_der)
        .expect_err("rpIdHash mismatch must be rejected");
    assert!(err.to_string().contains("rpIdHash mismatch"));

    // user presence flag cleared
    let mut no_up = out.authenticator_data.clone();
    no_up[32] &= !FLAG_UP;
    let err = verify_assertion(&reg.public_key_cose, rp, &cd, &no_up, &out.signature_der)
        .expect_err("cleared UP flag must be rejected");
    assert!(err.to_string().contains("user presence flag not set"));
}

// ============ RP-side registration verification (verify_attestation) ============

fn reencode_attestation(fmt: &str, auth_data: Vec<u8>) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
        (Value::Text("attStmt".to_string()), Value::Map(Vec::new())),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
    ]);
    let mut buf = Vec::new();
    coset::cbor::ser::into_writer(&map, &mut buf).unwrap();
    buf
}

fn attestation_auth_data(att: &[u8]) -> Vec<u8> {
    let value: Value = coset::cbor::de::from_reader(att).unwrap();
    let Value::Map(entries) = value else {
        panic!("map expected")
    };
    match att_map_get(&entries, "authData") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => panic!("authData expected"),
    }
}

#[test]
fn verify_attestation_accepts_none_format_registration() {
    let rp = "example.com";
    let challenge = "c2VydmVyLWlzc3VlZA";
    let cd = client_data(true, challenge, "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();

    let verified = verify_attestation(
        &reg.attestation_object,
        rp,
        "https://example.com",
        &cd,
        challenge,
    )
    .expect("issued registration must verify");
    assert_eq!(verified.public_key_cose, reg.public_key_cose);
    assert_eq!(verified.credential_id, reg.credential_id);
    assert_eq!(verified.sign_count, 0);
    assert_eq!(verified.aaguid, aaguid());
    assert!(!verified.backed_up);
}

#[test]
fn verify_attestation_rejects_challenge_mismatch() {
    let rp = "example.com";
    let cd = client_data(true, "aXNzdWVkLWNoYWxsZW5nZQ", "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
    let err = verify_attestation(
        &reg.attestation_object,
        rp,
        "https://example.com",
        &cd,
        "b3RoZXItY2hhbGxlbmdl",
    )
    .expect_err("stale/wrong challenge must be rejected");
    assert!(err.to_string().contains("issued challenge"), "{err}");
}

#[test]
fn verify_attestation_rejects_assertion_client_data() {
    let rp = "example.com";
    let challenge = "cmVnaXN0ZXI";
    let cd = client_data(true, challenge, "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
    let get_cd = client_data(false, challenge, "https://example.com");
    let err = verify_attestation(
        &reg.attestation_object,
        rp,
        "https://example.com",
        &get_cd,
        challenge,
    )
    .expect_err("webauthn.get client data must not pass registration");
    assert!(err.to_string().contains("type mismatch"), "{err}");
}

#[test]
fn verify_attestation_rejects_non_none_format() {
    let rp = "example.com";
    let challenge = "cGFja2VkLWZtdA";
    let cd = client_data(true, challenge, "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
    let packed = reencode_attestation("packed", attestation_auth_data(&reg.attestation_object));
    let err = verify_attestation(&packed, rp, "https://example.com", &cd, challenge)
        .expect_err("formats we did not request must be rejected");
    assert!(
        err.to_string().contains("unsupported attestation format"),
        "{err}"
    );
}

#[test]
fn verify_attestation_rejects_tampered_rp_id_hash() {
    let rp = "example.com";
    let challenge = "dGFtcGVyZWQtaGFzaA";
    let cd = client_data(true, challenge, "https://example.com");
    let reg = register_passkey(rp, "https://example.com", &cd, false).unwrap();
    let mut auth_data = attestation_auth_data(&reg.attestation_object);
    auth_data[0] ^= 0xFF;
    let tampered = reencode_attestation("none", auth_data);
    let err = verify_attestation(&tampered, rp, "https://example.com", &cd, challenge)
        .expect_err("forged rpIdHash must be rejected");
    assert!(err.to_string().contains("rpIdHash mismatch"), "{err}");
}

#[test]
fn assertion_signature_binds_client_data() {
    // Tampered client data must fail verification.
    let rp = "example.com";
    let reg = register_passkey(
        rp,
        "https://example.com",
        &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
        false,
    )
    .unwrap();
    let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
    let out = assert_passkey(rp, "https://example.com", &cd, &reg.signing_key, false).unwrap();

    // Untampered client data verifies...
    verify_assertion(
        &reg.public_key_cose,
        rp,
        &cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .unwrap();

    // ...tampered client data must not.
    let tampered = client_data(false, "dGFtcGVyZWQ", "https://example.com");
    assert!(verify_assertion(
        &reg.public_key_cose,
        rp,
        &tampered,
        &out.authenticator_data,
        &out.signature_der,
    )
    .is_err());
}

// ============ malformed attestation objects ============
//
// Feed hand-built CBOR through the structure checker so its defensive
// failure paths are actually exercised, not just compiled in.

fn cbor_bytes(value: &coset::cbor::value::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    coset::cbor::ser::into_writer(value, &mut buf).unwrap();
    buf
}

fn attestation_with(
    fields: Vec<(coset::cbor::value::Value, coset::cbor::value::Value)>,
) -> Vec<u8> {
    cbor_bytes(&coset::cbor::value::Value::Map(fields))
}

fn assert_panics_on_attestation(attestation: &[u8], expected: &str) {
    let rp = "example.com";
    let reg = register_passkey(
        rp,
        "https://example.com",
        &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
        false,
    )
    .unwrap();
    let broken = RegistrationOutput {
        attestation_object: attestation.to_vec(),
        ..reg
    };
    let result = std::panic::catch_unwind(move || {
        let cd = client_data(true, "cmVnaXN0ZXI", "https://example.com");
        let _ = verify_attestation_structure(rp, &broken, &cd);
    })
    .expect_err("malformed attestation must panic the checker");
    let message = result
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| result.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(message.contains(expected), "panic was: {message}");
}

#[test]
fn attestation_checker_rejects_non_map_root() {
    assert_panics_on_attestation(
        &cbor_bytes(&coset::cbor::value::Value::Text("not a map".to_string())),
        "attestation must be a map",
    );
}

#[test]
fn attestation_checker_rejects_non_text_fmt() {
    assert_panics_on_attestation(
        &attestation_with(vec![
            (
                coset::cbor::value::Value::Text("fmt".to_string()),
                coset::cbor::value::Value::Bytes(vec![1]),
            ),
            (
                coset::cbor::value::Value::Text("attStmt".to_string()),
                coset::cbor::value::Value::Map(Vec::new()),
            ),
            (
                coset::cbor::value::Value::Text("authData".to_string()),
                coset::cbor::value::Value::Bytes(vec![1]),
            ),
        ]),
        "fmt must be text",
    );
}

#[test]
fn attestation_checker_rejects_non_map_att_stmt() {
    assert_panics_on_attestation(
        &attestation_with(vec![
            (
                coset::cbor::value::Value::Text("fmt".to_string()),
                coset::cbor::value::Value::Text("none".to_string()),
            ),
            (
                coset::cbor::value::Value::Text("attStmt".to_string()),
                coset::cbor::value::Value::Text("nope".to_string()),
            ),
            (
                coset::cbor::value::Value::Text("authData".to_string()),
                coset::cbor::value::Value::Bytes(vec![1]),
            ),
        ]),
        "attStmt must be a map",
    );
}

#[test]
fn attestation_checker_rejects_non_bytes_auth_data() {
    assert_panics_on_attestation(
        &attestation_with(vec![
            (
                coset::cbor::value::Value::Text("fmt".to_string()),
                coset::cbor::value::Value::Text("none".to_string()),
            ),
            (
                coset::cbor::value::Value::Text("attStmt".to_string()),
                coset::cbor::value::Value::Map(Vec::new()),
            ),
            (
                coset::cbor::value::Value::Text("authData".to_string()),
                coset::cbor::value::Value::Text("nope".to_string()),
            ),
        ]),
        "authData must be bytes",
    );
}

fn cose_key_with_params(params: Vec<(coset::Label, coset::cbor::value::Value)>) -> Vec<u8> {
    let key = CoseKey {
        kty: coset::KeyType::Assigned(iana::KeyType::EC2),
        key_id: Vec::new(),
        alg: Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)),
        key_ops: Default::default(),
        base_iv: Vec::new(),
        params,
    };
    key.to_vec().unwrap()
}

#[test]
fn verify_assertion_rejects_cose_key_missing_coordinates() {
    let reg = register_passkey(
        "example.com",
        "https://example.com",
        &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
        false,
    )
    .unwrap();
    let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
    let out = assert_passkey(
        "example.com",
        "https://example.com",
        &cd,
        &reg.signing_key,
        false,
    )
    .unwrap();

    // Rebuild the real key to harvest a valid x coordinate.
    let real = CoseKey::from_slice(&reg.public_key_cose).unwrap();
    let x = real
        .params
        .iter()
        .find_map(|(l, v)| match (l, v) {
            (coset::Label::Int(-2), Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    let y = real
        .params
        .iter()
        .find_map(|(l, v)| match (l, v) {
            (coset::Label::Int(-3), Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        })
        .unwrap();

    // Missing y.
    let missing_y = cose_key_with_params(vec![(coset::Label::Int(-2), Value::Bytes(x.clone()))]);
    let err = verify_assertion(
        &missing_y,
        "example.com",
        &cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .expect_err("COSE key without y must be rejected");
    assert!(err.to_string().contains("missing y"));

    // Missing x.
    let missing_x = cose_key_with_params(vec![(coset::Label::Int(-3), Value::Bytes(y.clone()))]);
    let err = verify_assertion(
        &missing_x,
        "example.com",
        &cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .expect_err("COSE key without x must be rejected");
    assert!(err.to_string().contains("missing x"));

    // Coordinates that are not a valid P-256 point.
    let bad_point = cose_key_with_params(vec![
        (coset::Label::Int(-2), Value::Bytes(vec![0xFF; 32])),
        (coset::Label::Int(-3), Value::Bytes(vec![0xFF; 32])),
    ]);
    let err = verify_assertion(
        &bad_point,
        "example.com",
        &cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .expect_err("invalid P-256 point must be rejected");
    assert!(err.to_string().contains("Invalid P-256 point"));
}

#[test]
fn verify_assertion_error_paths() {
    let rp = "example.com";
    let reg = register_passkey(
        rp,
        "https://example.com",
        &client_data(true, "cmVnaXN0ZXI", "https://example.com"),
        false,
    )
    .unwrap();
    let cd = client_data(false, "Y2hhbGxlbmdl", "https://example.com");
    let out = assert_passkey(rp, "https://example.com", &cd, &reg.signing_key, false).unwrap();

    // Garbage instead of a COSE key.
    let err = verify_assertion(
        b"not a cose key",
        rp,
        &cd,
        &out.authenticator_data,
        &out.signature_der,
    )
    .expect_err("invalid COSE key must be rejected");
    assert!(err.to_string().contains("Invalid COSE key"));

    // Authenticator data shorter than the 37-byte header.
    let err = verify_assertion(
        &reg.public_key_cose,
        rp,
        &cd,
        &out.authenticator_data[..20],
        &out.signature_der,
    )
    .expect_err("truncated authenticator data must be rejected");
    assert!(err.to_string().contains("rpIdHash mismatch"));

    // Not a DER signature.
    let err = verify_assertion(
        &reg.public_key_cose,
        rp,
        &cd,
        &out.authenticator_data,
        b"not der",
    )
    .expect_err("non-DER signature must be rejected");
    assert!(err.to_string().contains("Invalid DER signature"));

    // A valid DER signature made over different bytes.
    let err = verify_assertion(
        &reg.public_key_cose,
        rp,
        &client_data(false, "dGFtcGVyZWQ", "https://example.com"),
        &out.authenticator_data,
        &out.signature_der,
    )
    .expect_err("signature over different client data must fail");
    assert!(err.to_string().contains("Assertion signature invalid"));
}
