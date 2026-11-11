use super::*;

// ============ passkey_create options parsing (bridge protocol v2) ============

#[test]
fn parse_options_defaults_rp_id_to_origin_host() {
    // rp.id omitted → the origin's effective host is used (WebAuthn §5.4).
    let parsed =
        parse_creation_options(&es256_options(None, Some("dXNlcg")), "https://example.com")
            .unwrap();
    assert_eq!(parsed.rp_id, "example.com");
    assert_eq!(parsed.user_handle, b"user");
    assert_eq!(parsed.user_name.as_deref(), Some("alice@example.com"));
    assert_eq!(parsed.user_display_name.as_deref(), Some("Alice"));
    assert_eq!(parsed.rp_name.as_deref(), None);
}

#[test]
fn parse_options_rejects_missing_or_invalid_user_id() {
    // user present but id missing / not a string
    let err = parse_creation_options(
        &es256_options(Some("example.com"), None),
        "https://example.com",
    )
    .expect_err("missing user.id must be rejected");
    assert!(err
        .to_string()
        .contains("user.id must be a base64url string"));

    // id decodes to zero bytes
    let err = parse_creation_options(
        &es256_options(Some("example.com"), Some("")),
        "https://example.com",
    )
    .expect_err("empty user.id must be rejected");
    assert!(err.to_string().contains("1..=64 bytes"));

    // id larger than 64 bytes
    let big = URL_SAFE_NO_PAD.encode(vec![0u8; 65]);
    let err = parse_creation_options(
        &es256_options(Some("example.com"), Some(&big)),
        "https://example.com",
    )
    .expect_err("oversized user.id must be rejected");
    assert!(err.to_string().contains("1..=64 bytes"));
}

#[test]
fn parse_options_rejects_invalid_rp_id_and_origin() {
    // rp.id is passed through unvalidated here; registration re-checks it
    // via validate_rp_id (tested below). What IS rejected at parse time:
    // an origin whose authority is empty when no rp.id can be derived.
    let err = parse_creation_options(&es256_options(None, Some("dQ")), "https://")
        .expect_err("hostless origin must be rejected");
    assert!(err.to_string().contains("Origin has no host"));

    // IPv6 origin: the host extraction strips brackets and port.
    let parsed = parse_creation_options(&es256_options(None, Some("dQ")), "https://[::1]:8443")
        .expect("IPv6 host must extract");
    assert_eq!(parsed.rp_id, "::1");
}

#[test]
fn parse_creation_options_rejects_missing_or_wrong_alg_params() {
    let origin = "https://example.com";

    // pubKeyCredParams missing entirely.
    let options = serde_json::json!({ "user": { "id": "dXNlcg" } });
    let err = parse_creation_options(&options, origin)
        .expect_err("missing pubKeyCredParams must be rejected");
    assert!(err.to_string().contains("passkey_alg_unsupported"));

    // Only non-ES256 algorithms offered.
    let options = serde_json::json!({
        "user": { "id": "dXNlcg" },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -257 }],
    });
    let err =
        parse_creation_options(&options, origin).expect_err("non-ES256 params must be rejected");
    assert!(err.to_string().contains("passkey_alg_unsupported"));

    // ES256 present but with a wrong type string.
    let options = serde_json::json!({
        "user": { "id": "dXNlcg" },
        "pubKeyCredParams": [{ "type": "other", "alg": -7 }],
    });
    assert!(parse_creation_options(&options, origin).is_err());

    // user object missing entirely.
    let options = serde_json::json!({ "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }] });
    let err = parse_creation_options(&options, origin).expect_err("missing user must be rejected");
    assert!(err.to_string().contains("missing user"));
}

#[test]
fn parse_creation_options_accepts_padded_base64url_and_rp_name() {
    // Padded base64url ("dXNlcg==") must decode via the fallback engine.
    let parsed = parse_creation_options(
        &es256_options(Some("example.com"), Some("dXNlcg==")),
        "https://example.com",
    )
    .unwrap();
    assert_eq!(parsed.user_handle, b"user");
    assert_eq!(parsed.rp_name.as_deref(), Some("Example"));
    assert_eq!(parsed.rp_id, "example.com");

    // Invalid base64url (bad alphabet) is rejected.
    let err = parse_creation_options(
        &es256_options(Some("example.com"), Some("!!!not-base64url!!!")),
        "https://example.com",
    )
    .expect_err("invalid base64url must be rejected");
    assert!(err.to_string().contains("invalid base64url encoding"));
}
