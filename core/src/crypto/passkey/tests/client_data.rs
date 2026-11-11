use super::*;

/// `ParsedClientData` is not `Debug`, so `expect_err` cannot be used.
fn expect_invalid(result: PersonaResult<ParsedClientData>, msg: &str) -> PersonaError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("{msg}"),
    }
}

#[test]
fn parse_client_data_error_paths() {
    // Malformed JSON.
    let err = expect_invalid(
        parse_client_data(b"{not json", CLIENT_DATA_TYPE_GET, "https://example.com"),
        "malformed JSON must be rejected",
    );
    assert!(err.to_string().contains("Invalid clientDataJSON"));

    // Missing type field.
    let err = expect_invalid(
        parse_client_data(
            br#"{"challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}"#,
            CLIENT_DATA_TYPE_GET,
            "https://example.com",
        ),
        "missing type must be rejected",
    );
    assert!(err.to_string().contains("missing type"));

    // Challenge that is not base64url.
    let err = expect_invalid(
        parse_client_data(
            br#"{"type":"webauthn.get","challenge":"!!!","origin":"https://example.com"}"#,
            CLIENT_DATA_TYPE_GET,
            "https://example.com",
        ),
        "non-base64url challenge must be rejected",
    );
    assert!(err.to_string().contains("challenge is not base64url"));

    // Missing origin field.
    let err = expect_invalid(
        parse_client_data(
            br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl"}"#,
            CLIENT_DATA_TYPE_GET,
            "https://example.com",
        ),
        "missing origin must be rejected",
    );
    assert!(err.to_string().contains("missing origin"));

    // Origin comparison is ASCII-case-insensitive.
    parse_client_data(
        br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"HTTPS://EXAMPLE.COM"}"#,
        CLIENT_DATA_TYPE_GET,
        "https://example.com",
    )
    .expect("case difference in origin must be tolerated");
}
