use super::*;

#[test]
fn ssh_key_type_inference_from_public_key_prefix() {
    let mk = |uuid: &str, title: &str, public: &str| {
        json!({
            "uuid": uuid,
            "categoryUuid": "114",
            "overview": { "title": title },
            "details": {
                "sections": [{
                    "fields": [
                        { "id": "private key", "value": "-----BEGIN OPENSSH PRIVATE KEY-----" },
                        { "id": "public key", "value": public }
                    ]
                }]
            }
        })
    };
    let plan = plan_from_items(json!([
        mk(
            "item-k1",
            "Prefixed",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI comment"
        ),
        mk("item-k2", "Unprefixed", "not-a-known-key-format")
    ]));

    assert_eq!(plan.credentials.len(), 2);
    let key_type_of = |name: &str| match &plan
        .credentials
        .iter()
        .find(|c| c.name == name)
        .unwrap()
        .credential_data
    {
        CredentialData::SshKey(k) => k.key_type.clone(),
        other => panic!("unexpected credential data: {other:?}"),
    };
    assert_eq!(key_type_of("Prefixed"), "ssh-ed25519");
    assert_eq!(key_type_of("Unprefixed"), "unknown");
}

#[test]
fn section_values_match_by_title_when_id_is_missing() {
    let item = json!({
        "uuid": "item-t",
        "categoryUuid": "112",
        "overview": { "title": "TitleOnly" },
        "details": {
            "sections": [{
                "fields": [
                    { "value": "no-label-ignored" },
                    { "title": "Credential", "value": "tok-by-title" }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    match &plan.credentials[0].credential_data {
        CredentialData::ApiKey(a) => assert_eq!(a.api_key, "tok-by-title"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn totp_section_field_matched_by_title_with_blank_filtered() {
    let item = json!({
        "uuid": "item-otp",
        "categoryUuid": "001",
        "overview": { "title": "TitleOtp" },
        "details": {
            "loginFields": [
                { "id": "password", "type": "P", "designation": "password", "value": "pw" }
            ],
            "sections": [{
                "fields": [
                    { "id": "totp", "value": "   " },
                    { "id": "custom", "title": "One Time Password", "value": "otpauth://totp/TitleOtp?secret=TITLESECRET" }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    // The blank `totp` field is filtered out; only the title-matched URI
    // yields a credential.
    assert_eq!(plan.skipped.len(), 0);
    assert_eq!(plan.credentials.len(), 2);
    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("TOTP credential");
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => assert_eq!(t.secret_key, "TITLESECRET"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn parse_otpauth_uri_validates_scheme_and_type() {
    // Unparseable input fails at URL parsing.
    let err = format!("{:#}", parse_otpauth_uri("").unwrap_err());
    assert!(err.contains("invalid otpauth URI"), "{err}");
    // A valid URL with the wrong scheme is rejected.
    let err = format!(
        "{:#}",
        parse_otpauth_uri("https://example.com/x?secret=A").unwrap_err()
    );
    assert!(err.contains("otpauth"), "{err}");
    // A non-otpauth otpauth host is rejected.
    let err = format!(
        "{:#}",
        parse_otpauth_uri("otpauth://foo/x?secret=A").unwrap_err()
    );
    assert!(err.contains("TOTP/HOTP"), "{err}");
}

#[test]
fn parse_otpauth_uri_ignores_unknown_params_and_bad_numbers() {
    let params =
        parse_otpauth_uri("otpauth://totp/Issuer:acct?secret=ABCD&foo=bar&digits=abc&period=45")
            .unwrap();
    assert_eq!(params.secret_key.as_deref(), Some("ABCD"));
    assert_eq!(params.issuer.as_deref(), Some("Issuer"));
    assert_eq!(params.account_name.as_deref(), Some("acct"));
    assert_eq!(
        params.digits, None,
        "non-numeric digits fall back to the default"
    );
    assert_eq!(params.period, Some(45));
    assert_eq!(params.hotp, Some(false), "totp host is time-based");
    assert_eq!(params.counter, None);
}

#[test]
fn parse_otpauth_uri_hotp_host_sets_counter_flag() {
    let params = parse_otpauth_uri(
            "otpauth://hotp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3&algorithm=SHA1&digits=6",
        )
        .unwrap();
    assert_eq!(params.hotp, Some(true));
    assert_eq!(params.counter, Some(3));
    assert_eq!(params.algorithm.as_deref(), Some("SHA1"));
    assert_eq!(params.digits, Some(6));

    // When mapped into TwoFactorData the counter-based flag and the initial
    // counter must both be carried, otherwise the imported
    // HOTP entry degrades to time-based and generates wrong codes.
    let data = parse_totp_value(
        "otpauth://hotp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=7",
        "Example",
        None,
    )
    .unwrap();
    assert_eq!(data.hotp, Some(true));
    assert_eq!(data.initial_counter, Some(7));

    let totp = parse_totp_value(
        "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "Example",
        None,
    )
    .unwrap();
    assert_eq!(totp.hotp, Some(false));
    assert_eq!(totp.initial_counter, None);
}
