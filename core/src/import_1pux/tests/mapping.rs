use super::*;

#[test]
fn login_maps_to_password_credential() {
    let plan = plan_from_items(json!([login_item()]));
    assert_eq!(plan.identities.len(), 1);
    assert_eq!(plan.identities[0].name, "Personal");
    assert_eq!(
        plan.identities[0].description,
        "Imported from 1Password vault vault-1"
    );
    assert_eq!(plan.skipped.len(), 0);

    let cred = &plan.credentials[0];
    assert_eq!(cred.vault_uuid, "vault-1");
    assert_eq!(cred.name, "Example");
    assert_eq!(cred.credential_type, CredentialType::Password);
    assert_eq!(cred.security_level, SecurityLevel::High);
    assert_eq!(cred.url.as_deref(), Some("https://example.com"));
    assert_eq!(cred.username.as_deref(), Some("alice@example.com"));
    assert_eq!(cred.notes.as_deref(), Some("note text"));
    assert_eq!(cred.tags, vec!["web".to_string(), "work".to_string()]);
    assert_eq!(
        cred.metadata.get("alt_urls").map(String::as_str),
        Some("https://example.com/login")
    );
    assert!(cred.is_favorite);
    match &cred.credential_data {
        CredentialData::Password(p) => {
            assert_eq!(p.password, "hunter2");
            assert_eq!(p.email.as_deref(), Some("alice@example.com"));
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn totp_otpauth_uri_splits_into_two_factor_credential() {
    let item = json!({
        "uuid": "item-2",
        "categoryUuid": "001",
        "overview": { "title": "Example", "urls": [{ "href": "https://example.com" }] },
        "details": {
            "loginFields": [
                { "id": "username", "type": "T", "designation": "username", "value": "alice" },
                { "id": "password", "type": "P", "designation": "password", "value": "hunter2" }
            ],
            "sections": [{
                "title": "",
                "fields": [{
                    "id": "ONE_TIME_PASSWORD",
                    "title": "One Time Password",
                    "value": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60"
                }]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert_eq!(plan.credentials.len(), 2);
    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("TOTP credential");
    assert_eq!(totp.name, "Example (TOTP)");
    assert_eq!(totp.url.as_deref(), Some("https://example.com"));
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => {
            assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
            assert_eq!(t.issuer, "Example");
            assert_eq!(t.account_name, "alice");
            assert_eq!(t.algorithm, "SHA256");
            assert_eq!(t.digits, 8);
            assert_eq!(t.period, 60);
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn totp_bare_base32_gets_defaults() {
    let item = json!({
        "uuid": "item-3",
        "categoryUuid": "001",
        "overview": { "title": "Bare" },
        "details": {
            "loginFields": [
                { "id": "username", "type": "T", "designation": "username", "value": "bob" },
                { "id": "password", "type": "P", "designation": "password", "value": "pw" },
                { "id": "totp", "type": "OTP", "designation": null, "value": "JBSWY3DPEHPK3PXP" }
            ]
        }
    });
    let plan = plan_from_items(json!([item]));

    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("TOTP credential");
    assert_eq!(totp.name, "Bare (TOTP)");
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => {
            assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
            assert_eq!(t.issuer, "Bare");
            assert_eq!(t.account_name, "bob");
            assert_eq!(t.algorithm, "SHA1");
            assert_eq!(t.digits, 6);
            assert_eq!(t.period, 30);
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn unparseable_totp_is_reported_but_login_imports() {
    let item = json!({
        "uuid": "item-4",
        "categoryUuid": "001",
        "overview": { "title": "Broken" },
        "details": {
            "loginFields": [
                { "id": "password", "type": "P", "designation": "password", "value": "pw" }
            ],
            "sections": [{
                "fields": [{
                    "id": "ONE_TIME_PASSWORD",
                    "value": "otpauth://totp/NoSecret"
                }]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert_eq!(plan.credentials.len(), 1);
    assert_eq!(
        plan.credentials[0].credential_type,
        CredentialType::Password
    );
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].title, "Broken (TOTP)");
    assert!(plan.skipped[0].reason.contains("secret"));
}

#[test]
fn api_key_category_maps_with_concealed_value() {
    let item = json!({
        "uuid": "item-5",
        "categoryUuid": "112",
        "overview": { "title": "Service token", "urls": [{ "href": "https://api.example.com" }] },
        "details": {
            "loginFields": [
                { "id": "username", "type": "T", "designation": "username", "value": "svc-user" }
            ],
            "sections": [{
                "title": "",
                "fields": [
                    { "id": "credential", "title": "Credential", "value": { "concealed": "sk-live-123" } },
                    { "id": "service", "title": "Service", "value": "Example API" }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert_eq!(plan.credentials.len(), 1);
    let cred = &plan.credentials[0];
    assert_eq!(cred.credential_type, CredentialType::ApiKey);
    assert_eq!(cred.name, "Service token");
    match &cred.credential_data {
        CredentialData::ApiKey(a) => {
            assert_eq!(a.api_key, "sk-live-123");
            assert!(a.permissions.is_empty());
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
    assert_eq!(
        cred.metadata.get("username").map(String::as_str),
        Some("svc-user")
    );
}

#[test]
fn api_key_without_value_is_skipped() {
    let item = json!({
        "uuid": "item-6",
        "categoryUuid": "112",
        "overview": { "title": "Empty" },
        "details": { "sections": [] }
    });
    let plan = plan_from_items(json!([item]));

    assert!(plan.credentials.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert!(plan.skipped[0].reason.contains("not found"));
}

#[test]
fn ssh_key_category_maps_sections() {
    let item = json!({
        "uuid": "item-7",
        "categoryUuid": "114",
        "overview": { "title": "Server key" },
        "details": {
            "sections": [{
                "fields": [
                    { "id": "private key", "value": { "concealed": "-----BEGIN OPENSSH PRIVATE KEY-----" } },
                    { "id": "public key", "value": "ssh-ed25519 AAAAC3Nza me@host" },
                    { "id": "key type", "value": "ed25519" },
                    { "id": "passphrase", "value": { "concealed": "pp" } }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert_eq!(plan.credentials.len(), 1);
    let cred = &plan.credentials[0];
    assert_eq!(cred.credential_type, CredentialType::SshKey);
    match &cred.credential_data {
        CredentialData::SshKey(k) => {
            assert_eq!(k.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----");
            assert_eq!(k.public_key, "ssh-ed25519 AAAAC3Nza me@host");
            assert_eq!(k.key_type, "ed25519");
            assert_eq!(k.passphrase.as_deref(), Some("pp"));
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn ssh_key_type_inferred_from_public_key() {
    let item = json!({
        "uuid": "item-8",
        "categoryUuid": "114",
        "overview": { "title": "RSA key" },
        "details": {
            "sections": [{
                "fields": [
                    { "id": "private key", "value": "RSA PRIVATE KEY DATA" },
                    { "id": "public key", "value": "ssh-rsa AAAAB3Nza root@host" }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    match &plan.credentials[0].credential_data {
        CredentialData::SshKey(k) => {
            assert_eq!(k.key_type, "ssh-rsa");
            assert_eq!(k.passphrase, None);
        }
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn ssh_key_without_private_key_is_skipped() {
    let item = json!({
        "uuid": "item-9",
        "categoryUuid": "114",
        "overview": { "title": "Only public" },
        "details": {
            "sections": [{
                "fields": [{ "id": "public key", "value": "ssh-ed25519 AAAA" }]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert!(plan.credentials.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert!(plan.skipped[0].reason.contains("private key"));
}

#[test]
fn archived_and_unmapped_categories_are_skipped() {
    let archived = json!({
        "uuid": "a-1", "categoryUuid": "001", "state": "ARCHIVED",
        "overview": { "title": "Old login" }, "details": {}
    });
    let card = json!({
        "uuid": "c-1", "categoryUuid": "002",
        "overview": { "title": "My card" }, "details": {}
    });
    let note = json!({
        "uuid": "n-1", "categoryUuid": "003",
        "overview": { "title": "My note" }, "details": {}
    });
    let plan = plan_from_items(json!([archived, card, note]));

    assert!(plan.credentials.is_empty());
    assert_eq!(plan.skipped.len(), 3);
    assert_eq!(plan.skipped[0].title, "Old login");
    assert!(plan.skipped[0].reason.contains("archived"));
    assert_eq!(plan.skipped[1].title, "My card");
    assert_eq!(plan.skipped[1].category, "Credit Card");
    assert!(plan.skipped[1].reason.contains("not supported"));
    assert_eq!(plan.skipped[2].category, "Secure Note");
    // The vault still becomes an identity even if nothing imports.
    assert_eq!(plan.identities.len(), 1);
}

#[test]
fn missing_title_falls_back_to_uuid() {
    let item = json!({
        "uuid": "anon-1", "categoryUuid": "004",
        "overview": {}, "details": {}
    });
    let plan = plan_from_items(json!([item]));

    assert_eq!(plan.skipped[0].title, "Untitled (anon-1)");
}

#[test]
fn empty_export_yields_empty_plan() {
    let bytes = make_1pux(&attributes_json(3), &json!({ "accounts": [] }).to_string());
    let export = parse_1pux(&bytes).unwrap();
    let plan = plan_import(&export);
    assert!(plan.identities.is_empty());
    assert!(plan.credentials.is_empty());
    assert!(plan.skipped.is_empty());
}

#[test]
fn unsupported_category_reports_unknown_category_name() {
    let item = json!({
        "uuid": "item-x",
        "categoryUuid": "999",
        "overview": { "title": "Mystery" },
        "details": { "sections": [] }
    });
    let plan = plan_from_items(json!([item]));

    assert!(plan.credentials.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].title, "Mystery");
    assert_eq!(plan.skipped[0].category, "Unknown category (999)");
    assert!(plan.skipped[0].reason.contains("not supported"));
}

#[test]
fn api_key_number_field_value_is_filtered_to_empty() {
    // A numeric section value deserializes (untagged Number) but renders
    // as an empty string, so no key can be extracted and the item is
    // reported as skipped instead of importing an empty secret.
    let item = json!({
        "uuid": "item-n",
        "categoryUuid": "112",
        "overview": { "title": "Numeric" },
        "details": {
            "sections": [{ "fields": [{ "title": "Credential", "value": 7 }] }]
        }
    });
    let plan = plan_from_items(json!([item]));

    assert!(plan.credentials.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert!(plan.skipped[0].reason.contains("not found"));
}

#[test]
fn api_key_concealed_fallback_skips_credential_id_and_blanks() {
    let item = json!({
        "uuid": "item-c",
        "categoryUuid": "112",
        "overview": { "title": "Concealed" },
        "details": {
            "sections": [{
                "fields": [
                    { "id": "credential", "value": "   " },
                    { "title": "blank", "value": { "concealed": "   " } },
                    { "title": "real", "value": { "concealed": "  the-secret  " } }
                ]
            }]
        }
    });
    let plan = plan_from_items(json!([item]));

    let cred = &plan.credentials[0];
    match &cred.credential_data {
        CredentialData::ApiKey(a) => assert_eq!(a.api_key, "the-secret"),
        other => panic!("unexpected credential data: {other:?}"),
    }
}

#[test]
fn login_urls_fall_back_to_overview_url() {
    let missing = json!({
        "uuid": "item-u1",
        "categoryUuid": "001",
        "overview": { "title": "NoUrls", "url": "https://fallback.example" },
        "details": { "loginFields": [] }
    });
    let blank = json!({
        "uuid": "item-u2",
        "categoryUuid": "001",
        "overview": {
            "title": "BlankUrls",
            "url": "https://blank.example",
            "urls": [
                { "label": "spaces", "href": "   " },
                { "label": "empty", "href": "" }
            ]
        },
        "details": { "loginFields": [] }
    });
    let plan = plan_from_items(json!([missing, blank]));

    assert_eq!(plan.credentials.len(), 2);
    let by_name = |n: &str| {
        plan.credentials
            .iter()
            .find(|c| c.name == n)
            .unwrap_or_else(|| panic!("credential {n} missing"))
    };
    assert_eq!(
        by_name("NoUrls").url.as_deref(),
        Some("https://fallback.example")
    );
    assert_eq!(
        by_name("BlankUrls").url.as_deref(),
        Some("https://blank.example")
    );
    // Neither item produced secondary URLs.
    assert!(!by_name("NoUrls").metadata.contains_key("alt_urls"));
}
