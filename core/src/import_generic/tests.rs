use super::*;
use crate::models::credential::CredentialType;

use crate::import_1pux::{ImportPlan, PlannedCredential};
use crate::models::credential::CredentialData;

fn plan_csv_str(csv: &str, name: &str) -> ImportPlan {
    let export = parse_generic(csv.as_bytes(), Some(GenericExportFormat::Csv)).unwrap();
    plan_generic_import(&export, name, "test.csv")
}

fn plan_bw_json(value: serde_json::Value, name: &str) -> ImportPlan {
    let bytes = value.to_string().into_bytes();
    let export = parse_generic(&bytes, Some(GenericExportFormat::BitwardenJson)).unwrap();
    plan_generic_import(&export, name, "test.json")
}

fn password_of<'a>(plan: &'a ImportPlan, name: &'a str) -> &'a PlannedCredential {
    plan.credentials
        .iter()
        .find(|c| c.name == name && c.credential_type == CredentialType::Password)
        .unwrap_or_else(|| panic!("no password credential named {name}"))
}

// -- Format sniffing ------------------------------------------------------

#[test]
fn detect_format_distinguishes_json_from_csv() {
    assert_eq!(
        detect_format(b"{\"items\":[]}"),
        GenericExportFormat::BitwardenJson
    );
    assert_eq!(
        detect_format(b"\xEF\xBB\xBF[{\"id\":1}]"),
        GenericExportFormat::BitwardenJson
    );
    assert_eq!(detect_format(b"name,url\nx,y"), GenericExportFormat::Csv);
    assert_eq!(
        detect_format(b"\xEF\xBB\xBFname,url\r\nx,y"),
        GenericExportFormat::Csv
    );
}

// -- CSV column shapes ----------------------------------------------------

#[test]
fn bitwarden_csv_full_shape_with_totp_folder_and_type_splits() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,\
                   login_password,totp\n\
                   Work,1,login,GitHub,some note,,0,https://github.com,alice,hunter2,\
                   otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
                   ,0,note,Recovery codes,codes...,,,\n\
                   ,0,card,Bank card,,,0,,,\n";
    let plan = plan_csv_str(csv, "bitwarden");

    assert_eq!(plan.identities.len(), 1);
    assert_eq!(plan.identities[0].name, "bitwarden");
    assert_eq!(plan.identities[0].vault_uuid, GENERIC_VAULT_KEY);

    let login = password_of(&plan, "GitHub");
    assert_eq!(login.url.as_deref(), Some("https://github.com"));
    assert_eq!(login.username.as_deref(), Some("alice"));
    assert!(login.is_favorite, "favorite=1 → is_favorite");
    assert_eq!(login.tags, vec!["Work"]);
    match &login.credential_data {
        CredentialData::Password(p) => assert_eq!(p.password, "hunter2"),
        other => panic!("unexpected: {other:?}"),
    }

    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("totp split out");
    assert_eq!(totp.name, "GitHub (TOTP)");
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => {
            assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
            assert_eq!(t.issuer, "GitHub");
            assert_eq!(t.account_name, "alice");
        }
        other => panic!("unexpected: {other:?}"),
    }

    let note = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::SecureNote)
        .expect("note row → SecureNote");
    assert_eq!(note.name, "Recovery codes");
    match &note.credential_data {
        CredentialData::SecureNote(n) => assert_eq!(n.note, "codes..."),
        other => panic!("unexpected: {other:?}"),
    }

    assert_eq!(plan.skipped.len(), 1, "card row skipped");
    assert!(plan.skipped[0].reason.contains("JSON"));
}

#[test]
fn chrome_csv_minimal_shape() {
    let plan = plan_csv_str(
        "name,url,username,password\nExample,https://example.com,bob,pw1\n",
        "chrome",
    );
    let login = password_of(&plan, "Example");
    assert_eq!(login.url.as_deref(), Some("https://example.com"));
    assert_eq!(login.username.as_deref(), Some("bob"));
    match &login.credential_data {
        CredentialData::Password(p) => assert_eq!(p.password, "pw1"),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(login.metadata.is_empty());
}

#[test]
fn firefox_csv_without_title_falls_back_to_host() {
    let plan = plan_csv_str(
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated\n\
             https://example.org/login,carol,pw2,,,abc,1\n",
        "firefox",
    );
    let login = password_of(&plan, "example.org");
    assert_eq!(login.username.as_deref(), Some("carol"));
    assert_eq!(login.url.as_deref(), Some("https://example.org/login"));
}

#[test]
fn keepass_one_csv_aliases() {
    let plan = plan_csv_str(
        "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\
             \"Server\",\"root\",\"s3cret\",\"https://srv.example.com\",\"prod box\"\n",
        "keepass1",
    );
    let login = password_of(&plan, "Server");
    assert_eq!(login.username.as_deref(), Some("root"));
    assert_eq!(login.url.as_deref(), Some("https://srv.example.com"));
    assert_eq!(login.notes.as_deref(), Some("prod box"));
}

#[test]
fn keepass_two_csv_aliases() {
    let plan = plan_csv_str(
        "Title,Username,Password,URL,Notes\nSite,admin,pw3,https://site.example.com,note\n",
        "keepass2",
    );
    let login = password_of(&plan, "Site");
    assert_eq!(login.username.as_deref(), Some("admin"));
    assert_eq!(login.url.as_deref(), Some("https://site.example.com"));
}

#[test]
fn quoted_multiline_notes_and_empty_rows() {
    let plan = plan_csv_str(
        "name,url,username,password,notes\n\
             \"Multi\",\"https://a.com\",u,p,\"line1\nline2\"\n\
             ,,,,\n\
             \"Bare\",,,,,\n",
        "multi",
    );
    let multi = password_of(&plan, "Multi");
    match &multi.credential_data {
        CredentialData::Password(p) if p.password == "p" => {}
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(multi.notes.as_deref(), Some("line1\nline2"));
    // The "Bare" row only has a title, yet it is still imported (empty password);
    // empty rows are ignored and do not reach the report.
    assert!(password_of(&plan, "Bare").username.is_none());
    assert_eq!(plan.credentials.len(), 2);
    assert!(plan.skipped.is_empty());
}

#[test]
fn unrecognized_headers_report_columns() {
    let err = parse_generic(b"foo,bar\n1,2\n", Some(GenericExportFormat::Csv))
        .expect_err("unknown columns must fail");
    assert!(err.to_string().contains("foo, bar"));
}

#[test]
fn broken_otpauth_totp_goes_to_skipped_without_the_secret() {
    // Same lenient policy as 1PUX: a bare value that is not otpauth is kept
    // verbatim as the base32 secret; only an otpauth-shaped URI whose host is neither totp
    // nor hotp fails to parse → skipped, and the reason carries no secret values.
    let plan = plan_csv_str(
        "name,username,password,totp\nX,u,p,otpauth://foo/x?secret=TOPSECRET\n",
        "badtotp",
    );
    assert_eq!(
        password_of(&plan, "X").username.as_deref(),
        Some("u"),
        "登录本体照常导入"
    );
    assert_eq!(plan.skipped.len(), 1);
    assert!(
        !plan.skipped[0].reason.contains("TOPSECRET"),
        "跳过原因不得携带密值: {}",
        plan.skipped[0].reason
    );
}

#[test]
fn hotp_otpauth_value_imports_as_counter_based_entry() {
    // otpauth://hotp/ is a legal URI like totp: after import it carries the hotp flag and
    // the initial counter, and is no longer skipped.
    let plan = plan_csv_str(
            "name,username,password,totp\nX,u,p,otpauth://hotp/Ex:acct?secret=JBSWY3DPEHPK3PXP&counter=5\n",
            "hotp",
        );
    assert_eq!(plan.skipped.len(), 0, "{:?}", plan.skipped);
    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("HOTP 条目作为 TwoFactor 导入");
    match &totp.credential_data {
        CredentialData::TwoFactor(tf) => {
            assert_eq!(tf.hotp, Some(true));
            assert_eq!(tf.initial_counter, Some(5));
        }
        other => panic!("unexpected data: {other:?}"),
    }
}

#[test]
fn bare_totp_value_is_imported_verbatim_like_1pux() {
    let plan = plan_csv_str(
        "name,username,password,totp\nX,u,p,NOTBASE32!!!\n",
        "lenient",
    );
    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("裸值宽容导入");
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => assert_eq!(t.secret_key, "NOTBASE32!!!"),
        other => panic!("unexpected: {other:?}"),
    }
}

// -- Bitwarden JSON -------------------------------------------------------

#[test]
fn bitwarden_json_login_with_uris_folder_and_favorite() {
    let plan = plan_bw_json(
        serde_json::json!({
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Infra"}],
            "items": [{
                "id": "i1", "type": 1, "name": "GitHub", "notes": "n",
                "favorite": true, "folderId": "f1",
                "login": {
                    "username": "alice", "password": "hunter2",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://github.com"}, {"uri": "https://gist.github.com"}]
                }
            }]
        }),
        "bw",
    );

    let login = password_of(&plan, "GitHub");
    assert_eq!(login.url.as_deref(), Some("https://github.com"));
    assert_eq!(
        login.metadata.get("alt_urls").map(String::as_str),
        Some("https://gist.github.com")
    );
    assert_eq!(login.tags, vec!["Infra"]);
    assert!(login.is_favorite);

    let totp = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::TwoFactor)
        .expect("bare secret totp split");
    match &totp.credential_data {
        CredentialData::TwoFactor(t) => {
            assert_eq!(t.secret_key, "JBSWY3DPEHPK3PXP");
            assert_eq!(t.issuer, "GitHub", "issuer 兜底用条目名");
            assert_eq!(t.account_name, "alice");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bitwarden_json_note_card_ssh_and_identity() {
    let plan = plan_bw_json(
        serde_json::json!({
            "items": [
                {"id": "i2", "type": 2, "name": "Note", "notes": "body"},
                {"id": "i3", "type": 3, "name": "Card",
                 "card": {"cardholderName": "A B", "brand": "visa", "number": "4111",
                          "expMonth": "12", "expYear": "2030", "code": "123"}},
                {"id": "i4", "type": 4, "name": "Identity"},
                {"id": "i5", "type": 5, "name": "Key",
                 "sshKey": {"privateKey": "-----BEGIN", "publicKey": "ssh-ed25519 AAAA"}},
                {"id": "i6", "type": 99, "name": "Mystery"}
            ]
        }),
        "bw",
    );

    let note = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::SecureNote)
        .unwrap();
    match &note.credential_data {
        CredentialData::SecureNote(n) => assert_eq!(n.note, "body"),
        other => panic!("unexpected: {other:?}"),
    }

    let card = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::BankCard)
        .unwrap();
    match &card.credential_data {
        CredentialData::BankCard(c) => {
            assert_eq!(c.card_number, "4111");
            assert_eq!(c.cardholder_name, "A B");
            assert_eq!(c.expiry_date, "12/2030");
            assert_eq!(c.cvv, "123");
            assert_eq!(c.card_type, "visa");
        }
        other => panic!("unexpected: {other:?}"),
    }

    let ssh = plan
        .credentials
        .iter()
        .find(|c| c.credential_type == CredentialType::SshKey)
        .unwrap();
    match &ssh.credential_data {
        CredentialData::SshKey(k) => {
            assert_eq!(k.key_type, "ssh-ed25519");
            assert!(k.private_key.starts_with("-----BEGIN"));
        }
        other => panic!("unexpected: {other:?}"),
    }

    let skipped_categories: Vec<&str> = plan.skipped.iter().map(|s| s.category.as_str()).collect();
    assert!(skipped_categories.contains(&"Bitwarden Identity"));
    assert!(skipped_categories.contains(&"Bitwarden type 99"));
}

#[test]
fn bitwarden_encrypted_export_is_rejected_with_guidance() {
    let bytes = serde_json::json!({
        "encrypted": true,
        "items": [{"type": 1, "name": "x"}]
    })
    .to_string()
    .into_bytes();
    let err = parse_generic(&bytes, Some(GenericExportFormat::BitwardenJson))
        .expect_err("encrypted export must be refused");
    assert!(err.to_string().contains("encrypted: true"));
}

#[test]
fn bitwarden_bare_item_array_is_accepted() {
    let bytes = serde_json::json!([
        {"id": "i1", "type": 1, "name": "Solo", "login": {"username": "u", "password": "p"}}
    ])
    .to_string()
    .into_bytes();
    let export = parse_generic(&bytes, None).unwrap();
    assert!(matches!(export, GenericExport::BitwardenJson(_)));
    let plan = plan_generic_import(&export, "bw", "test.json");
    assert_eq!(password_of(&plan, "Solo").username.as_deref(), Some("u"));
}

#[test]
fn bitwarden_item_without_name_gets_untitled_fallback() {
    let plan = plan_bw_json(
        serde_json::json!({"items": [{"id": "abc", "type": 2}]}),
        "bw",
    );
    assert_eq!(plan.credentials[0].name, "Untitled (abc)");
}
