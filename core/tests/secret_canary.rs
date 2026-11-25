//! AUDIT-021 synthetic canary: regression test for the hand-written Debug
//! redaction of secret-bearing data structures.
//!
//! The secret-bearing structures in `core/src/models/credential.rs` never derive
//! Debug; they get a hand-written implementation instead — secret fields print
//! `[redacted]` (an entry's password hash prints `[set]`) — so that no `{:?}`/
//! `dbg!`/error chain can write the master passphrase, an SSH private key, a
//! TOTP/HOTP seed, an API key, a card number/CVV, a mnemonic or an ID number
//! into logs, toasts, crash reports or test snapshots.
//!
//! This test constructs each structure with unique canary values and
//! `format!("{:?}")`s it, asserting three things:
//! 1. the secret value never appears (any canary leaking is a failure);
//! 2. the redaction placeholder is actually present;
//! 3. non-secret diagnostic fields stay visible.
//!
//! Any newly added secret-bearing data structure must be registered here in step,
//! to prevent a careless derive(Debug).
//!
//! The Debug of the private `LegacyTwoFactorData`/`LegacyGameTokenData` cannot
//! be reached from here and is covered by the equivalent tests in the `mod tests`
//! inside credential.rs.

use std::collections::HashMap;

use persona_core::models::credential::{
    ApiKeyData, BankCardData, CryptoWalletData, GameTokenData, IdentityData,
    PasswordCredentialData, SecurityQuestion, ServerConfigData, SoftwareLicenseData, SshKeyData,
    TwoFactorData,
};

/// Assert that `dbg` contains no canary (zero secret leakage), contains the redaction placeholder, and keeps the diagnostic fields.
fn assert_redacted(dbg: &str, canaries: &[&str], visible: &[&str]) {
    for c in canaries {
        assert!(!dbg.contains(c), "secret canary leaked: {c} in {dbg}");
    }
    assert!(
        dbg.contains("[redacted]") || dbg.contains("[set]"),
        "no redaction marker: {dbg}"
    );
    for v in visible {
        assert!(dbg.contains(v), "diagnostic field lost: {v} in {dbg}");
    }
}

#[test]
fn password_credential_data_debug_redacts_password_and_answers() {
    let data = PasswordCredentialData {
        password: "CANARY-pw-master-secret".into(),
        email: Some("alice@example.com".into()),
        security_questions: vec![SecurityQuestion {
            question: "first pet?".into(),
            answer: "CANARY-pw-answer-secret".into(),
        }],
    };
    let dbg = format!("{data:?}");
    assert_redacted(
        &dbg,
        &["CANARY-pw-master-secret", "CANARY-pw-answer-secret"],
        &["alice@example.com", "first pet?"],
    );
}

#[test]
fn security_question_debug_redacts_answer() {
    let q = SecurityQuestion {
        question: "birth city?".into(),
        answer: "CANARY-sq-answer-secret".into(),
    };
    let dbg = format!("{q:?}");
    assert_redacted(&dbg, &["CANARY-sq-answer-secret"], &["birth city?"]);
}

#[test]
fn crypto_wallet_data_debug_redacts_seed_material() {
    let wallet = CryptoWalletData {
        wallet_type: "bip39".into(),
        mnemonic_phrase: Some("CANARY-cw-mnemonic-secret".into()),
        private_key: Some("CANARY-cw-privkey-secret".into()),
        public_key: "pub-key-visible".into(),
        address: "0xvisible-address".into(),
        network: "ethereum".into(),
        bip39_passphrase: Some("CANARY-cw-passphrase-secret".into()),
        item_password_hash: Some("CANARY-cw-hash-secret".into()),
        item_password_hint: Some("hint-visible".into()),
    };
    let dbg = format!("{wallet:?}");
    assert_redacted(
        &dbg,
        &[
            "CANARY-cw-mnemonic-secret",
            "CANARY-cw-privkey-secret",
            "CANARY-cw-passphrase-secret",
            "CANARY-cw-hash-secret",
        ],
        &[
            "bip39",
            "pub-key-visible",
            "0xvisible-address",
            "ethereum",
            "hint-visible",
            "[set]",
        ],
    );

    // The None branch: the placeholder is absent but there is still zero secret leakage, and the hash slot honestly shows None.
    let bare = CryptoWalletData {
        mnemonic_phrase: None,
        private_key: None,
        bip39_passphrase: None,
        item_password_hash: None,
        ..wallet
    };
    let dbg = format!("{bare:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    assert!(dbg.contains("item_password_hash: None"), "{dbg}");
}

#[test]
fn ssh_key_data_debug_redacts_private_key_and_passphrase() {
    let key = SshKeyData {
        private_key: "CANARY-ssh-privkey-secret".into(),
        public_key: "ssh-ed25519 AAAA visible".into(),
        key_type: "ed25519".into(),
        passphrase: Some("CANARY-ssh-passphrase-secret".into()),
    };
    let dbg = format!("{key:?}");
    assert_redacted(
        &dbg,
        &["CANARY-ssh-privkey-secret", "CANARY-ssh-passphrase-secret"],
        &["ssh-ed25519 AAAA visible", "ed25519"],
    );

    let without = SshKeyData {
        passphrase: None,
        ..key
    };
    let dbg = format!("{without:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("passphrase: None"), "{dbg}");
}

#[test]
fn api_key_data_debug_redacts_key_secret_and_token() {
    let key = ApiKeyData {
        api_key: "CANARY-api-key-secret".into(),
        api_secret: Some("CANARY-api-secret-secret".into()),
        token: Some("CANARY-api-token-secret".into()),
        permissions: vec!["read".into(), "write".into()],
        expires_at: None,
    };
    let dbg = format!("{key:?}");
    assert_redacted(
        &dbg,
        &[
            "CANARY-api-key-secret",
            "CANARY-api-secret-secret",
            "CANARY-api-token-secret",
        ],
        &["read", "write"],
    );

    let without = ApiKeyData {
        api_secret: None,
        token: None,
        ..key
    };
    let dbg = format!("{without:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    assert!(dbg.contains("api_secret: None"), "{dbg}");
}

#[test]
fn bank_card_data_debug_redacts_number_and_cvv() {
    let card = BankCardData {
        card_number: "CANARY-card-number-secret".into(),
        cardholder_name: "Alice Visible".into(),
        expiry_date: "12/30".into(),
        cvv: "CANARY-card-cvv-secret".into(),
        bank_name: "Visible Bank".into(),
        card_type: "visa".into(),
    };
    let dbg = format!("{card:?}");
    assert_redacted(
        &dbg,
        &["CANARY-card-number-secret", "CANARY-card-cvv-secret"],
        &["Alice Visible", "12/30", "Visible Bank", "visa"],
    );
}

#[test]
fn server_config_data_debug_redacts_password() {
    let server = ServerConfigData {
        hostname: "host-visible".into(),
        ip_address: Some("10.0.0.2".into()),
        port: 22,
        protocol: "ssh".into(),
        username: "alice".into(),
        password: Some("CANARY-srv-password-secret".into()),
        ssh_key_id: None,
        additional_config: HashMap::from([("timezone".to_string(), "UTC".to_string())]),
    };
    let dbg = format!("{server:?}");
    assert_redacted(
        &dbg,
        &["CANARY-srv-password-secret"],
        &[
            "host-visible",
            "10.0.0.2",
            "ssh",
            "alice",
            "timezone",
            "UTC",
        ],
    );

    let without = ServerConfigData {
        password: None,
        ..server
    };
    let dbg = format!("{without:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("password: None"), "{dbg}");
}

#[test]
fn two_factor_data_debug_redacts_seed() {
    let totp = TwoFactorData {
        secret_key: "CANARY-totp-seed-secret".into(),
        issuer: "GitHub".into(),
        account_name: "alice@example.com".into(),
        algorithm: "SHA1".into(),
        digits: 6,
        period: 30,
        hotp: None,
        initial_counter: None,
    };
    let dbg = format!("{totp:?}");
    assert_redacted(
        &dbg,
        &["CANARY-totp-seed-secret"],
        &["GitHub", "alice@example.com", "SHA1"],
    );

    // HOTP fields are pass-through (non-secret), so the Some value should be visible as-is.
    let hotp = TwoFactorData {
        hotp: Some(true),
        initial_counter: Some(7),
        ..totp
    };
    let dbg = format!("{hotp:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    assert!(
        dbg.contains("hotp: Some(true)") && dbg.contains("initial_counter: Some(7)"),
        "{dbg}"
    );
}

#[test]
fn game_token_data_debug_redacts_steam_secrets() {
    let token = GameTokenData {
        provider: "steam_guard".into(),
        secret_key: "CANARY-game-secretkey-secret".into(),
        issuer: "Steam".into(),
        account_name: "gamer".into(),
        url: Some("https://steamcommunity.com".into()),
        identity_secret: Some("CANARY-game-identity-secret".into()),
        device_id: Some("mobile1234567".into()),
    };
    let dbg = format!("{token:?}");
    assert_redacted(
        &dbg,
        &[
            "CANARY-game-secretkey-secret",
            "CANARY-game-identity-secret",
        ],
        &[
            "steam_guard",
            "Steam",
            "gamer",
            "steamcommunity.com",
            "mobile1234567",
        ],
    );

    let bare = GameTokenData {
        identity_secret: None,
        ..token
    };
    let dbg = format!("{bare:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("identity_secret: None"), "{dbg}");
}

#[test]
fn identity_data_debug_redacts_government_ids() {
    let id = IdentityData {
        first_name: "Alice".into(),
        last_name: "Visible".into(),
        username: Some("alicevis".into()),
        email: Some("alice@example.com".into()),
        phone: Some("+8613800000000".into()),
        birthday: Some("1990-01-31".into()),
        address: Some("1 Visible St".into()),
        id_number: Some("CANARY-id-idnum-secret".into()),
        passport_number: Some("CANARY-id-passport-secret".into()),
        driver_license: Some("CANARY-id-dl-secret".into()),
        tax_id: Some("CANARY-id-tax-secret".into()),
        organization: Some("Visible Corp".into()),
        job_title: Some("Engineer".into()),
    };
    let dbg = format!("{id:?}");
    assert_redacted(
        &dbg,
        &[
            "CANARY-id-idnum-secret",
            "CANARY-id-passport-secret",
            "CANARY-id-dl-secret",
            "CANARY-id-tax-secret",
        ],
        &[
            "Alice",
            "alicevis",
            "alice@example.com",
            "+8613800000000",
            "1990-01-31",
            "1 Visible St",
            "Visible Corp",
            "Engineer",
        ],
    );
}

#[test]
fn software_license_data_debug_redacts_license_key() {
    let lic = SoftwareLicenseData {
        license_key: "CANARY-lic-key-secret".into(),
        version: Some("2.0".into()),
        publisher: Some("Visible Soft".into()),
        purchase_date: Some("2026-01-01".into()),
        order_number: Some("ORD-1".into()),
        support_email: Some("support@visible.example".into()),
        download_url: Some("https://download.visible.example".into()),
        seats: Some(3),
        valid_until: Some("2027-01-01".into()),
    };
    let dbg = format!("{lic:?}");
    assert_redacted(
        &dbg,
        &["CANARY-lic-key-secret"],
        &["2.0", "Visible Soft", "ORD-1", "support@visible.example"],
    );
}
