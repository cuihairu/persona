use super::*;

#[test]
fn credential_data_bincode_roundtrip() {
    let data = CredentialData::Password(PasswordCredentialData {
        password: "p@ss".to_string(),
        email: Some("alice@example.com".to_string()),
        security_questions: vec![SecurityQuestion {
            question: "q".to_string(),
            answer: "a".to_string(),
        }],
    });

    let bytes = data.to_bytes().unwrap();
    let decoded = CredentialData::from_bytes(&bytes).unwrap();
    assert!(matches!(decoded, CredentialData::Password(_)));
}

#[test]
fn credential_data_bincode_roundtrip_all_variants() {
    let variants = vec![
        CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "hd".to_string(),
            mnemonic_phrase: Some("word word word".to_string()),
            private_key: Some("hex".to_string()),
            public_key: "pub".to_string(),
            address: "0xabc".to_string(),
            network: "ethereum".to_string(),
            bip39_passphrase: Some("tungsten".to_string()),
            item_password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$hash".to_string()),
            item_password_hint: Some("hint".to_string()),
        }),
        CredentialData::SshKey(SshKeyData {
            private_key: "priv".to_string(),
            public_key: "pub".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: Some("phrase".to_string()),
        }),
        CredentialData::ApiKey(ApiKeyData {
            api_key: "key".to_string(),
            api_secret: Some("secret".to_string()),
            token: Some("token".to_string()),
            permissions: vec!["read".to_string(), "write".to_string()],
            expires_at: Some(chrono::Utc::now()),
        }),
        CredentialData::BankCard(BankCardData {
            card_number: "4242".to_string(),
            cardholder_name: "Alice".to_string(),
            expiry_date: "12/30".to_string(),
            cvv: "123".to_string(),
            bank_name: "Example Bank".to_string(),
            card_type: "visa".to_string(),
        }),
        CredentialData::ServerConfig(ServerConfigData {
            hostname: "server.example.com".to_string(),
            ip_address: Some("10.0.0.2".to_string()),
            port: 22,
            protocol: "ssh".to_string(),
            username: "deploy".to_string(),
            password: None,
            ssh_key_id: Some(Uuid::new_v4()),
            additional_config: HashMap::new(),
        }),
        CredentialData::TwoFactor(TwoFactorData {
            secret_key: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: "Example".to_string(),
            account_name: "alice@example.com".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            hotp: None,
            initial_counter: None,
            period: 30,
        }),
        CredentialData::Raw(vec![1, 2, 3]),
        CredentialData::GameToken(GameTokenData {
            provider: "steam_guard".to_string(),
            secret_key: "abcdefghijklmnopqrst".to_string(),
            issuer: "Steam".to_string(),
            account_name: "alice".to_string(),
            url: Some("https://steamcommunity.com".to_string()),
            identity_secret: None,
            device_id: None,
        }),
        CredentialData::SecureNote(SecureNoteData {
            note: "recovery codes:\n1111-2222\n3333-4444".to_string(),
        }),
        CredentialData::Identity(IdentityData {
            first_name: "Alice".to_string(),
            last_name: "Zhang".to_string(),
            username: Some("alicez".to_string()),
            email: Some("alice@example.com".to_string()),
            phone: Some("+86 13800000000".to_string()),
            birthday: Some("1990-01-31".to_string()),
            address: Some("1 Main St\nBeijing".to_string()),
            id_number: Some("110101199001310011".to_string()),
            passport_number: Some("E12345678".to_string()),
            driver_license: None,
            tax_id: None,
            organization: Some("Example Inc".to_string()),
            job_title: Some("Engineer".to_string()),
        }),
        CredentialData::SoftwareLicense(SoftwareLicenseData {
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            version: Some("2.1.0".to_string()),
            publisher: Some("Example Soft".to_string()),
            purchase_date: Some("2024-05-01".to_string()),
            order_number: Some("ORD-42".to_string()),
            support_email: Some("support@example.com".to_string()),
            download_url: Some("https://example.com/dl".to_string()),
            seats: Some(3),
            valid_until: Some("2027-05-01".to_string()),
        }),
    ];

    for data in variants {
        let bytes = data.to_bytes().unwrap();
        let decoded = CredentialData::from_bytes(&bytes).unwrap();
        assert_eq!(
            std::mem::discriminant(&decoded),
            std::mem::discriminant(&data)
        );
    }
}

#[test]
fn credential_data_from_bytes_rejects_garbage() {
    assert!(CredentialData::from_bytes(b"not bincode").is_err());
}

/// The bincode encoding of existing variants must be byte-for-byte stable
/// (variant index = enum ordinal); new variants may only be appended at the
/// end — otherwise every old ciphertext is bricked.
#[test]
fn credential_data_bincode_variant_indices_are_stable() {
    // Raw is the last variant before GameToken was appended (index 7; the Vec
    // carries a u64 length prefix)
    assert_eq!(
        CredentialData::Raw(vec![1, 2, 3]).to_bytes().unwrap(),
        vec![7, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]
    );
    // GameToken appended at the end, index 8
    let game = CredentialData::GameToken(GameTokenData {
        provider: "steam_guard".to_string(),
        secret_key: "s".to_string(),
        issuer: "i".to_string(),
        account_name: "a".to_string(),
        url: None,
        identity_secret: None,
        device_id: None,
    })
    .to_bytes()
    .unwrap();
    assert_eq!(&game[..4], &[8, 0, 0, 0]);
    let decoded = CredentialData::from_bytes(&game).unwrap();
    assert!(matches!(decoded, CredentialData::GameToken(_)));
    // SecureNote appended at the end, index 9 (String has a u64 length prefix)
    let note = CredentialData::SecureNote(SecureNoteData {
        note: "abc".to_string(),
    })
    .to_bytes()
    .unwrap();
    assert_eq!(&note[..4], &[9, 0, 0, 0]);
    let decoded = CredentialData::from_bytes(&note).unwrap();
    assert!(matches!(decoded, CredentialData::SecureNote(_)));
    // Identity appended at the end, index 10
    let identity = CredentialData::Identity(IdentityData {
        first_name: "a".to_string(),
        last_name: "b".to_string(),
        username: None,
        email: None,
        phone: None,
        birthday: None,
        address: None,
        id_number: None,
        passport_number: None,
        driver_license: None,
        tax_id: None,
        organization: None,
        job_title: None,
    })
    .to_bytes()
    .unwrap();
    assert_eq!(&identity[..4], &[10, 0, 0, 0]);
    let decoded = CredentialData::from_bytes(&identity).unwrap();
    assert!(matches!(decoded, CredentialData::Identity(_)));
    // SoftwareLicense appended at the end, index 11
    let license = CredentialData::SoftwareLicense(SoftwareLicenseData {
        license_key: "k".to_string(),
        version: None,
        publisher: None,
        purchase_date: None,
        order_number: None,
        support_email: None,
        download_url: None,
        seats: None,
        valid_until: None,
    })
    .to_bytes()
    .unwrap();
    assert_eq!(&license[..4], &[11, 0, 0, 0]);
    let decoded = CredentialData::from_bytes(&license).unwrap();
    assert!(matches!(decoded, CredentialData::SoftwareLicense(_)));
}

/// A GameToken ciphertext (five-field payload) written before
/// identity_secret/device_id were appended must stay readable, with the new
/// fields mapping to None and the business fields preserved as-is.
#[test]
fn legacy_game_token_payload_reads_with_none_new_fields() {
    let legacy = LegacyGameTokenData {
        provider: "steam_guard".to_string(),
        secret_key: "abcdefghijklmnopqrst".to_string(),
        issuer: "Steam".to_string(),
        account_name: "alice".to_string(),
        url: Some("https://steamcommunity.com".to_string()),
    };
    let mut payload = CredentialData::GameToken(GameTokenData {
        provider: legacy.provider.clone(),
        secret_key: legacy.secret_key.clone(),
        issuer: legacy.issuer.clone(),
        account_name: legacy.account_name.clone(),
        url: legacy.url.clone(),
        identity_secret: None,
        device_id: None,
    })
    .to_bytes()
    .unwrap();
    // Chop off the two new Option fields (each Option::None costs 1 marker byte
    // in bincode, see the serialization probe; only the variant index is u32),
    // to rebuild the legacy payload
    payload.truncate(payload.len() - 2);

    let decoded = CredentialData::from_bytes(&payload).unwrap();
    // Re-encryption uses the new shape (legacy payloads are never written back,
    // which would keep re-entering the legacy branch)
    let rewritten = decoded.to_bytes().unwrap();
    assert_ne!(rewritten, payload);
    match decoded {
        CredentialData::GameToken(data) => {
            assert_eq!(data.provider, "steam_guard");
            assert_eq!(data.secret_key, "abcdefghijklmnopqrst");
            assert_eq!(data.issuer, "Steam");
            assert_eq!(data.account_name, "alice");
            assert_eq!(data.url.as_deref(), Some("https://steamcommunity.com"));
            assert_eq!(data.identity_secret, None);
            assert_eq!(data.device_id, None);
        }
        other => panic!("unexpected data: {:?}", other),
    }
}

/// A TwoFactor ciphertext (six-field payload) written before
/// hotp/initial_counter were appended must stay readable, with the new fields
/// mapping to None (such entries are still time-based TOTP).
#[test]
fn legacy_two_factor_payload_reads_with_none_new_fields() {
    let legacy = LegacyTwoFactorData {
        secret_key: "JBSWY3DPEHPK3PXP".to_string(),
        issuer: "Example".to_string(),
        account_name: "alice".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };
    let mut payload = CredentialData::TwoFactor(TwoFactorData {
        secret_key: legacy.secret_key.clone(),
        issuer: legacy.issuer.clone(),
        account_name: legacy.account_name.clone(),
        algorithm: legacy.algorithm.clone(),
        digits: legacy.digits,
        period: legacy.period,
        hotp: None,
        initial_counter: None,
    })
    .to_bytes()
    .unwrap();
    // Chop off the two new Option fields (each Option::None costs 1 marker byte
    // in bincode) to rebuild the legacy payload
    payload.truncate(payload.len() - 2);

    let decoded = CredentialData::from_bytes(&payload).unwrap();
    let rewritten = decoded.to_bytes().unwrap();
    assert_ne!(rewritten, payload);
    match decoded {
        CredentialData::TwoFactor(data) => {
            assert_eq!(data.secret_key, "JBSWY3DPEHPK3PXP");
            assert_eq!(data.issuer, "Example");
            assert_eq!(data.account_name, "alice");
            assert_eq!(data.algorithm, "SHA1");
            assert_eq!(data.digits, 6);
            assert_eq!(data.period, 30);
            assert_eq!(data.hotp, None);
            assert_eq!(data.initial_counter, None);
        }
        other => panic!("unexpected data: {:?}", other),
    }
}

/// A ciphertext in the new shape (hotp=Some(true) + initial_counter=Some(3))
/// round-trips straight through the current struct, without the legacy branch.
#[test]
fn two_factor_hotp_payload_round_trips_directly() {
    let payload = CredentialData::TwoFactor(TwoFactorData {
        secret_key: "JBSWY3DPEHPK3PXP".to_string(),
        issuer: "Example".to_string(),
        account_name: "alice".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        hotp: Some(true),
        initial_counter: Some(3),
    })
    .to_bytes()
    .unwrap();
    let decoded = CredentialData::from_bytes(&payload).unwrap();
    match decoded {
        CredentialData::TwoFactor(data) => {
            assert_eq!(data.hotp, Some(true));
            assert_eq!(data.initial_counter, Some(3));
        }
        other => panic!("unexpected data: {:?}", other),
    }
}

/// Tag guard for the legacy TwoFactor branch: tag 6 + a truncated string
/// payload must keep its deserialization error, not get mistaken for TOTP.
#[test]
fn legacy_two_factor_tolerance_rejects_truncated_payloads() {
    let mut truncated = 6u32.to_le_bytes().to_vec();
    truncated.extend_from_slice(&13u64.to_le_bytes()); // secret_key length prefix
    truncated.extend_from_slice(b"abc"); // length claims 13, only 3 bytes present
    assert!(CredentialData::from_bytes(&truncated).is_err());
}

/// The legacy branch only accepts when "the whole payload is exactly the old
/// shape": truncated/garbage data starting with 0x08000000 must keep its
/// deserialization error, not get mistaken for a token.
#[test]
fn legacy_tolerance_rejects_truncated_and_garbage_payloads() {
    // tag 8 + the start of the five-field struct, truncated at the string length
    let mut truncated = 8u32.to_le_bytes().to_vec();
    truncated.extend_from_slice(&13u64.to_le_bytes()); // provider length prefix
    truncated.extend_from_slice(b"steam"); // length claims 13, only 5 bytes present
    assert!(CredentialData::from_bytes(&truncated).is_err());

    // tag 8 + pure garbage bytes (doesn't even cover provider's u64 length prefix)
    let mut garbage = 8u32.to_le_bytes().to_vec();
    garbage.extend_from_slice(&[0xff, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x42]);
    assert!(CredentialData::from_bytes(&garbage).is_err());

    // Garbage with a non-GameToken tag errors too (never reaches the legacy branch)
    let mut wrong_tag = 99u32.to_le_bytes().to_vec();
    wrong_tag.extend_from_slice(b"irrelevant");
    assert!(CredentialData::from_bytes(&wrong_tag).is_err());
}

/// JSON surface (export files) stays backward compatible: a GameTokenData
/// missing the new fields deserializes with the Option fields as None.
#[test]
fn game_token_json_without_new_fields_deserializes() {
    let json = r#"{
            "provider": "steam_guard",
            "secret_key": "abcdefghijklmnopqrst",
            "issuer": "Steam",
            "account_name": "alice",
            "url": "https://steamcommunity.com"
        }"#;
    let data: GameTokenData = serde_json::from_str(json).unwrap();
    assert_eq!(data.identity_secret, None);
    assert_eq!(data.device_id, None);
}

#[test]
fn bank_card_data_serde_roundtrip() {
    let card = BankCardData {
        card_number: "4111 1111 1111 1111".to_string(),
        cardholder_name: "Alice".to_string(),
        expiry_date: "09/28".to_string(),
        cvv: "123".to_string(),
        bank_name: "Test Bank".to_string(),
        card_type: "visa".to_string(),
    };

    let json = serde_json::to_string(&card).unwrap();
    let decoded: BankCardData = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.card_number, card.card_number);
    assert_eq!(decoded.cardholder_name, card.cardholder_name);
    assert_eq!(decoded.expiry_date, card.expiry_date);
    assert_eq!(decoded.cvv, card.cvv);
    assert_eq!(decoded.bank_name, card.bank_name);
    assert_eq!(decoded.card_type, card.card_type);
}

// The legacy mirror structs are private types the integration canary
// (core/tests/secret_canary.rs) can't reach, so only module-local coverage
// works: same standard — secrets → [redacted], diagnostic fields kept.

#[test]
fn legacy_debug_impls_redact_secrets() {
    let ltf = LegacyTwoFactorData {
        secret_key: "CANARY-ltf-seed-secret".to_string(),
        issuer: "Legacy Issuer".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };
    let dbg = format!("{ltf:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    assert!(dbg.contains("Legacy Issuer"), "{dbg}");

    let lgt = LegacyGameTokenData {
        provider: "steam_guard".to_string(),
        secret_key: "CANARY-lgt-secretkey-secret".to_string(),
        issuer: "Legacy Steam".to_string(),
        account_name: "gamer".to_string(),
        url: Some("https://legacy.example".to_string()),
    };
    let dbg = format!("{lgt:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    assert!(
        dbg.contains("Legacy Steam") && dbg.contains("legacy.example"),
        "{dbg}"
    );
}
