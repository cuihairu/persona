use super::export_requires_password;
use persona_core::crypto::ExportFormat;

#[test]
fn parse_network_accepts_every_alias_case_insensitively() {
    let cases = [
        ("bitcoin", "BlockchainNetwork::Bitcoin"),
        ("btc", ""),
        ("ethereum", ""),
        ("eth", ""),
        ("solana", ""),
        ("sol", ""),
        ("bitcoin-cash", ""),
        ("bch", ""),
        ("litecoin", ""),
        ("ltc", ""),
        ("dogecoin", ""),
        ("doge", ""),
        ("polygon", ""),
        ("matic", ""),
        ("arbitrum", ""),
        ("arb", ""),
        ("optimism", ""),
        ("op", ""),
        ("binance", ""),
        ("bsc", ""),
        ("bnb", ""),
    ];
    for (input, _) in &cases {
        let parsed = super::parse_network(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        let reparsed = super::parse_network(&input.to_uppercase())
            .unwrap_or_else(|e| panic!("{input} upper: {e}"));
        assert_eq!(parsed, reparsed, "{input} must be case insensitive");
    }

    // Spot-check the canonical mappings.
    assert_eq!(
        super::parse_network("btc").unwrap(),
        persona_core::models::wallet::BlockchainNetwork::Bitcoin
    );
    assert_eq!(
        super::parse_network("MATIC").unwrap(),
        persona_core::models::wallet::BlockchainNetwork::Polygon
    );
    assert_eq!(
        super::parse_network("bnb").unwrap(),
        persona_core::models::wallet::BlockchainNetwork::BinanceSmartChain
    );
}

#[test]
fn parse_network_rejects_unknown_names() {
    let err = super::parse_network("moon").expect_err("unknown network must fail");
    assert!(err.to_string().contains("Unsupported network: moon"));
    assert!(super::parse_network("").is_err());
}

#[test]
fn parse_wallet_type_covers_every_variant() {
    use persona_core::models::wallet::{BipVersion, WalletType};

    assert_eq!(
        super::parse_wallet_type("single", None, None).unwrap(),
        WalletType::SingleAddress
    );
    assert_eq!(
        super::parse_wallet_type("Single-Address", None, None).unwrap(),
        WalletType::SingleAddress
    );
    assert_eq!(
        super::parse_wallet_type("multisig", None, None).unwrap(),
        WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: None,
        }
    );
    assert_eq!(
        super::parse_wallet_type("multi-signature", None, None).unwrap(),
        super::parse_wallet_type("multisig", None, None).unwrap()
    );
    assert_eq!(
        super::parse_wallet_type("hardware", None, None).unwrap(),
        WalletType::Hardware {
            device_type: "Generic".to_string(),
            device_fingerprint: None,
        }
    );
    assert_eq!(
        super::parse_wallet_type("HW", None, None).unwrap(),
        super::parse_wallet_type("hardware", None, None).unwrap()
    );

    // HD: every supported BIP version, plus defaults and custom counts.
    for (bip, expected) in [
        (Some(32), BipVersion::Bip32),
        (Some(44), BipVersion::Bip44),
        (Some(49), BipVersion::Bip49),
        (Some(84), BipVersion::Bip84),
        (Some(86), BipVersion::Bip86),
    ] {
        assert_eq!(
            super::parse_wallet_type("hd", bip, Some(7)).unwrap(),
            WalletType::HierarchicalDeterministic {
                bip_version: expected,
                address_count: 7,
                gap_limit: 20,
            }
        );
    }
    assert_eq!(
        super::parse_wallet_type("hierarchical", None, None).unwrap(),
        WalletType::HierarchicalDeterministic {
            bip_version: BipVersion::Bip44,
            address_count: 20,
            gap_limit: 20,
        }
    );
}

#[test]
fn parse_wallet_type_rejects_unknown_type_and_bip() {
    let err =
        super::parse_wallet_type("paper", None, None).expect_err("unknown wallet type must fail");
    assert!(err.to_string().contains("Unsupported wallet type: paper"));

    let err =
        super::parse_wallet_type("hd", Some(33), None).expect_err("unknown BIP version must fail");
    assert!(err.to_string().contains("Unsupported BIP version: 33"));
}

#[test]
fn parse_address_type_accepts_known_and_rejects_unknown() {
    use persona_core::models::wallet::AddressType;

    assert_eq!(
        super::parse_address_type("P2PKH").unwrap(),
        AddressType::P2PKH
    );
    assert_eq!(
        super::parse_address_type("p2sh").unwrap(),
        AddressType::P2SH
    );
    assert_eq!(
        super::parse_address_type("p2wpkh").unwrap(),
        AddressType::P2WPKH
    );
    assert_eq!(
        super::parse_address_type("p2tr").unwrap(),
        AddressType::P2TR
    );
    assert_eq!(
        super::parse_address_type("ETH").unwrap(),
        AddressType::Ethereum
    );
    assert_eq!(
        super::parse_address_type("sol").unwrap(),
        AddressType::Solana
    );

    let err = super::parse_address_type("bech32").expect_err("unknown type must fail");
    assert!(err.to_string().contains("Unsupported address type: bech32"));
}

#[test]
fn format_wallet_type_renders_every_variant() {
    use persona_core::models::wallet::{BipVersion, WalletType};

    assert_eq!(
        super::format_wallet_type(&WalletType::SingleAddress),
        "Single"
    );
    assert_eq!(
        super::format_wallet_type(&WalletType::HierarchicalDeterministic {
            bip_version: BipVersion::Bip44,
            address_count: 5,
            gap_limit: 20,
        }),
        "HD (BIP-44, 5 addrs)"
    );
    // Zero address count suppresses the suffix.
    assert_eq!(
        super::format_wallet_type(&WalletType::HierarchicalDeterministic {
            bip_version: BipVersion::Bip86,
            address_count: 0,
            gap_limit: 20,
        }),
        "HD (BIP-86)"
    );
    assert_eq!(
        super::format_wallet_type(&WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: None,
        }),
        "Multi-sig (2/3)"
    );
    assert_eq!(
        super::format_wallet_type(&WalletType::Hardware {
            device_type: "Ledger".to_string(),
            device_fingerprint: None,
        }),
        "Hardware (Ledger)"
    );
}

#[test]
fn format_address_type_renders_every_variant_including_custom() {
    use persona_core::models::wallet::AddressType;

    assert_eq!(super::format_address_type(&AddressType::P2PKH), "P2PKH");
    assert_eq!(super::format_address_type(&AddressType::P2SH), "P2SH");
    assert_eq!(super::format_address_type(&AddressType::P2WPKH), "P2WPKH");
    assert_eq!(super::format_address_type(&AddressType::P2TR), "P2TR");
    assert_eq!(super::format_address_type(&AddressType::Ethereum), "ETH");
    assert_eq!(super::format_address_type(&AddressType::Solana), "SOL");
    assert_eq!(
        super::format_address_type(&AddressType::Custom("taproot-test".to_string())),
        "taproot-test"
    );
}

#[test]
fn parse_wallet_security_level_accepts_aliases_and_rejects_unknown() {
    use persona_core::models::wallet::WalletSecurityLevel;

    assert_eq!(
        super::parse_wallet_security_level("maximum").unwrap(),
        WalletSecurityLevel::Maximum
    );
    assert_eq!(
        super::parse_wallet_security_level("MAX").unwrap(),
        WalletSecurityLevel::Maximum
    );
    assert_eq!(
        super::parse_wallet_security_level("High").unwrap(),
        WalletSecurityLevel::High
    );
    assert_eq!(
        super::parse_wallet_security_level("hi").unwrap(),
        WalletSecurityLevel::High
    );
    assert_eq!(
        super::parse_wallet_security_level("medium").unwrap(),
        WalletSecurityLevel::Medium
    );
    assert_eq!(
        super::parse_wallet_security_level("med").unwrap(),
        WalletSecurityLevel::Medium
    );
    assert_eq!(
        super::parse_wallet_security_level("mid").unwrap(),
        WalletSecurityLevel::Medium
    );
    assert_eq!(
        super::parse_wallet_security_level("low").unwrap(),
        WalletSecurityLevel::Low
    );
    assert_eq!(
        super::parse_wallet_security_level("LO").unwrap(),
        WalletSecurityLevel::Low
    );

    let err = super::parse_wallet_security_level("ultra").expect_err("unknown level must fail");
    assert!(err.to_string().contains("Invalid security level: ultra"));
    assert!(err.to_string().contains("low, medium, high, maximum"));
}

#[test]
fn mnemonic_export_requires_password_without_include_private() {
    assert!(export_requires_password(ExportFormat::Mnemonic, false));
}

#[test]
fn private_key_export_requires_password_without_include_private() {
    assert!(export_requires_password(ExportFormat::PrivateKey, false));
}

#[test]
fn wif_export_requires_password_without_include_private() {
    assert!(export_requires_password(ExportFormat::Wif, false));
}

#[test]
fn keystore_export_requires_password_without_include_private() {
    assert!(export_requires_password(ExportFormat::Keystore, false));
}

#[test]
fn json_export_requires_password_only_when_private_data_is_requested() {
    assert!(!export_requires_password(ExportFormat::Json, false));
    assert!(export_requires_password(ExportFormat::Json, true));
}

#[test]
fn xpub_export_does_not_require_password() {
    assert!(!export_requires_password(ExportFormat::Xpub, false));
}
