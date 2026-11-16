use super::*;

#[test]
fn test_wallet_address_serde_roundtrip() {
    let addresses = vec![
        WalletAddress {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            address_type: AddressType::P2PKH,
            derivation_path: Some("m/44'/0'/0'/0/0".to_string()),
            index: 0,
            used: true,
            balance: Some("0.5".to_string()),
            last_activity: Some(Utc::now()),
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "addr".to_string(),
            address_type: AddressType::P2SH,
            derivation_path: None,
            index: 1,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "addr".to_string(),
            address_type: AddressType::P2WPKH,
            derivation_path: None,
            index: 2,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "addr".to_string(),
            address_type: AddressType::P2TR,
            derivation_path: None,
            index: 3,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "0x0000000000000000000000000000000000000000".to_string(),
            address_type: AddressType::Ethereum,
            derivation_path: None,
            index: 4,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "sol-addr".to_string(),
            address_type: AddressType::Solana,
            derivation_path: None,
            index: 5,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
        WalletAddress {
            address: "custom-addr".to_string(),
            address_type: AddressType::Custom("Bech32".to_string()),
            derivation_path: None,
            index: 6,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        },
    ];
    for address in addresses {
        assert_eq!(roundtrip(&address), address);
    }
}

#[test]
fn test_wallet_metadata_defaults() {
    let metadata = WalletMetadata::default();
    assert!(metadata.tags.is_empty());
    assert!(metadata.notes.is_none());
    assert!(metadata.platform.is_none());
    assert!(metadata.purpose.is_none());
    assert!(metadata.associated_services.is_empty());
    assert!(metadata.backup_info.is_none());
    assert!(metadata.custom_data.is_empty());

    let settings = WalletSecuritySettings::default();
    assert!(!settings.require_biometric);
    assert!(!settings.require_password);
    assert!(settings.max_unverified_amount.is_none());
    assert!(settings.require_2fa_above.is_none());
    assert!(!settings.transaction_notifications);
    assert!(!settings.address_book_only);
    assert!(settings.address_whitelist.is_empty());
    assert!(settings.address_blacklist.is_empty());
    assert!(settings.daily_transaction_limit.is_none());
    assert!(settings.weekly_transaction_limit.is_none());
    assert!(settings.monthly_transaction_limit.is_none());
    assert!(settings.spending_frozen_until.is_none());
    assert!(settings.spending_frozen_with_recovery.is_none());
}
