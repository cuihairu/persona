use super::*;

#[test]
fn test_wallet_creation() {
    let identity_id = Uuid::new_v4();
    let wallet = CryptoWallet::new(
        identity_id,
        "Test Wallet".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4], // Encrypted private key placeholder
    );

    assert_eq!(wallet.name, "Test Wallet");
    assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
    assert!(!wallet.watch_only);
    assert_eq!(wallet.security_level, WalletSecurityLevel::Medium);
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_watch_only_wallet() {
    let identity_id = Uuid::new_v4();
    let wallet = CryptoWallet::new_watch_only(
        identity_id,
        "Watch Only".to_string(),
        BlockchainNetwork::Ethereum,
        "xpub...".to_string(),
    );

    assert_eq!(wallet.name, "Watch Only");
    assert!(wallet.watch_only);
    assert_eq!(wallet.security_level, WalletSecurityLevel::Low);
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_wallet_security_score() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );
    wallet.security_level = WalletSecurityLevel::High;

    let score = wallet.security_score();
    assert!(score > 70); // Should be quite secure

    wallet.security_level = WalletSecurityLevel::Maximum;
    let higher_score = wallet.security_score();
    assert!(higher_score > score); // Should be even more secure
}

#[test]
fn test_recommended_derivation_path() {
    let btc_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Bitcoin, 0);
    assert_eq!(btc_path, "m/44'/0'/0'/0");

    let eth_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Ethereum, 1);
    assert_eq!(eth_path, "m/44'/60'/1'/0");

    let sol_path = CryptoWallet::recommended_derivation_path(&BlockchainNetwork::Solana, 0);
    assert_eq!(sol_path, "m/44'/501'/0'/0'");
}

#[test]
fn test_address_management() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    let address = WalletAddress {
        address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        address_type: AddressType::P2PKH,
        derivation_path: None,
        index: 0,
        used: false,
        balance: None,
        last_activity: None,
        metadata: HashMap::new(),
        created_at: Utc::now(),
    };

    wallet.add_address(address);
    assert_eq!(wallet.addresses.len(), 1);
    assert!(wallet.get_unused_addresses().len() == 1);

    let mark_used = wallet.mark_address_used("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    assert!(mark_used);
    assert!(wallet.get_unused_addresses().is_empty());
}

#[test]
fn test_wallet_validation() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "".to_string(), // Empty name
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    assert!(wallet.validate().is_err());

    wallet.name = "Valid Wallet".to_string();
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_multi_signature_validation() {
    let wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Multi-sig".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::MultiSignature {
            required_signatures: 3,
            total_signers: 2, // Invalid: required > total
            redeem_script: None,
        },
        vec![1, 2, 3, 4],
    );

    assert!(wallet.validate().is_err());
}

#[test]
fn test_get_address_by_index() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    for index in [0u32, 5] {
        wallet.add_address(WalletAddress {
            address: format!("addr-{}", index),
            address_type: AddressType::P2PKH,
            derivation_path: None,
            index,
            used: false,
            balance: None,
            last_activity: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        });
    }

    assert_eq!(
        wallet.get_address_by_index(5).map(|a| a.address.as_str()),
        Some("addr-5")
    );
    assert!(wallet.get_address_by_index(42).is_none());
}

#[test]
fn test_mark_address_used_missing_returns_false() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    assert!(!wallet.mark_address_used("unknown-address"));
}

#[test]
fn test_security_score_components() {
    // Default: Medium (+10) on a base of 50.
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );
    assert_eq!(wallet.security_score(), 60);

    // Low level subtracts 10.
    wallet.security_level = WalletSecurityLevel::Low;
    assert_eq!(wallet.security_score(), 40);

    // Maximum (+35) combined with watch-only (-20).
    wallet.security_level = WalletSecurityLevel::Maximum;
    wallet.watch_only = true;
    assert_eq!(wallet.security_score(), 65);
    wallet.watch_only = false;

    // High (+25) plus encrypted mnemonic (+10).
    wallet.security_level = WalletSecurityLevel::High;
    wallet.encrypted_mnemonic = Some(vec![9, 9]);
    assert_eq!(wallet.security_score(), 85);

    // Hardware wallet (+10) on top of Medium and mnemonic.
    wallet.security_level = WalletSecurityLevel::Medium;
    wallet.wallet_type = WalletType::Hardware {
        device_type: "Ledger Nano S".to_string(),
        device_fingerprint: Some("fp".to_string()),
    };
    assert_eq!(wallet.security_score(), 80);

    // Backup info present but unverified adds nothing.
    wallet.security_level = WalletSecurityLevel::High;
    wallet.encrypted_mnemonic = None;
    wallet.wallet_type = WalletType::SingleAddress;
    wallet.metadata.backup_info = Some(WalletBackupInfo {
        backup_location: BackupLocation::PaperBackup,
        last_backup_at: None,
        backup_verified: false,
        backup_copies: 1,
        recovery_phrase_backup_method: None,
    });
    assert_eq!(wallet.security_score(), 75);
}

#[test]
fn test_security_score_clamps_at_100() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: None,
        },
        vec![1, 2, 3, 4],
    );
    wallet.security_level = WalletSecurityLevel::Maximum;
    wallet.encrypted_mnemonic = Some(vec![1]);
    wallet.metadata.backup_info = Some(WalletBackupInfo {
        backup_location: BackupLocation::MetalBackup,
        last_backup_at: Some(Utc::now()),
        backup_verified: true,
        backup_copies: 2,
        recovery_phrase_backup_method: Some(RecoveryPhraseBackupMethod::Metal),
    });

    // 50 + 35 + 10 + 15 + 5 = 115, clamped to 100.
    assert_eq!(wallet.security_score(), 100);
}

#[test]
fn test_validate_hot_wallet_without_private_key() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        Vec::new(),
    );

    assert!(wallet.validate().is_err());

    wallet.encrypted_private_key = vec![1];
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_validate_watch_only_without_xpub() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );
    wallet.watch_only = true;
    wallet.encrypted_private_key.clear();

    assert!(wallet.validate().is_err());

    wallet.extended_public_key = Some("xpub661MyMw".to_string());
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_validate_multisig_zero_required_signatures() {
    let wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Multi-sig".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::MultiSignature {
            required_signatures: 0,
            total_signers: 3,
            redeem_script: None,
        },
        vec![1, 2, 3, 4],
    );

    assert!(wallet.validate().is_err());
}

#[test]
fn test_validate_multisig_valid_configuration() {
    let wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Multi-sig".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: Some("script".to_string()),
        },
        vec![1, 2, 3, 4],
    );

    assert!(wallet.validate().is_ok());
}

#[test]
fn test_validate_derivation_path_format() {
    let mut wallet = CryptoWallet::new(
        Uuid::new_v4(),
        "Test".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    wallet.derivation_path = Some("44'/0'/0'/0".to_string());
    assert!(wallet.validate().is_err());

    wallet.derivation_path = Some("m/44'/0'/0'/0".to_string());
    assert!(wallet.validate().is_ok());
}

#[test]
fn test_recommended_derivation_path_all_networks() {
    let cases = [
        (BlockchainNetwork::BitcoinCash, "m/44'/145'/7'/0"),
        (BlockchainNetwork::Litecoin, "m/44'/2'/7'/0"),
        (BlockchainNetwork::Dogecoin, "m/44'/3'/7'/0"),
        (BlockchainNetwork::Polygon, "m/44'/137'/7'/0"),
        (BlockchainNetwork::Arbitrum, "m/44'/42161'/7'/0"),
        (BlockchainNetwork::Optimism, "m/44'/10'/7'/0"),
        (BlockchainNetwork::BinanceSmartChain, "m/44'/714'/7'/0"),
        (
            BlockchainNetwork::Custom("MyChain".to_string()),
            "m/44'/0'/7'/0",
        ),
    ];
    for (network, expected) in cases {
        assert_eq!(
            CryptoWallet::recommended_derivation_path(&network, 7),
            expected
        );
    }
}

#[test]
fn test_wallet_serde_roundtrip() {
    let mut wallet = CryptoWallet::new_watch_only(
        Uuid::new_v4(),
        "Roundtrip".to_string(),
        BlockchainNetwork::Ethereum,
        "xpub-roundtrip".to_string(),
    );
    wallet.description = Some("kept".to_string());
    wallet.derivation_path = Some("m/44'/60'/0'/0".to_string());
    wallet.encrypted_mnemonic = Some(vec![7, 8, 9]);
    wallet.metadata.tags = vec!["cold".to_string()];
    wallet.metadata.notes = Some("note".to_string());
    wallet.metadata.platform = Some("Ledger".to_string());
    wallet.metadata.purpose = Some("savings".to_string());
    wallet.metadata.associated_services = vec!["dapp.example".to_string()];
    wallet.metadata.backup_info = Some(WalletBackupInfo {
        backup_location: BackupLocation::SplitStorage {
            required_shares: 2,
            total_shares: 3,
        },
        last_backup_at: Some(Utc::now()),
        backup_verified: true,
        backup_copies: 3,
        recovery_phrase_backup_method: Some(RecoveryPhraseBackupMethod::SplitLocations),
    });
    wallet.metadata.security_settings = WalletSecuritySettings {
        require_biometric: true,
        require_password: true,
        max_unverified_amount: Some("0.1".to_string()),
        require_2fa_above: Some("1.0".to_string()),
        transaction_notifications: true,
        address_book_only: true,
        address_whitelist: vec!["0xabc".to_string()],
        address_blacklist: vec!["0xdead".to_string()],
        daily_transaction_limit: Some("2".to_string()),
        weekly_transaction_limit: Some("10".to_string()),
        monthly_transaction_limit: Some("40".to_string()),
        spending_frozen_until: Some(Utc::now()),
        spending_frozen_with_recovery: Some("recover".to_string()),
    };
    wallet
        .metadata
        .custom_data
        .insert("k".to_string(), "v".to_string());

    let decoded: CryptoWallet = roundtrip(&wallet);
    assert_eq!(decoded, wallet);
}
