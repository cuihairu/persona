use super::*;

#[test]
fn test_blockchain_network_display() {
    assert_eq!(BlockchainNetwork::Bitcoin.to_string(), "Bitcoin");
    assert_eq!(BlockchainNetwork::Ethereum.to_string(), "Ethereum");
    assert_eq!(BlockchainNetwork::Solana.to_string(), "Solana");
    assert_eq!(BlockchainNetwork::BitcoinCash.to_string(), "Bitcoin Cash");
    assert_eq!(BlockchainNetwork::Litecoin.to_string(), "Litecoin");
    assert_eq!(BlockchainNetwork::Dogecoin.to_string(), "Dogecoin");
    assert_eq!(BlockchainNetwork::Polygon.to_string(), "Polygon");
    assert_eq!(BlockchainNetwork::Arbitrum.to_string(), "Arbitrum");
    assert_eq!(BlockchainNetwork::Optimism.to_string(), "Optimism");
    assert_eq!(
        BlockchainNetwork::BinanceSmartChain.to_string(),
        "Binance Smart Chain"
    );
    assert_eq!(
        BlockchainNetwork::Custom("Foo Chain".to_string()).to_string(),
        "Foo Chain"
    );
}

#[test]
fn test_bip_version_display() {
    assert_eq!(BipVersion::Bip32.to_string(), "32");
    assert_eq!(BipVersion::Bip44.to_string(), "44");
    assert_eq!(BipVersion::Bip49.to_string(), "49");
    assert_eq!(BipVersion::Bip84.to_string(), "84");
    assert_eq!(BipVersion::Bip86.to_string(), "86");
    assert_eq!(BipVersion::Slip44.to_string(), "SLIP-44");
}

#[test]
fn test_wallet_type_serde_roundtrip() {
    let types = vec![
        WalletType::HierarchicalDeterministic {
            bip_version: BipVersion::Bip84,
            address_count: 10,
            gap_limit: 5,
        },
        WalletType::SingleAddress,
        WalletType::MultiSignature {
            required_signatures: 2,
            total_signers: 3,
            redeem_script: Some("script".to_string()),
        },
        WalletType::Hardware {
            device_type: "Trezor".to_string(),
            device_fingerprint: None,
        },
    ];
    for wallet_type in types {
        assert_eq!(roundtrip(&wallet_type), wallet_type);
    }
}
