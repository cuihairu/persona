use super::*;

#[test]
fn test_export_mnemonic() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity_id = Uuid::new_v4();
    let password = "test_password";

    let wallet = import_from_mnemonic(
        identity_id,
        "Test Wallet".to_string(),
        test_mnemonic,
        "",
        BlockchainNetwork::Ethereum,
        None,
        1,
        password,
    )
    .unwrap();

    let exported = export_mnemonic(&wallet, password).unwrap();
    assert_eq!(exported, test_mnemonic);
}

#[test]
fn test_export_private_key_for_single_address_wallet() {
    let identity_id = Uuid::new_v4();
    let password = "test_password";
    let private_key = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

    let wallet = import_from_private_key(
        identity_id,
        "Single Address".to_string(),
        private_key,
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();

    let exported = export_private_key(&wallet, password).unwrap();
    assert_eq!(exported, private_key);
}

#[test]
fn test_export_to_wif_for_bitcoin_single_address_wallet() {
    let identity_id = Uuid::new_v4();
    let password = "test_password";
    let private_key = "1111111111111111111111111111111111111111111111111111111111111111";

    let wallet = import_from_private_key(
        identity_id,
        "BTC Wallet".to_string(),
        private_key,
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();

    let exported = export_to_wif(&wallet, password).unwrap();
    let roundtrip =
        import_from_wif(identity_id, "Roundtrip".to_string(), &exported, password).unwrap();

    assert_eq!(roundtrip.network, BlockchainNetwork::Bitcoin);
    assert_eq!(
        export_private_key(&roundtrip, password).unwrap(),
        private_key
    );
}

#[test]
fn test_export_json_includes_private_keys_for_hd_wallet() {
    let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity_id = Uuid::new_v4();
    let password = "test_password";

    let wallet = import_from_mnemonic(
        identity_id,
        "HD Wallet".to_string(),
        mnemonic,
        "",
        BlockchainNetwork::Ethereum,
        None,
        2,
        password,
    )
    .unwrap();

    let exported = export_to_json(&wallet, true, Some(password)).unwrap();
    let export: WalletExport = serde_json::from_str(&exported).unwrap();

    assert_eq!(export.mnemonic.as_deref(), Some(mnemonic));
    let private_keys = export.private_keys.expect("expected private keys");
    assert_eq!(private_keys.len(), 2);
    for address in &wallet.addresses {
        let exported_key = private_keys
            .get(&address.address)
            .expect("missing derived private key");
        assert_eq!(exported_key.len(), 64);
    }
}

#[test]
fn export_mnemonic_requires_stored_mnemonic() {
    let wallet = import_from_private_key(
        Uuid::new_v4(),
        "single".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .unwrap();
    let err = export_mnemonic(&wallet, "pw").expect_err("single-key wallets have no mnemonic");
    assert!(err.to_string().contains("Wallet has no mnemonic"));
}

#[test]
fn export_private_key_falls_back_to_any_stored_key() {
    let mut wallet = import_from_private_key(
        Uuid::new_v4(),
        "single".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .unwrap();
    // With the address list cleared, the per-address lookup misses and the
    // export falls back to the only stored key ("primary" bucket).
    wallet.addresses.clear();
    let exported = export_private_key(&wallet, "pw").unwrap();
    assert_eq!(exported, ETH_KEY);
}

#[test]
fn export_private_keys_requires_paths_for_hd_addresses() {
    let mut wallet = hd_wallet(BlockchainNetwork::Ethereum, 2);
    wallet.addresses[1].derivation_path = None;
    let err = export_private_key(&wallet, "pw")
        .expect_err("HD address without a derivation path must fail");
    assert!(err.to_string().contains("missing a derivation path"));
}

#[test]
fn export_to_wif_guardrails() {
    let password = "pw";

    // Watch-only.
    let mut watch = import_from_private_key(
        Uuid::new_v4(),
        "w".to_string(),
        ETH_KEY,
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    watch.watch_only = true;
    let err = export_to_wif(&watch, password).expect_err("watch-only must not export WIF");
    assert!(err
        .to_string()
        .contains("Watch-only wallets cannot export WIF"));

    // Non-Bitcoin network.
    let eth = import_from_private_key(
        Uuid::new_v4(),
        "e".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    let err = export_to_wif(&eth, password).expect_err("WIF is Bitcoin-only");
    assert!(err.to_string().contains("only supported for Bitcoin"));

    // HD Bitcoin wallet.
    let hd = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    let err = export_to_wif(&hd, password).expect_err("HD wallets must not export WIF");
    assert!(err.to_string().contains("single-address Bitcoin wallets"));

    // Wrong password.
    let btc = import_from_private_key(
        Uuid::new_v4(),
        "b".to_string(),
        ETH_KEY,
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    assert!(export_to_wif(&btc, "wrong").is_err());
}

#[test]
fn export_xpub_presence() {
    let hd = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    let xpub = export_xpub(&hd).unwrap();
    assert!(xpub.starts_with("xpub"));

    let single = import_from_private_key(
        Uuid::new_v4(),
        "s".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .unwrap();
    let err = export_xpub(&single).expect_err("single-key wallets have no xpub");
    assert!(err.to_string().contains("no extended public key"));
}

#[test]
fn export_to_json_requires_password_for_private_data() {
    let wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    let err = export_to_json(&wallet, true, None)
        .expect_err("private export without a password must fail");
    assert!(err.to_string().contains("Password required"));

    // Public-only export needs no password and omits secrets.
    let public = export_to_json(&wallet, false, None).unwrap();
    let parsed: WalletExport = serde_json::from_str(&public).unwrap();
    assert!(parsed.mnemonic.is_none());
    assert!(parsed.private_keys.is_none());
    assert_eq!(parsed.addresses.len(), 1);
}

#[test]
fn export_private_key_fails_for_watch_only_wallet() {
    // Watch-only wallets export no keys at all, so the per-address lookup
    // and the fallback both miss.
    let mut wallet = hd_wallet(BlockchainNetwork::Ethereum, 1);
    wallet.watch_only = true;
    let err =
        export_private_key(&wallet, "pw").expect_err("watch-only wallets expose no private keys");
    assert!(err
        .to_string()
        .contains("does not contain an exportable private key"));
}
