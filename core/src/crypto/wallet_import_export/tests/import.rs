use super::*;

#[test]
fn test_import_from_mnemonic() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity_id = Uuid::new_v4();
    let password = "test_password";

    let wallet = import_from_mnemonic(
        identity_id,
        "Test Wallet".to_string(),
        test_mnemonic,
        "",
        BlockchainNetwork::Bitcoin,
        None,
        5,
        password,
    )
    .unwrap();

    assert_eq!(wallet.name, "Test Wallet");
    assert_eq!(wallet.addresses.len(), 5);
    assert_eq!(wallet.derivation_path.as_deref(), Some("m/44'/0'/0'/0"));
    assert!(wallet.extended_public_key.is_some());
    assert!(wallet.encrypted_mnemonic.is_some());
    assert_eq!(
        wallet
            .addresses
            .first()
            .and_then(|address| address.derivation_path.as_deref()),
        Some("m/44'/0'/0'/0/0")
    );
    assert_eq!(
        wallet
            .addresses
            .get(1)
            .and_then(|address| address.derivation_path.as_deref()),
        Some("m/44'/0'/0'/0/1")
    );
}

#[test]
fn test_import_from_mnemonic_solana() {
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "test_password";

    let mut wallet = import_from_mnemonic(
        Uuid::new_v4(),
        "sol".to_string(),
        test_mnemonic,
        "",
        BlockchainNetwork::Solana,
        None,
        3,
        password,
    )
    .unwrap();

    // Solana address paths follow the hardened leaf convention
    assert_eq!(
        wallet
            .addresses
            .first()
            .and_then(|a| a.derivation_path.as_deref()),
        Some("m/44'/501'/0'/0'")
    );
    assert_eq!(
        wallet
            .addresses
            .get(2)
            .and_then(|a| a.derivation_path.as_deref()),
        Some("m/44'/501'/0'/2'")
    );
    for address in &wallet.addresses {
        assert!(crate::crypto::address_generator::validate_solana_address(
            &address.address
        ));
    }

    // The signing key derived for the first address must reproduce it
    let first_address = wallet.addresses[0].address.clone();
    let key = signing_key_for_address(&wallet, password, &first_address).unwrap();
    let WalletSigningKey::Ed25519(ed_key) = key else {
        panic!("expected Ed25519 signing key");
    };
    let derived_address =
        crate::crypto::address_generator::generate_solana_address(&ed_key.public_bytes()).unwrap();
    assert_eq!(derived_address, first_address);

    // A different address must derive a different key
    let second_address = wallet.addresses[1].address.clone();
    let key2 = signing_key_for_address(&wallet, password, &second_address).unwrap();
    let WalletSigningKey::Ed25519(ed_key2) = key2 else {
        panic!("expected Ed25519 signing key");
    };
    assert_ne!(ed_key.public_bytes(), ed_key2.public_bytes());

    // Wrong password must not decrypt
    assert!(signing_key_for_address(&wallet, "wrong", &first_address).is_err());

    // Cleanup sensitive clone we made for assertions
    wallet.addresses.clear();
}

#[test]
fn test_import_from_private_key_solana() {
    let secret = [9u8; 32];
    let wallet = import_from_private_key(
        Uuid::new_v4(),
        "sol-single".to_string(),
        &hex::encode(secret),
        BlockchainNetwork::Solana,
        "pw",
    )
    .unwrap();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let expected = crate::crypto::address_generator::generate_solana_address(
        &signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(wallet.addresses[0].address, expected);
}

// 深审 Major 回归（2026-11-13）：单密钥 Solana 钱包存的是原始 32 字节
// Ed25519 种子，签名路径此前无条件按 64 字节 SLIP-0010 根节点解析，
// 导入成功却永远无法签名。
#[test]
fn single_address_solana_wallet_signs_with_raw_seed() {
    let mut wallet = import_from_private_key(
        Uuid::new_v4(),
        "sol-single".to_string(),
        &hex::encode([9u8; 32]),
        BlockchainNetwork::Solana,
        "pw",
    )
    .unwrap();

    let address = wallet.addresses[0].address.clone();
    let key = signing_key_for_address(&wallet, "pw", &address).unwrap();
    let WalletSigningKey::Ed25519(ed) = key else {
        panic!("expected Ed25519 signing key");
    };
    // 签名密钥必须复现自身地址（此前解析错位，公钥对不上地址）
    let derived =
        crate::crypto::address_generator::generate_solana_address(&ed.public_bytes()).unwrap();
    assert_eq!(derived, address);
    let sig = ed.sign(b"payload");
    assert!(ed.verify(b"payload", &sig));

    // 错误密码不得解密
    assert!(signing_key_for_address(&wallet, "wrong", &address).is_err());

    wallet.addresses.clear();
}

// 深审 Major 回归（2026-11-13）：0xFF…FF 不是合法 secp256k1 标量
//（≥ 曲线阶 n），但任何 32 字节都是合法 Ed25519 种子——导入侧的
// secp256k1 校验不得对 Solana 生效。
#[test]
fn solana_seed_import_skips_secp256k1_validation() {
    let wallet = import_from_private_key(
        Uuid::new_v4(),
        "sol-ff".to_string(),
        &hex::encode([0xff_u8; 32]),
        BlockchainNetwork::Solana,
        "pw",
    )
    .expect("any 32 bytes are a valid Ed25519 seed");

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xff_u8; 32]);
    let expected = crate::crypto::address_generator::generate_solana_address(
        &signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(wallet.addresses[0].address, expected);
}

// 深审 Major 回归（2026-11-13）：Solana HD 导出私钥此前按 secp256k1
// XPrv 解析 Ed25519 根节点，必然报错——现在按 SLIP-0010 逐地址派生导出，
// 且整包 JSON 可无损还原（恢复一致性核对放行）。
#[test]
fn solana_hd_wallet_export_roundtrips_private_keys() {
    let password = "pw";
    let wallet = import_from_mnemonic(
        Uuid::new_v4(),
        "sol-hd".to_string(),
        TEST_PHRASE,
        "",
        BlockchainNetwork::Solana,
        None,
        2,
        password,
    )
    .unwrap();

    let exported = export_to_json(&wallet, true, Some(password)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&exported).unwrap();
    let keys = value["private_keys"]
        .as_object()
        .expect("solana HD export must carry private keys");
    assert_eq!(keys.len(), 2);

    // 每把导出密钥必须是 32 字节 hex，且重派生公钥等于其地址
    for (addr, key_hex) in keys {
        let secret: [u8; 32] = hex::decode(key_hex.as_str().unwrap())
            .unwrap()
            .as_slice()
            .try_into()
            .expect("child secret must be 32 bytes");
        let key = crate::crypto::wallet_crypto::Ed25519Key::from_parts(secret, [0u8; 32]).unwrap();
        let derived =
            crate::crypto::address_generator::generate_solana_address(&key.public_bytes()).unwrap();
        assert_eq!(&derived, addr);
    }

    // JSON 恢复：地址逐一一致
    let restored = import_from_json(Uuid::new_v4(), None, &exported, password).unwrap();
    let restored_addrs: Vec<&str> = restored
        .addresses
        .iter()
        .map(|a| a.address.as_str())
        .collect();
    let declared: Vec<&str> = wallet
        .addresses
        .iter()
        .map(|a| a.address.as_str())
        .collect();
    assert_eq!(restored_addrs, declared);
}

#[test]
fn test_parse_wif() {
    // Canonical mainnet compressed WIF for private key 1 (well-known pair).
    let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    let parsed = parse_wif(wif).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(parsed.secret, one);
    assert!(parsed.compressed);
    assert!(!parsed.testnet);

    // Uncompressed variant drops the 0x01 suffix byte.
    let wif_uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let parsed = parse_wif(wif_uncompressed).unwrap();
    assert_eq!(
        parsed.secret,
        hex::decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
            .unwrap()
            .as_slice()
    );
    assert!(!parsed.compressed);

    // Checksum tampering must be rejected.
    let mut bad = wif.to_string();
    bad.replace_range(0..1, if wif.starts_with('K') { "L" } else { "K" });
    assert!(parse_wif(&bad).is_err());

    // Invalid version byte (address instead of key).
    assert!(parse_wif("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
}

#[test]
fn test_import_from_private_key_accepts_wif() {
    let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    let wallet = import_from_private_key(
        Uuid::new_v4(),
        "btc-wif".to_string(),
        wif,
        BlockchainNetwork::Bitcoin,
        "pw",
    )
    .unwrap();

    // Key 0x01..01 compressed -> known P2WPKH address derived from
    // pubkey 0279BE667E... (the generator point).
    assert_eq!(wallet.addresses.len(), 1);
    assert!(wallet.addresses[0].address.starts_with("bc1q"));

    // Signing must round-trip back to the same secret (key = 1).
    let key = signing_key_for_address(&wallet, "pw", &wallet.addresses[0].address).unwrap();
    let WalletSigningKey::Secp256k1(signing) = key else {
        panic!("expected secp256k1");
    };
    let mut one = [0u8; 32];
    one[31] = 1;
    let expected = k256::ecdsa::SigningKey::from_bytes(&one.into()).unwrap();
    assert_eq!(
        signing.to_bytes().as_slice(),
        expected.to_bytes().as_slice()
    );

    // WIF is Bitcoin-specific.
    assert!(import_from_private_key(
        Uuid::new_v4(),
        "eth-wif".to_string(),
        wif,
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .is_err());
}

// 深审 Major 回归（2026-11-13）：import_from_private_key 的 WIF 回退入口
// 此前绕过 import_from_wif 的 testnet/非压缩两道检查。
#[test]
fn import_from_private_key_wif_fallback_enforces_wif_contract() {
    // Testnet WIF: version byte 0xef, compressed suffix.
    let mut payload = vec![0xefu8];
    payload.extend_from_slice(&[0x22u8; 32]);
    payload.push(0x01);
    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    let testnet_wif = bs58::encode(payload).into_string();

    let err = import_from_private_key(
        Uuid::new_v4(),
        "t".to_string(),
        &testnet_wif,
        BlockchainNetwork::Bitcoin,
        "pw",
    )
    .expect_err("testnet WIF must be rejected through the fallback too");
    assert!(err.to_string().contains("testnet WIF is not supported"));

    // Uncompressed mainnet WIF (no 0x01 suffix).
    let uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let err = import_from_private_key(
        Uuid::new_v4(),
        "u".to_string(),
        uncompressed,
        BlockchainNetwork::Bitcoin,
        "pw",
    )
    .expect_err("uncompressed WIF must be rejected through the fallback too");
    assert!(err
        .to_string()
        .contains("Uncompressed WIF is not supported"));
}

#[test]
fn test_import_from_wif() {
    let identity_id = Uuid::new_v4();
    let password = "test_password";
    let private_key = [0x11u8; 32];
    let wif = encode_compressed_mainnet_wif(&private_key);

    let wallet = import_from_wif(identity_id, "WIF Wallet".to_string(), &wif, password).unwrap();

    assert_eq!(wallet.name, "WIF Wallet");
    assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
    assert_eq!(wallet.addresses.len(), 1);
}

#[test]
fn test_import_from_json_roundtrip_for_hd_wallet() {
    let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let identity_id = Uuid::new_v4();
    let password = "test_password";

    let wallet = import_from_mnemonic(
        identity_id,
        "HD Wallet".to_string(),
        mnemonic,
        "",
        BlockchainNetwork::Bitcoin,
        None,
        3,
        password,
    )
    .unwrap();

    let exported = export_to_json(&wallet, true, Some(password)).unwrap();
    let imported = import_from_json(
        Uuid::new_v4(),
        Some("Imported HD".to_string()),
        &exported,
        password,
    )
    .unwrap();

    assert_eq!(imported.name, "Imported HD");
    assert_eq!(imported.network, BlockchainNetwork::Bitcoin);
    assert_eq!(imported.addresses.len(), 3);
    assert_eq!(export_mnemonic(&imported, password).unwrap(), mnemonic);
}

#[test]
fn test_import_from_json_roundtrip_for_single_address_wallet() {
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

    let exported = export_to_json(&wallet, true, Some(password)).unwrap();
    let imported = import_from_json(Uuid::new_v4(), None, &exported, password).unwrap();

    assert_eq!(imported.name, "Single Address");
    assert_eq!(imported.network, BlockchainNetwork::Ethereum);
    assert_eq!(
        export_private_key(&imported, password).unwrap(),
        private_key
    );
}

#[test]
fn import_from_mnemonic_rejects_invalid_phrase() {
    let err = import_from_mnemonic(
        Uuid::new_v4(),
        "bad".to_string(),
        "not a valid mnemonic at all",
        "",
        BlockchainNetwork::Bitcoin,
        None,
        1,
        "pw",
    )
    .expect_err("invalid mnemonic must be rejected");
    assert!(err.to_string().contains("Invalid mnemonic"));
}

#[test]
fn import_from_mnemonic_honors_explicit_derivation_path() {
    let wallet = import_from_mnemonic(
        Uuid::new_v4(),
        "custom path".to_string(),
        TEST_PHRASE,
        "passphrase",
        BlockchainNetwork::Bitcoin,
        Some("m/84'/0'/7'/0".to_string()),
        2,
        "pw",
    )
    .unwrap();
    assert_eq!(wallet.derivation_path.as_deref(), Some("m/84'/0'/7'/0"));
    assert_eq!(
        wallet.addresses[0].derivation_path.as_deref(),
        Some("m/84'/0'/7'/0/0")
    );
    // A BIP-84 path yields bech32 (P2WPKH) addresses.
    assert!(wallet.addresses[0].address.starts_with("bc1q"));
}

#[test]
fn signing_key_for_address_rejects_corrupt_key_payload() {
    let mut wallet = hd_wallet(BlockchainNetwork::Bitcoin, 1);
    wallet.encrypted_private_key = b"corrupt".to_vec();
    let err = expect_sign_err(
        signing_key_for_address(&wallet, "pw", "anything"),
        "corrupt payload must be rejected",
    );
    assert!(err.to_string().contains("Deserialization error"));
}

#[test]
fn import_from_private_key_rejects_bad_lengths_and_formats() {
    // 31-byte hex payload.
    let err = import_from_private_key(
        Uuid::new_v4(),
        "short".to_string(),
        &"ab".repeat(31),
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .expect_err("31-byte key must be rejected");
    assert!(err.to_string().contains("Private key must be 32 bytes"));

    // 33-byte hex payload.
    assert!(import_from_private_key(
        Uuid::new_v4(),
        "long".to_string(),
        &"ab".repeat(33),
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .is_err());

    // Neither hex nor WIF, on a non-Bitcoin network.
    let err = import_from_private_key(
        Uuid::new_v4(),
        "junk".to_string(),
        "zzz-not-hex",
        BlockchainNetwork::Ethereum,
        "pw",
    )
    .expect_err("non-hex must be rejected outside Bitcoin");
    assert!(err.to_string().contains("neither valid hex nor a WIF"));

    // On Bitcoin it falls through to WIF parsing, which also fails.
    let err = import_from_private_key(
        Uuid::new_v4(),
        "junk-btc".to_string(),
        "zzz-not-hex",
        BlockchainNetwork::Bitcoin,
        "pw",
    )
    .expect_err("garbage input must fail WIF parsing too");
    assert!(err.to_string().contains("Invalid WIF"));
}

#[test]
fn import_from_private_key_rejects_unsupported_networks() {
    let err = import_from_private_key(
        Uuid::new_v4(),
        "custom".to_string(),
        ETH_KEY,
        BlockchainNetwork::Custom("fantasy".to_string()),
        "pw",
    )
    .expect_err("custom networks have no address scheme");
    assert!(err.to_string().contains("not implemented for"));
}

#[test]
fn import_from_wif_rejects_testnet_and_uncompressed() {
    // Testnet WIF: version byte 0xef, compressed suffix.
    let mut payload = vec![0xefu8];
    payload.extend_from_slice(&[0x22u8; 32]);
    payload.push(0x01);
    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    let testnet_wif = bs58::encode(payload).into_string();

    let err = import_from_wif(Uuid::new_v4(), "t".to_string(), &testnet_wif, "pw")
        .expect_err("testnet WIF must be rejected");
    assert!(err.to_string().contains("testnet WIF is not supported"));

    // Uncompressed mainnet WIF (no 0x01 suffix).
    let uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let err = import_from_wif(Uuid::new_v4(), "u".to_string(), uncompressed, "pw")
        .expect_err("uncompressed WIF must be rejected");
    assert!(err
        .to_string()
        .contains("Uncompressed WIF is not supported"));
}

#[test]
fn import_from_json_error_paths() {
    // Malformed JSON.
    let err = import_from_json(Uuid::new_v4(), None, "{nope", "pw")
        .expect_err("malformed export must be rejected");
    assert!(err.to_string().contains("Invalid wallet JSON export"));

    // Neither mnemonic nor private keys.
    let bare = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"bare","network":"bitcoin","wallet_type":"HD","addresses":[],"created_at":"2024-01-01T00:00:00Z"}"#;
    let err = import_from_json(Uuid::new_v4(), None, bare, "pw")
        .expect_err("export without key material must be rejected");
    assert!(err
        .to_string()
        .contains("requires mnemonic or private key data"));

    // Empty private-keys map.
    let empty_keys = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"empty","network":"bitcoin","wallet_type":"single","addresses":[],"private_keys":{},"created_at":"2024-01-01T00:00:00Z"}"#;
    let err = import_from_json(Uuid::new_v4(), None, empty_keys, "pw")
        .expect_err("empty private key map must be rejected");
    assert!(err
        .to_string()
        .contains("does not contain any private keys"));

    // Missing name and no fallback.
    let nameless = r#"{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"  ","network":"bitcoin","wallet_type":"hd","addresses":[],"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about","created_at":"2024-01-01T00:00:00Z"}"#;
    let err = import_from_json(Uuid::new_v4(), None, nameless, "pw")
        .expect_err("missing name must be rejected");
    assert!(err.to_string().contains("missing a name"));
}

#[test]
fn import_from_json_defaults_optional_fields() {
    // extended_public_key / description / watch_only are serde-defaulted.
    // addresses 必须写真实派生地址：恢复一致性核对（2026-11-13 深审
    // Critical 修复）会拒绝与助记词派生不符的地址集。
    let reference = import_from_mnemonic(
        Uuid::new_v4(),
        "Ref".to_string(),
        TEST_PHRASE,
        "",
        BlockchainNetwork::Polygon,
        None,
        1,
        "pw",
    )
    .unwrap();
    let first = reference.addresses[0].address.clone();
    let minimal = format!(
        r#"{{"version":1,"wallet_id":"00000000-0000-0000-0000-000000000000","name":"minimal","network":"polygon","wallet_type":"hd","mnemonic":"{TEST_PHRASE}","addresses":["{first}"],"created_at":"2024-01-01T00:00:00Z"}}"#
    );
    let wallet = import_from_json(Uuid::new_v4(), None, &minimal, "pw").unwrap();
    assert_eq!(wallet.network, BlockchainNetwork::Polygon);
    assert!(!wallet.watch_only);
    assert_eq!(wallet.addresses.len(), 1);
    assert!(wallet.addresses[0].address.starts_with("0x"));
}

#[test]
fn test_import_bitcoin_private_key_yields_p2wkh_address() {
    let identity_id = Uuid::new_v4();
    let password = "test_password";
    let private_key = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";

    let wallet = import_from_private_key(
        identity_id,
        "BTC Single".to_string(),
        private_key,
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();

    assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
    assert_eq!(wallet.addresses.len(), 1);
    assert_eq!(
        wallet.addresses[0].address_type,
        crate::models::wallet::AddressType::P2WPKH
    );
    assert!(
        wallet.addresses[0].address.starts_with("bc1q"),
        "bech32 P2WPKH address, got {}",
        wallet.addresses[0].address
    );

    // The key round-trips through WIF export (compressed mainnet).
    let wif = export_to_wif(&wallet, password).unwrap();
    assert!(wif.starts_with('K') || wif.starts_with('L'));
}

// 深审 Critical 回归（2026-11-13）：带 BIP39 passphrase 的 HD 导出，
// JSON 里只有助记词、passphrase 无法随文件走——恢复时用空 passphrase
// 会派生出另一个钱包。恢复一致性核对必须拒绝静默错位恢复，而不是
// 假装成功（老行为：恢复出完全不同地址的钱包还覆盖 xpub）。
#[test]
fn json_restore_of_passphrase_export_is_refused() {
    let identity_id = Uuid::new_v4();
    let password = "test_password";

    let wallet = import_from_mnemonic(
        identity_id,
        "Passphrase HD".to_string(),
        TEST_PHRASE,
        "hunter2",
        BlockchainNetwork::Bitcoin,
        None,
        2,
        password,
    )
    .unwrap();

    let exported = export_to_json(&wallet, true, Some(password)).unwrap();
    let err = import_from_json(Uuid::new_v4(), None, &exported, password)
        .expect_err("passphrase-protected export must not restore silently");
    assert!(
        err.to_string().contains("passphrase"),
        "error must point at the missing passphrase: {err}"
    );

    // 对照组：无 passphrase 导出照常恢复，地址逐一一致
    let plain = import_from_mnemonic(
        identity_id,
        "Plain HD".to_string(),
        TEST_PHRASE,
        "",
        BlockchainNetwork::Bitcoin,
        None,
        2,
        password,
    )
    .unwrap();
    let plain_export = export_to_json(&plain, true, Some(password)).unwrap();
    let restored = import_from_json(Uuid::new_v4(), None, &plain_export, password).unwrap();
    let restored_addrs: Vec<&str> = restored
        .addresses
        .iter()
        .map(|a| a.address.as_str())
        .collect();
    let declared: Vec<&str> = plain.addresses.iter().map(|a| a.address.as_str()).collect();
    assert_eq!(restored_addrs, declared);
}
