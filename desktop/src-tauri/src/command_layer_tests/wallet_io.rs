//! Command-layer integration tests — `wallet_io` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// wallet_import's three import types + address derivation + delete and locked gates.
#[tokio::test]
async fn wallet_import_address_management_and_locked_gates() {
    let (app, identity_id) = app_with_identity().await;

    // HD import (mnemonic, 2 addresses).
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Imported HD".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(2),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let hd = resp.data.expect("hd imported");
    assert!(hd.wallet_type.contains("HierarchicalDeterministic"));
    assert_eq!(hd.network, "Ethereum");
    assert_eq!(hd.address_count, 2);

    // Single-address import (private_key).
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Imported Single".to_string(),
            network: "Ethereum".to_string(),
            import_type: "private_key".to_string(),
            data: "4646464646464646464646464646464646464646464646464646464646464646".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let single = resp.data.expect("single imported");
    assert!(!single.wallet_type.contains("HierarchicalDeterministic"));
    assert_eq!(single.address_count, 1);

    // Short password / unknown import_type / bad mnemonic are all rejected.
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon about".to_string(),
            password: "short".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "yaml".to_string(),
            data: "whatever".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("Unsupported import_type"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "not a real mnemonic phrase at all".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "invalid mnemonic must be rejected");

    // Filter by identity + invalid UUID.
    let resp = wallet_list(Some(identity_id.clone()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().wallets.len(), 2);

    // wallet_list turns a bad UUID into an ApiResponse error, no longer escaping the command boundary.
    let resp = wallet_list(Some("not-a-uuid".to_string()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // Address list: invalid UUID / unknown wallet.
    // A bad UUID likewise lands as an ApiResponse.
    let resp = wallet_list_addresses("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet UUID format"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    // add_address: unknown wallet / short password / wrong password / single-address wallet / HD derives normally.
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    let resp = wallet_add_address(hd.id.clone(), "short".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );

    // A decrypt failure lands as an ApiResponse error message, not escaping the command boundary.
    let resp = wallet_add_address(
        hd.id.clone(),
        "wrong-passphrase".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to decrypt private key")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_add_address(
        single.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Address generation is only supported for HD wallets.")
    );

    let resp = wallet_add_address(
        hd.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addr = resp.data.expect("new address");
    assert_eq!(addr.index, 2, "next index after the two imported ones");
    assert_eq!(addr.address_type, "ETH");
    assert!(addr.address.starts_with("0x"));
    assert_eq!(
        addr.derivation_path.as_deref().map(|p| p.ends_with("/2")),
        Some(true)
    );

    // The address list can see the new address (the serialize_wallet_address path).
    let resp = wallet_list_addresses(hd.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addresses = resp.data.unwrap().addresses;
    assert_eq!(addresses.len(), 3);
    assert!(addresses.iter().any(|a| a.index == 2));

    // Delete: an unknown wallet errors, a real delete returns true.
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    for id in [hd.id, single.id] {
        let resp = wallet_delete(id, app.state::<AppState>()).await.unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }

    // Once locked, the whole family is gated down by "Service is locked".
    let resp = lock_service(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_import(
        uuid::Uuid::new_v4().to_string(),
        WalletImportRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: uuid::Uuid::new_v4().to_string(),
            format: "json".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
}
/// Export format matrix: json (with private key) / mnemonic / private_key / xpub / wif.
#[tokio::test]
async fn wallet_export_format_matrix() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Eth HD".to_string(),
            network: "Ethereum".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let eth = resp.data.expect("eth wallet");
    let eth_id = eth.id.clone();

    // A Bitcoin wallet for WIF export.
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Btc".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "mnemonic".to_string(),
            data: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc = resp.data.expect("btc wallet");

    // mnemonic export: rejected without a password, returns the mnemonic with one.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "mnemonic".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Password required for mnemonic export")
    );

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "mnemonic".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().split_whitespace().count(), 12);

    // private_key export: rejected without a password, yields 0x hex with one.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "private_key".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Password required for private key export")
    );

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "private_key".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let priv_hex = resp.data.unwrap();
    assert!(
        priv_hex.len() >= 64,
        "hex private key, got {} chars",
        priv_hex.len()
    );

    // xpub export (an HD import writes extended_public_key).
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "xpub".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().starts_with("xpub"));

    // WIF export: an HD Bitcoin wallet is rejected (a single address is required); only a single-address Bitcoin wallet succeeds.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: btc.id.clone(),
            format: "wif".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .map(|e| e.contains("single-address Bitcoin wallets"))
            .unwrap_or(false),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Btc Single".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "private_key".to_string(),
            data: "4646464646464646464646464646464646464646464646464646464646464646".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc_single = resp.data.expect("btc single");

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: btc_single.id.clone(),
            format: "wif".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().len() >= 51);

    // JSON export with the private key + an unknown format.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "json".to_string(),
            include_private: true,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let exported: serde_json::Value =
        serde_json::from_str(&resp.data.unwrap()).expect("export is valid JSON");
    assert!(exported.get("private_keys").is_some());

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "yaml".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "unknown export format must be rejected");

    // Keystore v3 arm: the boundary of the export arm (geth's default scrypt
    // n=2^18 is too slow for this test; round-trip coverage lives in core's
    // keystore normative vectors and the low-work-factor round trip). The
    // import arm runs a keystore built with a low work factor end to end.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id.clone(),
            format: "keystore".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Password required for keystore export")),
        "got: {:?}",
        resp.error
    );

    // The original wallet's private key, used to verify the keystore round trip.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: eth_id,
            format: "private_key".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let original_pk = resp.data.unwrap();

    let keystore_json = persona_core::crypto::export_to_keystore_with_params(
        hex::decode(original_pk.trim()).unwrap().as_slice(),
        "wallet-pass-123",
        Some("".to_string()),
        persona_core::crypto::ScryptExportParams {
            log_n: 4,
            r: 8,
            p: 1,
        },
    )
    .expect("small-factor keystore export");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&keystore_json).unwrap()["version"],
        3
    );

    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Keystore Roundtrip".to_string(),
            network: "Ethereum".to_string(),
            import_type: "keystore".to_string(),
            data: keystore_json,
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let imported = resp.data.expect("imported wallet");
    assert!(!imported.watch_only);
    assert_eq!(imported.address_count, 1);

    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: imported.id,
            format: "private_key".to_string(),
            include_private: false,
            password: Some("wallet-pass-123".to_string()),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(original_pk, resp.data.unwrap(), "same private key material");

    // Bad data for the import arm: invalid JSON is rejected before scrypt.
    let resp = wallet_import(
        identity_id,
        WalletImportRequest {
            name: "Bad Keystore".to_string(),
            network: "Ethereum".to_string(),
            import_type: "keystore".to_string(),
            data: "{not json".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("keystore")),
        "got: {:?}",
        resp.error
    );
}
