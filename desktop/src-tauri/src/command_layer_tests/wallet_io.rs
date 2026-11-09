//! Command-layer integration tests — `wallet_io` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// wallet_import 三种导入方式 + 地址派生 + 删除与锁定门禁。
#[tokio::test]
async fn wallet_import_address_management_and_locked_gates() {
    let (app, identity_id) = app_with_identity().await;

    // HD 导入（mnemonic，2 个地址）。
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

    // 单地址导入（private_key）。
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

    // 短密码 / 未知 import_type / 坏助记词都被拒绝。
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

    // 按 identity 过滤 + 非法 UUID。
    let resp = wallet_list(Some(identity_id.clone()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().wallets.len(), 2);

    // wallet_list 落 bad UUID 为 ApiResponse 错误，不再逃逸命令边界。
    let resp = wallet_list(Some("not-a-uuid".to_string()), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // 地址列表：非法 UUID / 未知钱包。
    // Bad UUID 同样落 ApiResponse。
    let resp = wallet_list_addresses("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet UUID format"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    // add_address：未知钱包 / 短密码 / 错误密码 / 单地址钱包 / HD 正常派生。
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

    // Decrypt failure 落 ApiResponse 错误消息，不逃逸命令边界。
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

    // 地址列表能看到新地址（serialize_wallet_address 路径）。
    let resp = wallet_list_addresses(hd.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addresses = resp.data.unwrap().addresses;
    assert_eq!(addresses.len(), 3);
    assert!(addresses.iter().any(|a| a.index == 2));

    // 删除：未知钱包报错，真实删除返回 true。
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    for id in [hd.id, single.id] {
        let resp = wallet_delete(id, app.state::<AppState>()).await.unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }

    // 锁定后整个家族都被 "Service is locked" 门禁拦下。
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
/// 导出格式矩阵：json（含私钥）/ mnemonic / private_key / xpub / wif。
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

    // Bitcoin 钱包供 WIF 导出。
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

    // mnemonic 导出：无密码被拒，有密码还原助记词。
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

    // private_key 导出：无密码被拒，有密码得到 0x hex。
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

    // xpub 导出（HD 导入会写 extended_public_key）。
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

    // WIF 导出：HD Bitcoin 钱包被拒（要求单地址），单地址 Bitcoin 才成功。
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

    // JSON 含私钥导出 + 未知格式。
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

    // Keystore v3 臂：导出臂的边界（geth 默认 scrypt n=2^18 在本测试里太慢，
    // 往返覆盖见 core 的 keystore 规范向量与低 work factor 往返），导入臂用
    // 低 work factor 造的 keystore 端到端走一遍。
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

    // 原钱包的私钥，供 keystore 往返校验。
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

    // 导入臂的坏数据：非法 JSON 在 scrypt 之前就被拒。
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
