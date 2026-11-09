//! Command-layer integration tests — `wallet` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn wallet_commands_round_trip_generate_list_export_delete() {
    let (app, identity_id) = app_with_identity().await;

    // Empty listing before anything exists.
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().wallets.is_empty());

    // Generate an HD wallet (24-word mnemonic, 3 addresses).
    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Desktop HD".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(3),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let generated = resp.data.expect("wallet generated");
    assert_eq!(generated.mnemonic.split_whitespace().count(), 24);
    assert!(generated.first_address.starts_with("0x"));

    // Short passwords are rejected up front.
    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Bad".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
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

    // Listing now contains the wallet.
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallets = resp.data.unwrap().wallets;
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].id, generated.wallet_id);

    // Address listing shows the generated count.
    let resp = wallet_list_addresses(generated.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().addresses.len(), 3);

    // JSON export (no private material) succeeds.
    let resp = wallet_export(
        WalletExportRequest {
            wallet_id: generated.wallet_id.clone(),
            format: "json".to_string(),
            include_private: false,
            password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let exported: serde_json::Value =
        serde_json::from_str(&resp.data.unwrap()).expect("export is valid JSON");
    assert_eq!(exported["name"], "Desktop HD");

    // Delete the wallet.
    let resp = wallet_delete(generated.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap());
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().wallets.is_empty());
}
/// wallet 家族在"服务未初始化"下一律失败关闭。
#[tokio::test]
async fn wallet_family_fails_closed_without_service() {
    let app = mock_app();

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

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
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

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
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
}
/// wallet_add_address 的 Bitcoin P2WPKH 派生臂与 Solana"未实现"拒绝臂。
#[tokio::test]
async fn wallet_add_address_bitcoin_and_unsupported_network() {
    let (app, identity_id) = app_with_identity().await;

    // BTC HD 钱包（1 地址）→ 追加地址走 Bitcoin P2WPKH 派生臂。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "BTC HD".to_string(),
            network: "bitcoin".to_string(),
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
    let btc = resp.data.expect("btc imported");

    let resp = wallet_add_address(
        btc.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addr = resp.data.expect("address added");
    assert!(
        addr.address.starts_with("bc1"),
        "P2WPKH bech32 address, got {}",
        addr.address
    );
    assert_eq!(addr.address_type, "P2WPKH");
    assert_eq!(addr.index, 1, "next index after the seeded first address");

    // 地址生成未实现的网络：core 的 import/generate 都在派生阶段就拒绝
    //（derive_addresses 对非 BTC/ETH 系报 not implemented），所以拿已导入
    // 的 BTC HD 钱包把 network 改写为 Litecoin（等价于旧版本遗留钱包），
    // 让 add_address 走完派生后撞上命令层的 not-implemented 拒绝臂。
    let wallet_id = uuid::Uuid::parse_str(&btc.id).unwrap();
    {
        let db_path = app
            .state::<AppState>()
            .db_path
            .lock()
            .await
            .clone()
            .expect("db path set by wallet_import");
        let db = persona_core::storage::Database::from_file(&db_path)
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = persona_core::storage::CryptoWalletRepository::new(std::sync::Arc::new(db));
        let mut wallet = repo
            .find_by_id(&wallet_id)
            .await
            .unwrap()
            .expect("wallet persisted");
        wallet.network = persona_core::models::wallet::BlockchainNetwork::Litecoin;
        repo.update(&wallet).await.unwrap();
    }

    let resp = wallet_add_address(
        btc.id.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let msg = resp.error.expect("error message");
    assert!(
        msg.contains("Address generation not implemented for Litecoin"),
        "got: {msg}"
    );
}
/// db_path 坏文件/坏目录时 wallet 命令大声报连接或迁移错误（sqlx 惰性
/// 连接：from_file 不检查文件内容，migrate 才暴露 "not a database"）。
#[tokio::test]
async fn wallet_commands_report_db_path_failures_loudly() {
    let (app, identity_id) = app_with_identity().await;

    // 指向不存在目录 → 连接失败。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some("/nonexistent-dir-for-persona-tests/bad.db".to_string());
    }
    // 连接失败：基础设施错误走 Ok(ApiResponse::error)，不逃出命令边界。
    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Database connection failed")),
        "got: {:?}",
        resp.error
    );

    // 垃圾文件：from_file 的 connect 能打开任意可读文件，migrate 执行时
    // 才撞上 (code: 26) file is not a database → "Database migration failed"。
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"definitely not a sqlite database").unwrap();
    let junk_path = junk.to_string_lossy().to_string();
    // 保留 tempdir 到测试结束（list/addresses/import/generate 均复用）。
    std::mem::forget(dir);
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk_path.clone());
    }

    let resp = wallet_list(None, app.state::<AppState>()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Database migration failed") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_list_addresses(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_import(
        identity_id.clone(),
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
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );

    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "g".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
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
            .is_some_and(|e| e.contains("not a database")),
        "got: {:?}",
        resp.error
    );
}
/// wallet_generate 拒绝未支持的 wallet_type。
#[tokio::test]
async fn wallet_generate_rejects_unsupported_wallet_type() {
    let (app, identity_id) = app_with_identity().await;
    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "w".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "ledger".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Unsupported wallet_type 'ledger'. Use 'hd'.")
    );
}
/// 五个此前只覆盖成功/半覆盖路径的 wallet 命令（add_address/delete/export/
/// create_transaction/sign_transaction）的前置臂与死库矩阵：
/// None service → Ok(error)（wallet_db 路径为 Err）、locked → 同型、
/// 短密码专属臂、db_path 缺失 → Err、垃圾库 → migrate 失败。
#[tokio::test]
async fn wallet_five_commands_precondition_and_dead_db_matrix() {
    let export_request = || WalletExportRequest {
        wallet_id: uuid::Uuid::new_v4().to_string(),
        format: "json".to_string(),
        include_private: false,
        password: None,
    };
    let create_request = |wallet_id: &str| WalletCreateTransactionRequest {
        wallet_id: wallet_id.to_string(),
        to_address: "0x2222222222222222222222222222222222222222".to_string(),
        amount: "1".to_string(),
        fee: "21000".to_string(),
        gas_price: None,
        gas_limit: None,
        nonce: None,
        memo: None,
        expires_in_minutes: None,
    };
    let sign_request = |wallet_id: &str| WalletSignTransactionRequest {
        transaction_id: wallet_id.to_string(),
        password: "wallet-pass-123".to_string(),
        confirm_poisoning_check: false,
    };

    // 场景 A：未初始化。add/delete/export 返回 Ok 包错误体；
    // create/sign 先解析 UUID 再走 wallet_db 的 Err 臂。
    let app = mock_app();
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "pw".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_create_transaction(
        create_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));
    let resp = wallet_sign_transaction(
        sign_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    // 场景 B：锁定。同型消息，wallet_db 路径的锁定语义带码落 ApiResponse。
    let (app, _identity_id) = app_with_identity().await;
    lock_service(app.state::<AppState>()).await.unwrap();
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "pw".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_delete(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    let resp = wallet_create_transaction(
        create_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));
    let resp = wallet_sign_transaction(
        sign_request(&uuid::Uuid::new_v4().to_string()),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Service is locked"));
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // 场景 C/D：已解锁。短密码专属臂、db_path 缺失、垃圾库 migrate 失败。
    let (app, _identity_id) = app_with_identity().await;

    // add_address：合法 UUID 但密码太短（UUID 解析之后、db_path 之前）。
    let resp = wallet_add_address(
        uuid::Uuid::new_v4().to_string(),
        "short".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Wallet password must be at least 8 characters")
    );
    // delete 的 UUID 解析在 db_path 之后——用非法 UUID 顺带钉住顺序。
    let resp = wallet_delete("bad-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet UUID format"));

    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"junk for wallet matrix").unwrap();
    let junk_path = junk.to_string_lossy().to_string();
    std::mem::forget(dir);

    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = None;
    }
    let wallet_uuid = uuid::Uuid::new_v4().to_string();
    fn expect_db_path_err<T>(resp: &ApiResponse<T>) {
        assert!(!resp.success);
        assert_eq!(
            resp.error.as_deref(),
            Some("Database path unavailable. Initialize the service first.")
        );
    }
    let resp = wallet_add_address(
        wallet_uuid.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_delete(wallet_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);
    let resp = wallet_sign_transaction(sign_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_db_path_err(&resp);

    // 垃圾库：migrate 才撞 not a database。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = Some(junk_path);
    }
    fn expect_junk_err<T>(resp: &ApiResponse<T>) {
        assert!(!resp.success);
        assert!(
            resp.error
                .as_deref()
                .is_some_and(|e| e.contains("not a database")),
            "got: {:?}",
            resp.error
        );
    }
    let resp = wallet_add_address(
        wallet_uuid.clone(),
        "wallet-pass-123".to_string(),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error.as_deref().is_some_and(
            |e| e.starts_with("Database migration failed") && e.contains("not a database")
        ),
        "got: {:?}",
        resp.error
    );
    let resp = wallet_delete(wallet_uuid.clone(), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_export(export_request(), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_sign_transaction(sign_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
    let resp = wallet_create_transaction(create_request(&wallet_uuid), app.state::<AppState>())
        .await
        .unwrap();
    expect_junk_err(&resp);
}
/// wallet_list_addresses 的 AddressType 标签全臂（命令内联 match，与
/// serialize_wallet_address 单测不共享）；wallet_generate 的非法 UUID 臂；
/// passkey_create 的非法 base64 两臂。
#[tokio::test]
async fn wallet_address_labels_and_passkey_create_base64_gates() {
    let (app, identity_id) = app_with_identity().await;

    // wallet_generate：非法 identity_id 在任何 db 操作前拦下。
    let resp = wallet_generate(
        "bad-uuid".to_string(),
        WalletGenerateRequest {
            name: "g".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid identity UUID format"));

    // 手工插一个七种地址类型齐全的钱包，驱动命令内联 match 全臂。
    let db_path = {
        let state = app.state::<AppState>();
        let guard = state.db_path.lock().await;
        guard.clone().expect("db path set")
    };
    let db = Arc::new(persona_core::Database::from_file(&db_path).await.unwrap());
    db.migrate().await.unwrap();
    let mut wallet = persona_core::models::wallet::CryptoWallet::new(
        uuid::Uuid::parse_str(&identity_id).unwrap(),
        "All Address Types".to_string(),
        persona_core::models::wallet::BlockchainNetwork::Bitcoin,
        persona_core::models::wallet::WalletType::HierarchicalDeterministic {
            bip_version: persona_core::models::wallet::BipVersion::Bip84,
            address_count: 7,
            gap_limit: 20,
        },
        vec![1, 2, 3],
    );
    let cases = [
        (persona_core::models::wallet::AddressType::P2PKH, "P2PKH"),
        (persona_core::models::wallet::AddressType::P2SH, "P2SH"),
        (persona_core::models::wallet::AddressType::P2WPKH, "P2WPKH"),
        (persona_core::models::wallet::AddressType::P2TR, "P2TR"),
        (persona_core::models::wallet::AddressType::Ethereum, "ETH"),
        (persona_core::models::wallet::AddressType::Solana, "SOL"),
    ];
    for (i, (address_type, _)) in cases.iter().enumerate() {
        wallet
            .addresses
            .push(persona_core::models::wallet::WalletAddress {
                address: format!("addr-{i}"),
                address_type: address_type.clone(),
                derivation_path: Some(format!("m/0/{i}")),
                index: i as u32,
                used: false,
                balance: None,
                last_activity: None,
                metadata: HashMap::new(),
                created_at: chrono::Utc::now(),
            });
    }
    // Custom 变体的标签就是自定义名本身。
    wallet
        .addresses
        .push(persona_core::models::wallet::WalletAddress {
            address: "addr-custom".to_string(),
            address_type: persona_core::models::wallet::AddressType::Custom(
                "my-custom-chain".to_string(),
            ),
            derivation_path: None,
            index: 99,
            used: false,
            balance: Some("1.5".to_string()),
            last_activity: None,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        });
    persona_core::storage::wallet_repository::CryptoWalletRepository::new(db.clone())
        .create(&wallet)
        .await
        .unwrap();

    let resp = wallet_list_addresses(wallet.id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let addresses = resp.data.expect("addresses").addresses;
    assert_eq!(addresses.len(), cases.len() + 1);
    for (addr, (_, label)) in addresses.iter().zip(cases.iter()) {
        assert_eq!(addr.address_type, *label);
    }
    assert_eq!(
        addresses.last().unwrap().address_type,
        "my-custom-chain",
        "custom type renders its own name"
    );

    // passkey_create：client_data_json_b64 非法 base64 → 专属错误体。
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id: identity_id.clone(),
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: "!!!not-base64!!!".to_string(),
            user_handle_b64: None,
            user_name: None,
            user_display_name: None,
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Invalid client_data_json_b64")),
        "got: {:?}",
        resp.error
    );

    // user_handle_b64 非法 base64 → 第二道门。
    let resp = passkey_create(
        CreatePasskeyRequest {
            identity_id,
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            client_data_json_b64: "e30=".to_string(), // "{}"
            user_handle_b64: Some("@@@".to_string()),
            user_name: None,
            user_display_name: None,
            user_verification: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.starts_with("Invalid user_handle_b64")),
        "got: {:?}",
        resp.error
    );
}
