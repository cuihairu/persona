//! 钱包 CRUD、查询与地址维护域测试。

use super::*;

#[tokio::test]
async fn test_wallet_crud() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = CryptoWallet::new(
        identity_id,
        "Test Wallet".to_string(),
        BlockchainNetwork::Bitcoin,
        WalletType::SingleAddress,
        vec![1, 2, 3, 4],
    );

    // Create
    let created = repo.create(&wallet).await.unwrap();
    assert_eq!(created.name, "Test Wallet");
    assert_eq!(created.identity_id, identity_id);

    // Find by ID
    let found = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(found.name, created.name);

    // Find by identity
    let by_identity = repo.find_by_identity(&identity_id).await.unwrap();
    assert_eq!(by_identity.len(), 1);

    // Update
    let mut updated_wallet = found.clone();
    updated_wallet.name = "Updated Wallet".to_string();
    updated_wallet.updated_at = chrono::Utc::now();
    let updated = repo.update(&updated_wallet).await.unwrap();
    assert_eq!(updated.name, "Updated Wallet");

    // Delete
    let deleted = repo.delete(&updated.id).await.unwrap();
    assert!(deleted);

    // Verify deletion
    let found_deleted = repo.find_by_id(&updated.id).await.unwrap();
    assert!(found_deleted.is_none());
}

#[tokio::test]
async fn test_address_management() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let mut wallet = CryptoWallet::new(
        identity_id,
        "Test Wallet".to_string(),
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
        metadata: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };

    wallet.add_address(address.clone());

    // Create wallet with address
    let created = repo.create(&wallet).await.unwrap();
    assert_eq!(created.addresses.len(), 1);
    assert_eq!(created.addresses[0].address, address.address);

    // Update address usage
    let updated = repo
        .update_address_usage(&created.id, &address.address, true)
        .await
        .unwrap();
    assert!(updated);
}

#[tokio::test]
async fn test_touch_updates_timestamp() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    // Seed a stale updated_at (timestamps are stored at second precision).
    let mut wallet = make_wallet(identity_id, "Touch Wallet");
    wallet.updated_at = chrono::Utc::now() - chrono::Duration::hours(1);
    let created = repo.create(&wallet).await.unwrap();
    let before = created.updated_at;

    repo.touch(&created.id).await.unwrap();

    let found = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert!(found.updated_at > before);
}

#[tokio::test]
async fn test_find_all_returns_every_wallet() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    assert!(repo.find_all().await.unwrap().is_empty());

    repo.create(&make_wallet(identity_id, "Wallet One"))
        .await
        .unwrap();
    repo.create(&make_wallet(identity_id, "Wallet Two"))
        .await
        .unwrap();

    assert_eq!(repo.find_all().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_find_by_network() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let mut btc = make_wallet(identity_id, "BTC Wallet");
    btc.network = BlockchainNetwork::Bitcoin;
    repo.create(&btc).await.unwrap();

    let mut eth = make_wallet(identity_id, "ETH Wallet");
    eth.network = BlockchainNetwork::Ethereum;
    repo.create(&eth).await.unwrap();

    let btc_wallets = repo
        .find_by_network(&BlockchainNetwork::Bitcoin)
        .await
        .unwrap();
    assert_eq!(btc_wallets.len(), 1);
    assert_eq!(btc_wallets[0].name, "BTC Wallet");

    let custom = repo
        .find_by_network(&BlockchainNetwork::Custom("testnet".to_string()))
        .await
        .unwrap();
    assert!(custom.is_empty());
}

#[tokio::test]
async fn test_find_by_security_level() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let mut high = make_wallet(identity_id, "High Sec");
    high.security_level = WalletSecurityLevel::High;
    repo.create(&high).await.unwrap();

    let found = repo
        .find_by_security_level(&WalletSecurityLevel::High)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "High Sec");

    assert!(repo
        .find_by_security_level(&WalletSecurityLevel::Maximum)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_find_by_name_and_name_like() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    repo.create(&make_wallet(identity_id, "Savings Wallet"))
        .await
        .unwrap();
    repo.create(&make_wallet(identity_id, "Trading Wallet"))
        .await
        .unwrap();

    // Case-insensitive exact match.
    let by_name = repo.find_by_name("SAVINGS wallet").await.unwrap();
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].name, "Savings Wallet");

    // Substring match.
    let by_like = repo.find_by_name_like("WALL").await.unwrap();
    assert_eq!(by_like.len(), 2);

    assert!(repo.find_by_name("nope").await.unwrap().is_empty());
    assert!(repo.find_by_name_like("zzz").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_find_by_id_prefix() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = make_wallet(identity_id, "Prefix Wallet");
    repo.create(&wallet).await.unwrap();

    let id_str = wallet.id.to_string();
    let by_prefix = repo.find_by_id_prefix(&id_str[..8]).await.unwrap();
    assert_eq!(by_prefix.len(), 1);
    assert_eq!(by_prefix[0].id, wallet.id);

    assert!(repo.find_by_id_prefix("zzzzzzzz").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_missing_wallet_returns_false() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let repo = CryptoWalletRepository::new(Arc::new(db));

    assert!(!repo.delete(&Uuid::new_v4()).await.unwrap());
}

#[tokio::test]
async fn test_update_address_usage_missing_returns_false() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = make_wallet(identity_id, "No Address");
    let created = repo.create(&wallet).await.unwrap();

    assert!(!repo
        .update_address_usage(&created.id, "missing-address", true)
        .await
        .unwrap());
}

#[tokio::test]
async fn test_update_missing_wallet_is_not_found() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    // Never inserted: the UPDATE affects no rows, so the repository must
    // surface NotFound instead of silently succeeding.
    let ghost = make_wallet(identity_id, "Ghost Wallet");
    let err = repo
        .update(&ghost)
        .await
        .expect_err("updating a missing wallet must fail");
    assert!(matches!(err, PersonaError::NotFound(_)));
}

// 深审 Critical 回归（2026-11-13）：update 全程单事务——地址重建中途
// 约束失败（同 wallet 重复 address 撞 UNIQUE(wallet_id, address)）必须
// 整体回滚，钱包行保持原值。老实现 UPDATE 先行提交，失败后留下新密钥
// 与残缺地址的混合状态。
#[tokio::test]
async fn update_rolls_back_as_a_whole_on_address_conflict() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let mut wallet = make_wallet(identity_id, "Orig Name");
    wallet.addresses.push(make_address("1Original", 0));
    let created = repo.create(&wallet).await.unwrap();

    let mut bad = created.clone();
    bad.name = "Changed Name".to_string();
    bad.encrypted_private_key = vec![9, 9, 9, 9];
    bad.updated_at = chrono::Utc::now();
    bad.addresses = vec![make_address("1Duplicate", 0), make_address("1Duplicate", 1)];

    assert!(
        repo.update(&bad).await.is_err(),
        "duplicate address must fail the update"
    );

    // 整体回滚：名字与密钥保持原值，地址仍是原来的那一条
    let after = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(after.name, "Orig Name");
    assert_eq!(after.encrypted_private_key, vec![1, 2, 3, 4]);
    assert_eq!(after.addresses.len(), 1);
    assert_eq!(after.addresses[0].address, "1Original");
}

// 深审 Critical 回归（2026-11-13）：delete 改为单条父表删除，四张子表
// 经 ON DELETE CASCADE 在同一语句内清除——中途失败不再可能留下半删除
// 状态（老实现逐表独立删除）。
#[tokio::test]
async fn delete_cascades_to_all_child_rows() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));

    let mut wallet = make_wallet(identity_id, "Cascade Wallet");
    wallet.addresses.push(make_address("1Cascade", 0));
    let created = repo.create(&wallet).await.unwrap();

    let request = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: created.id,
        network: BlockchainNetwork::Bitcoin,
        from_address: "1Cascade".to_string(),
        to_address: "1Sink".to_string(),
        amount: "5".to_string(),
        fee: "1".to_string(),
        gas_price: None,
        gas_limit: None,
        nonce: None,
        memo: None,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: None,
        metadata: std::collections::HashMap::new(),
    };
    repo.create_transaction_request(&request).await.unwrap();
    repo.create_signed_transaction(&SignedTransaction {
        id: Uuid::new_v4(),
        request: request.clone(),
        signatures: vec![],
        raw_signed_transaction: vec![1],
        transaction_hash: "deadbeef".to_string(),
        signed_at: chrono::Utc::now(),
        broadcast_status: crate::models::wallet::BroadcastStatus::NotBroadcast,
    })
    .await
    .unwrap();

    assert!(repo.delete(&created.id).await.unwrap());

    for table in [
        "wallet_addresses",
        "wallet_metadata",
        "transaction_requests",
        "signed_transactions",
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE wallet_id = ?");
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(created.id.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "{table} rows must cascade away");
    }
    assert!(repo.find_by_id(&created.id).await.unwrap().is_none());
    assert!(!repo.delete(&created.id).await.unwrap());
}
