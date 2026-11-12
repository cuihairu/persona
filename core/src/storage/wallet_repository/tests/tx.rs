//! 交易请求、签名交易、元数据与时间戳 helper 域测试。

use super::*;

#[tokio::test]
async fn test_transaction_requests_and_signed_transactions() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));

    let wallet = make_wallet(identity_id, "Tx Wallet");
    let created = repo.create(&wallet).await.unwrap();

    let mut request = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: created.id,
        network: BlockchainNetwork::Bitcoin,
        from_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        to_address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        amount: "1000".to_string(),
        fee: "10".to_string(),
        gas_price: None,
        gas_limit: Some(21000),
        nonce: Some(1),
        memo: Some("test memo".to_string()),
        raw_transaction_data: Some(vec![9, 9, 9]),
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        metadata: std::collections::HashMap::new(),
    };
    repo.create_transaction_request(&request).await.unwrap();

    let pending = repo.get_pending_requests(&created.id).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, request.id);
    assert_eq!(pending[0].amount, "1000");
    assert_eq!(pending[0].gas_limit, Some(21000));
    assert_eq!(pending[0].nonce, Some(1));
    assert_eq!(pending[0].memo.as_deref(), Some("test memo"));
    assert!(pending[0].expires_at.is_some());

    // Stats start at zero.
    let stats = repo.get_transaction_stats(&created.id).await.unwrap();
    assert_eq!(stats.total_transactions, 0);
    assert_eq!(stats.successful_transactions, 0);
    assert_eq!(stats.failed_transactions, 0);

    // One successful and one failed broadcast.
    let success = SignedTransaction {
        id: Uuid::new_v4(),
        request: request.clone(),
        signatures: vec![crate::models::wallet::TransactionSignature {
            signer_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            signature: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            signature_scheme: crate::models::wallet::SignatureScheme::ECDSA,
            signed_at: chrono::Utc::now(),
        }],
        raw_signed_transaction: vec![7, 8, 9],
        transaction_hash: "deadbeef".to_string(),
        signed_at: chrono::Utc::now(),
        broadcast_status: crate::models::wallet::BroadcastStatus::BroadcastSuccess {
            hash: "deadbeef".to_string(),
            block_height: Some(800_000),
            confirmations: 6,
            confirmed_at: Some(chrono::Utc::now()),
        },
    };
    repo.create_signed_transaction(&success).await.unwrap();

    request.id = Uuid::new_v4();
    let failed = SignedTransaction {
        id: Uuid::new_v4(),
        request,
        signatures: vec![],
        raw_signed_transaction: vec![1],
        transaction_hash: "cafebabe".to_string(),
        signed_at: chrono::Utc::now(),
        broadcast_status: crate::models::wallet::BroadcastStatus::BroadcastFailed {
            error: "mempool rejected".to_string(),
            retry_count: 2,
        },
    };
    repo.create_signed_transaction(&failed).await.unwrap();

    let stats = repo.get_transaction_stats(&created.id).await.unwrap();
    assert_eq!(stats.total_transactions, 2);
    assert_eq!(stats.successful_transactions, 1);
    assert_eq!(stats.failed_transactions, 1);
    assert_eq!(stats.total_amount_sent, 0.0);

    // Private row mapper (currently unused in production) must round-trip.
    let row = sqlx::query("SELECT * FROM signed_transactions WHERE id = ?")
        .bind(success.id.to_string())
        .fetch_one(db.pool())
        .await
        .unwrap();
    let parsed = repo.signed_transaction_from_row(&row).unwrap();
    assert_eq!(parsed.id, success.id);
    assert_eq!(parsed.transaction_hash, "deadbeef");
    assert_eq!(parsed.signatures.len(), 1);
    assert!(matches!(
        parsed.broadcast_status,
        crate::models::wallet::BroadcastStatus::BroadcastSuccess {
            block_height: Some(800_000),
            confirmations: 6,
            ..
        }
    ));
}

#[tokio::test]
async fn test_get_request_by_id_roundtrip_and_missing() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));

    let wallet = make_wallet(identity_id, "By Id Wallet");
    let created = repo.create(&wallet).await.unwrap();

    let request = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: created.id,
        network: BlockchainNetwork::Ethereum,
        from_address: "0x1111111111111111111111111111111111111111".to_string(),
        to_address: "0x2222222222222222222222222222222222222222".to_string(),
        amount: "5".to_string(),
        fee: "21000".to_string(),
        gas_price: Some("20".to_string()),
        gas_limit: Some(21000),
        nonce: None,
        memo: None,
        raw_transaction_data: None,
        required_signatures: 2,
        created_at: chrono::Utc::now(),
        expires_at: None,
        metadata: std::collections::HashMap::new(),
    };
    repo.create_transaction_request(&request).await.unwrap();

    let found = repo.get_request_by_id(&request.id).await.unwrap().unwrap();
    assert_eq!(found.id, request.id);
    assert_eq!(found.wallet_id, created.id);
    assert_eq!(found.network, BlockchainNetwork::Ethereum);
    assert_eq!(found.to_address, request.to_address);
    assert_eq!(found.gas_price.as_deref(), Some("20"));
    assert_eq!(found.gas_limit, Some(21000));
    assert_eq!(found.nonce, None);
    assert_eq!(found.required_signatures, 2);
    assert!(found.memo.is_none());
    assert!(found.expires_at.is_none());

    // An unknown id maps to None rather than an error.
    let missing = repo.get_request_by_id(&Uuid::new_v4()).await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn test_wallet_metadata_roundtrip_and_default_fallback() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db.clone()));

    let mut wallet = make_wallet(identity_id, "Rich Metadata");
    wallet.metadata = WalletMetadata {
        tags: vec!["cold-storage".to_string()],
        notes: Some("keep offline".to_string()),
        platform: Some("Ledger".to_string()),
        purpose: Some("savings".to_string()),
        associated_services: vec!["service-a".to_string()],
        backup_info: Some(crate::models::wallet::WalletBackupInfo {
            backup_location: crate::models::wallet::BackupLocation::PaperBackup,
            last_backup_at: Some(chrono::Utc::now()),
            backup_verified: true,
            backup_copies: 2,
            recovery_phrase_backup_method: Some(
                crate::models::wallet::RecoveryPhraseBackupMethod::Metal,
            ),
        }),
        security_settings: crate::models::wallet::WalletSecuritySettings {
            require_biometric: true,
            address_book_only: true,
            address_whitelist: vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string()],
            ..Default::default()
        },
        custom_data: {
            let mut map = std::collections::HashMap::new();
            map.insert("key".to_string(), "value".to_string());
            map
        },
    };
    wallet.add_address(make_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0));

    let created = repo.create(&wallet).await.unwrap();
    assert_eq!(created.metadata.tags, vec!["cold-storage".to_string()]);
    assert_eq!(created.metadata.notes.as_deref(), Some("keep offline"));
    assert_eq!(created.metadata.platform.as_deref(), Some("Ledger"));
    assert_eq!(created.metadata.purpose.as_deref(), Some("savings"));
    assert_eq!(
        created.metadata.associated_services,
        vec!["service-a".to_string()]
    );
    let backup = created.metadata.backup_info.as_ref().unwrap();
    assert!(backup.backup_verified);
    assert_eq!(backup.backup_copies, 2);
    assert!(created.metadata.security_settings.require_biometric);
    assert_eq!(
        created.metadata.custom_data.get("key").map(String::as_str),
        Some("value")
    );

    // Addresses survive the round-trip too (including optional fields).
    assert_eq!(created.addresses.len(), 1);
    assert_eq!(
        created.addresses[0].derivation_path.as_deref(),
        Some("m/44'/0'/0'/0/0")
    );
    assert_eq!(created.addresses[0].balance.as_deref(), Some("1000"));
    assert!(created.addresses[0].last_activity.is_some());

    // If the metadata row disappears the loader falls back to defaults.
    sqlx::query("DELETE FROM wallet_metadata WHERE wallet_id = ?")
        .bind(created.id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    let refetched = repo.find_by_id(&created.id).await.unwrap().unwrap();
    assert_eq!(refetched.metadata, WalletMetadata::default());
}

#[tokio::test]
async fn test_update_replaces_addresses() {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let identity_id = seed_identity(&db).await;
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let mut wallet = make_wallet(identity_id, "Addr Swap");
    wallet.add_address(make_address("old-address", 0));
    let created = repo.create(&wallet).await.unwrap();
    assert_eq!(created.addresses.len(), 1);

    let mut updated = created.clone();
    updated.addresses = vec![
        make_address("new-address-1", 0),
        make_address("new-address-2", 1),
    ];
    let result = repo.update(&updated).await.unwrap();
    assert_eq!(result.addresses.len(), 2);
    assert!(result
        .addresses
        .iter()
        .any(|a| a.address == "new-address-1"));
    assert!(result
        .addresses
        .iter()
        .any(|a| a.address == "new-address-2"));

    assert!(!repo
        .update_address_usage(&created.id, "old-address", true)
        .await
        .unwrap());
}

#[test]
fn test_timestamp_to_datetime_helper() {
    let dt = timestamp_to_datetime(1_700_000_000).unwrap();
    assert_eq!(dt.timestamp(), 1_700_000_000);
    assert_eq!(*dt.offset(), chrono::Utc);

    // Values beyond chrono's representable range surface as a Database
    // error instead of a panic.
    assert!(matches!(
        timestamp_to_datetime(i64::MAX),
        Err(PersonaError::Database(_))
    ));
}
