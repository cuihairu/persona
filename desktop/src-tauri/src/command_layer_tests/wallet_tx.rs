//! Command-layer integration tests — `wallet_tx` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn wallet_transaction_commands_round_trip_and_rejections() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Tx Wallet".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallet = resp.data.expect("wallet generated");

    // Bad UUID and unknown wallet rejections come before any DB work.
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: "not-a-uuid".to_string(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1".to_string(),
            fee: "21000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid wallet_id"));

    let missing = uuid::Uuid::new_v4().to_string();
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: missing.clone(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1".to_string(),
            fee: "21000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Wallet not found"));

    // Create the pending request with full gas metadata (legacy EIP-155).
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id.clone(),
            to_address: "0x1111111111111111111111111111111111111111".to_string(),
            amount: "1000000000000000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("20000000000".to_string()),
            gas_limit: Some(21000),
            nonce: Some(0),
            memo: Some("integration".to_string()),
            expires_in_minutes: Some(30),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let tx = resp.data.expect("transaction created");
    let tx_id = tx["id"].as_str().expect("transaction id").to_string();
    assert_eq!(
        tx["to_address"],
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(tx["network"], "Ethereum");

    // The pending listing contains it.
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"].as_str(), Some(tx_id.as_str()));

    // Bad uuid / unknown transaction on the sign path.
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: "not-a-uuid".to_string(),
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid transaction_id"));

    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Transaction not found"));

    // Wrong password fails key derivation without storing a signature.
    // Boundary discipline: the caller sees an ApiResponse error body,
    // never an invoke-layer Err(String).
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wrong-pass".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to derive signing key")),
        "got: {:?}",
        resp.error
    );

    // Correct password: sign → local verify → raw assembly → stored.
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let signed = resp.data.expect("signed transaction returned");
    let hash = signed["transaction_hash"].as_str().expect("tx hash");
    assert!(
        hash.starts_with("0x") && hash.len() == 66,
        "EIP-155 hash is a 32-byte hex: {hash}"
    );
    // raw_signed_transaction is a Vec<u8>, so it arrives as a JSON array of
    // bytes — a non-empty one proves the EIP-155 assembly succeeded (the
    // audit-only fallback would leave it empty).
    assert!(
        signed["raw_signed_transaction"]
            .as_array()
            .is_some_and(|raw| !raw.is_empty()),
        "raw transaction assembled"
    );

    // Re-signing the same request reproduces the identical RFC 6979
    // deterministic signature and hash, which the store's
    // UNIQUE(transaction_hash) guard refuses to duplicate. That rejection is
    // the current dedup contract (prevents double-broadcast records).
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to store signed transaction")),
        "got: {:?}",
        resp.error
    );
}
#[tokio::test]
async fn wallet_sign_refuses_address_poisoning_without_ack() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_generate(
        identity_id.clone(),
        WalletGenerateRequest {
            name: "Poison Wallet".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallet = resp.data.expect("wallet generated");
    let wallet_id = wallet.wallet_id.clone();
    let own = wallet.first_address.clone();
    assert!(own.len() >= 12);

    // 仿冒地址：与钱包自身地址前 6 + 后 6 字符相同、中段不同
    let spoof = format!(
        "{}{}{}",
        &own[..6],
        "0".repeat(own.len() - 12),
        &own[own.len() - 6..]
    );

    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id,
            to_address: spoof.clone(),
            amount: "1000000000000000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("20000000000".to_string()),
            gas_limit: Some(21000),
            nonce: Some(0),
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let tx_id = resp.data.expect("transaction created")["id"]
        .as_str()
        .expect("transaction id")
        .to_string();

    // 缺 ack：拒绝签名，且不落 signed_transactions。
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id.clone(),
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("address-poisoning spoof")),
        "got: {:?}",
        resp.error
    );

    // 带 ack（桌面确认弹窗展示告警后的二次确认）：放行并正常落库。
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: true,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let signed = resp.data.expect("signed transaction returned");
    assert!(
        signed["transaction_hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("0x")),
        "hash: {:?}",
        signed["transaction_hash"]
    );
}
/// 多链签名路径（命令层可达部分）：
/// - Bitcoin：命令层无法提供 UTXO inputs（metadata 恒空），build_raw 失败 →
///   走 audit-only 落库（raw 为空、hash 带 `audit:` 前缀）——这是无 UTXO
///   集时唯一可落库的签名记录路径。
/// - Solana：命令层无法携带 raw_transaction_data，签名直接被拒。
#[tokio::test]
async fn wallet_sign_bitcoin_audit_only_and_solana_rejection() {
    let (app, identity_id) = app_with_identity().await;
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Bitcoin 单地址钱包（mnemonic 派生 P2WPKH）。
    let resp = wallet_import(
        identity_id.clone(),
        WalletImportRequest {
            name: "Btc Sign".to_string(),
            network: "Bitcoin".to_string(),
            import_type: "mnemonic".to_string(),
            data: mnemonic.to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let btc = resp.data.expect("btc wallet");

    // 创建 pending BTC 交易。
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: btc.id.clone(),
            to_address: "bc1qexample0recipient0address".to_string(),
            amount: "1000".to_string(),
            fee: "150".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: Some("audit-only".to_string()),
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending btc tx");
    let tx_id = pending["id"].as_str().expect("tx id").to_string();

    // 签名落库：audit-only 记录。
    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "btc sign failed: {:?}", resp.error);
    let signed = resp.data.expect("signed btc tx");
    assert!(
        signed["transaction_hash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("audit:"),
        "audit-only record must carry an audit: hash, got {signed}"
    );
    assert!(
        signed["raw_signed_transaction"]
            .as_array()
            .is_some_and(|raw| raw.is_empty()),
        "audit-only record must not carry raw bytes"
    );

    // Solana 钱包：签名因缺 raw_transaction_data 被拒。
    let resp = wallet_import(
        identity_id,
        WalletImportRequest {
            name: "Sol Sign".to_string(),
            network: "Solana".to_string(),
            import_type: "mnemonic".to_string(),
            data: mnemonic.to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let sol = resp.data.expect("sol wallet");

    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: sol.id.clone(),
            to_address: "SolanaRecipientAddress11111111111111111111111".to_string(),
            amount: "1000".to_string(),
            fee: "5000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending sol tx");
    let tx_id = pending["id"].as_str().expect("tx id").to_string();

    let resp = wallet_sign_transaction(
        WalletSignTransactionRequest {
            transaction_id: tx_id,
            password: "wallet-pass-123".to_string(),
            confirm_poisoning_check: false,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Failed to sign transaction")),
        "solana sign must fail without raw_transaction_data: {:?}",
        resp.error
    );
}
/// wallet_pending_transactions 列出未签名请求；db_path 缺失时报
/// "Database path unavailable"（wallet_db 的 None 臂）。
#[tokio::test]
async fn wallet_pending_transactions_round_trip_and_missing_db() {
    let (app, identity_id) = app_with_identity().await;

    let resp = wallet_generate(
        identity_id,
        WalletGenerateRequest {
            name: "Pending Wallet".to_string(),
            network: "Ethereum".to_string(),
            wallet_type: "hd".to_string(),
            password: "wallet-pass-123".to_string(),
            address_count: Some(1),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let wallet = resp.data.expect("wallet generated");

    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id.clone(),
            to_address: "0x2222222222222222222222222222222222222222".to_string(),
            amount: "1000000000000000000".to_string(),
            fee: "21000".to_string(),
            gas_price: Some("20000000000".to_string()),
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("pending request created");
    let request_id = created["id"].as_str().expect("request id").to_string();

    // 列出 pending：包含刚创建的请求。
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let pending = resp.data.expect("pending list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"].as_str(), Some(request_id.as_str()));

    // db_path 缺失：wallet_db 报 "Database path unavailable"。
    {
        let state = app.state::<AppState>();
        *state.db_path.lock().await = None;
    }
    let resp = wallet_pending_transactions(wallet.wallet_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
    let resp = wallet_create_transaction(
        WalletCreateTransactionRequest {
            wallet_id: wallet.wallet_id,
            to_address: "0x2222222222222222222222222222222222222222".to_string(),
            amount: "1".to_string(),
            fee: "21000".to_string(),
            gas_price: None,
            gas_limit: None,
            nonce: None,
            memo: None,
            expires_in_minutes: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database path unavailable. Initialize the service first.")
    );
}
