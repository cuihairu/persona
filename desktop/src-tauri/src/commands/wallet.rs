use super::*;

/// 助记词校验结果：词数与（失败时的）具体错误，供表单实时反馈
#[derive(serde::Serialize)]
pub struct MnemonicValidation {
    pub valid: bool,
    pub word_count: Option<usize>,
    pub error: Option<String>,
}

/// 校验助记词（BIP-39 词表 + 校验和）：纯计算，不触库、不留存。
#[command(rename_all = "snake_case")]
pub async fn wallet_validate_mnemonic(
    phrase: String,
) -> std::result::Result<ApiResponse<MnemonicValidation>, String> {
    let trimmed = phrase.trim().to_string();
    if trimmed.is_empty() {
        return Ok(ApiResponse::success(MnemonicValidation {
            valid: false,
            word_count: Some(0),
            error: Some("Mnemonic phrase is empty".to_string()),
        }));
    }
    let words = trimmed.split_whitespace().count();
    match SecureMnemonic::from_phrase(&trimmed) {
        Ok(m) => Ok(ApiResponse::success(MnemonicValidation {
            valid: true,
            word_count: Some(m.word_count()),
            error: None,
        })),
        Err(e) => Ok(ApiResponse::success(MnemonicValidation {
            valid: false,
            word_count: Some(words),
            error: Some(e.to_string()),
        })),
    }
}

/// 生成 BIP-39 助记词（12/15/18/21/24 词）：纯计算，不触库、不留存。
#[command(rename_all = "snake_case")]
pub async fn wallet_generate_mnemonic(
    word_count: u32,
) -> std::result::Result<ApiResponse<String>, String> {
    let count = match word_count {
        12 => MnemonicWordCount::Words12,
        15 => MnemonicWordCount::Words15,
        18 => MnemonicWordCount::Words18,
        21 => MnemonicWordCount::Words21,
        24 => MnemonicWordCount::Words24,
        other => {
            return Ok(ApiResponse::error(format!(
                "Unsupported word count: {}. Use 12/15/18/21/24.",
                other
            )))
        }
    };
    match SecureMnemonic::generate(count) {
        Ok(m) => Ok(ApiResponse::success(m.phrase())),
        Err(e) => Ok(ApiResponse::error(e.to_string())),
    }
}

#[command(rename_all = "snake_case")]
pub async fn wallet_list(
    identity_id: Option<String>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletListResponse>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallets = match identity_id {
        Some(identity_id) => {
            let uuid = ok_or_error_response!(Uuid::from_str(&identity_id)
                .map_err(|_| "Invalid identity UUID format".to_string()));
            ok_or_error_response!(repo.find_by_identity(&uuid).await)
        }
        None => ok_or_error_response!(repo.find_all().await),
    };

    let serializable = wallets
        .into_iter()
        .map(|wallet| SerializableWallet {
            id: wallet.id.to_string(),
            name: wallet.name,
            network: wallet.network.to_string(),
            wallet_type: format!("{:?}", wallet.wallet_type),
            balance: "-".to_string(),
            address_count: wallet.addresses.len(),
            watch_only: wallet.watch_only,
            security_level: wallet.security_level.to_string(),
            created_at: wallet.created_at.to_rfc3339(),
            updated_at: wallet.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(ApiResponse::success(WalletListResponse {
        wallets: serializable,
    }))
}

#[command(rename_all = "snake_case")]
pub async fn wallet_list_addresses(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletAddressesResponse>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let uuid = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );
    let wallet: CryptoWallet = match repo.find_by_id(&uuid).await.map_err(|e| e.to_string())? {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let addresses = wallet
        .addresses
        .into_iter()
        .map(|addr| SerializableWalletAddress {
            address: addr.address,
            address_type: match addr.address_type {
                persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
                persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
                persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
                persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
                persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
                persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
                persona_core::models::wallet::AddressType::Custom(name) => name,
            },
            index: addr.index,
            used: addr.used,
            balance: addr.balance.unwrap_or_else(|| "-".to_string()),
            derivation_path: addr.derivation_path,
        })
        .collect();

    Ok(ApiResponse::success(WalletAddressesResponse { addresses }))
}

#[command(rename_all = "snake_case")]
pub async fn wallet_generate(
    identity_id: String,
    request: WalletGenerateRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WalletGenerateResponse>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let identity_id = ok_or_error_response!(
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())
    );
    let network = ok_or_error_response!(parse_network(&request.network));
    let address_count = request.address_count.unwrap_or(5);

    if request.password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let mnemonic = ok_or_error_response!(
        persona_core::crypto::wallet_crypto::SecureMnemonic::generate(
            persona_core::crypto::wallet_crypto::MnemonicWordCount::Words24,
        )
    );
    let mnemonic_phrase = mnemonic.phrase();

    let derivation_path = match request.wallet_type.to_lowercase().as_str() {
        "hd" | "hierarchical" | "hierarchical_deterministic" => None,
        other => {
            return Ok(ApiResponse::error(format!(
                "Unsupported wallet_type '{}'. Use 'hd'.",
                other
            )))
        }
    };

    let wallet = ok_or_error_response!(
        persona_core::crypto::wallet_import_export::import_from_mnemonic(
            identity_id,
            request.name.clone(),
            &mnemonic_phrase,
            "",
            network,
            derivation_path,
            address_count,
            &request.password,
        )
    );

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = ok_or_error_response!(repo.create(&wallet).await);
    let first_address = created
        .addresses
        .first()
        .map(|addr| addr.address.clone())
        .unwrap_or_else(|| "-".to_string());

    Ok(ApiResponse::success(WalletGenerateResponse {
        wallet_id: created.id.to_string(),
        name: created.name,
        network: created.network.to_string(),
        mnemonic: mnemonic_phrase,
        first_address,
    }))
}

#[command(rename_all = "snake_case")]
pub async fn wallet_import(
    identity_id: String,
    request: WalletImportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWallet>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let identity_id = ok_or_error_response!(
        Uuid::from_str(&identity_id).map_err(|_| "Invalid identity UUID format".to_string())
    );
    let wallet = match import_wallet_from_request(identity_id, &request) {
        Ok(wallet) => wallet,
        Err(error) => return Ok(ApiResponse::error(error)),
    };

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let created = ok_or_error_response!(repo.create(&wallet).await);
    Ok(ApiResponse::success(serialize_wallet_summary(&created)))
}

#[command(rename_all = "snake_case")]
pub async fn wallet_add_address(
    wallet_id: String,
    password: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<SerializableWalletAddress>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );
    if password.len() < 8 {
        return Ok(ApiResponse::error(
            "Wallet password must be at least 8 characters".to_string(),
        ));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet: CryptoWallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    if wallet.watch_only {
        return Ok(ApiResponse::error(
            "Address generation for watch-only wallets is not implemented yet.".to_string(),
        ));
    }

    if !matches!(
        wallet.wallet_type,
        persona_core::models::wallet::WalletType::HierarchicalDeterministic { .. }
    ) {
        return Ok(ApiResponse::error(
            "Address generation is only supported for HD wallets.".to_string(),
        ));
    }

    let derivation_path = wallet
        .derivation_path
        .clone()
        .unwrap_or_else(|| CryptoWallet::recommended_derivation_path(&wallet.network, 0));

    let next_index = wallet
        .addresses
        .iter()
        .map(|addr| addr.index)
        .max()
        .map(|v| v + 1)
        .unwrap_or(0);

    let encrypted_key: persona_core::crypto::wallet_encryption::EncryptedWalletKey = ok_or_error_response_ctx!(
        serde_json::from_slice(&wallet.encrypted_private_key),
        "Invalid wallet key encoding: {}"
    );
    let master_key = ok_or_error_response!(
        persona_core::crypto::wallet_encryption::decrypt_master_key(&encrypted_key, &password)
    );

    let parent = ok_or_error_response!(master_key.derive_path(&derivation_path));
    let child = ok_or_error_response!(parent.derive_child(next_index, false));

    let (address_string, address_type) = match wallet.network {
        BlockchainNetwork::Bitcoin => (
            ok_or_error_response!(
                persona_core::crypto::address_generator::generate_bitcoin_address(
                    &child,
                    persona_core::crypto::address_generator::BitcoinAddressType::P2WPKH,
                    false,
                )
            ),
            persona_core::models::wallet::AddressType::P2WPKH,
        ),
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => (
            ok_or_error_response!(
                persona_core::crypto::address_generator::generate_ethereum_address_checksummed(
                    &child
                )
            ),
            persona_core::models::wallet::AddressType::Ethereum,
        ),
        other => {
            return Ok(ApiResponse::error(format!(
                "Address generation not implemented for {}",
                other
            )))
        }
    };

    let wallet_address = persona_core::models::wallet::WalletAddress {
        address: address_string,
        address_type,
        derivation_path: Some(format!("{}/{}", derivation_path, next_index)),
        index: next_index,
        used: false,
        balance: None,
        last_activity: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now(),
    };

    ok_or_error_response!(repo.add_address(&wallet_id, &wallet_address).await);
    ok_or_error_response!(repo.touch(&wallet_id).await);

    Ok(ApiResponse::success(serialize_wallet_address(
        wallet_address,
    )))
}

#[command(rename_all = "snake_case")]
pub async fn wallet_delete(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let repo = CryptoWalletRepository::new(Arc::new(db));
    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet UUID format".to_string())
    );

    let deleted = ok_or_error_response!(repo.delete(&wallet_id).await);
    if !deleted {
        return Ok(ApiResponse::error("Wallet not found".to_string()));
    }

    Ok(ApiResponse::success(true))
}

#[command]
pub async fn wallet_export(
    request: WalletExportRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<String>, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Ok(ApiResponse::error("Service not initialized".to_string())),
        }
    };
    if !service_unlocked {
        return Ok(ApiResponse::error("Service is locked".to_string()));
    }

    let db_path = db_path_or_return!(state);

    let db = open_db_or_return!(db_path);

    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet_id =
        ok_or_error_response!(Uuid::from_str(&request.wallet_id)
            .map_err(|_| "Invalid wallet UUID format".to_string()));
    let wallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let exported = match export_wallet_from_request(&wallet, &request) {
        Ok(exported) => exported,
        Err(error) => return Ok(ApiResponse::error(error)),
    };

    Ok(ApiResponse::success(exported))
}

#[derive(Debug, Deserialize)]
pub struct WalletCreateTransactionRequest {
    pub wallet_id: String,
    pub to_address: String,
    /// 最小单位字符串（wei / satoshi / lamport）
    pub amount: String,
    pub fee: String,
    pub gas_price: Option<String>,
    pub gas_limit: Option<u64>,
    pub nonce: Option<u64>,
    pub memo: Option<String>,
    pub expires_in_minutes: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct WalletSignTransactionRequest {
    pub transaction_id: String,
    pub password: String,
    /// 桌面确认弹窗展示投毒告警后用户再次确认；缺省按未确认处理（拒绝签名）。
    #[serde(default)]
    pub confirm_poisoning_check: bool,
}

/// 从数据库加载钱包交易仓库。
///
/// 钱包命令绕过 PersonaService 直用 `CryptoWalletRepository`（既有架构决策）。
pub(crate) async fn wallet_db(
    state: &State<'_, AppState>,
) -> std::result::Result<Database, String> {
    let service_unlocked = {
        let guard = state.service.lock().await;
        match guard.as_ref() {
            Some(service) => service.is_unlocked(),
            None => return Err("Service not initialized".to_string()),
        }
    };
    if !service_unlocked {
        return Err("Service is locked".to_string());
    }

    // helper 内部：Err(String) 不跨命令边界，走手写样板（宏会往
    // ApiResponse 边界 return，类型在这里不成立）。
    let db_path = {
        let guard = state.db_path.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?
    };

    let db = Database::from_file(&db_path)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    db.migrate()
        .await
        .map_err(|e| format!("Database migration failed: {}", e))?;
    Ok(db)
}

/// Create a pending transaction request for a wallet
#[command]
pub async fn wallet_create_transaction(
    request: WalletCreateTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    use persona_core::models::wallet::TransactionRequest;

    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&request.wallet_id).map_err(|_| "Invalid wallet_id".to_string())
    );
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let wallet = match ok_or_error_response!(repo.find_by_id(&wallet_id).await) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let from_address = ok_or_error_response!(wallet
        .addresses
        .first()
        .map(|a| a.address.clone())
        .ok_or_else(|| "Wallet has no addresses".to_string()));

    let transaction = TransactionRequest {
        id: Uuid::new_v4(),
        wallet_id: wallet.id,
        network: wallet.network.clone(),
        from_address,
        to_address: request.to_address,
        amount: request.amount,
        fee: request.fee,
        gas_price: request.gas_price,
        gas_limit: request.gas_limit,
        nonce: request.nonce,
        memo: request.memo,
        raw_transaction_data: None,
        required_signatures: 1,
        created_at: chrono::Utc::now(),
        expires_at: request
            .expires_in_minutes
            .map(|mins| chrono::Utc::now() + chrono::Duration::minutes(mins as i64)),
        metadata: HashMap::new(),
    };

    let created = ok_or_error_response_ctx!(
        repo.create_transaction_request(&transaction).await,
        "Failed to create transaction: {}"
    );
    let value = ok_or_error_response_ctx!(
        serde_json::to_value(&created),
        "Failed to serialize transaction: {}"
    );
    Ok(ApiResponse::success(value))
}

/// List pending (unsigned) transaction requests for a wallet
#[command(rename_all = "snake_case")]
pub async fn wallet_pending_transactions(
    wallet_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<Vec<serde_json::Value>>, String> {
    let wallet_id = ok_or_error_response!(
        Uuid::from_str(&wallet_id).map_err(|_| "Invalid wallet_id".to_string())
    );
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let requests = ok_or_error_response_ctx!(
        repo.get_pending_requests(&wallet_id).await,
        "Failed to list pending transactions: {}"
    );
    let values = ok_or_error_response!(requests
        .into_iter()
        .map(|r| serde_json::to_value(&r).map_err(|e| e.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>());
    Ok(ApiResponse::success(values))
}

/// Sign a pending transaction (derive key → sign → verify → persist).
///
/// 流程与 CLI `wallet --sign` 一致：签名后先本地验签，验签失败拒绝落库。
#[command]
pub async fn wallet_sign_transaction(
    request: WalletSignTransactionRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    let request_id =
        ok_or_error_response!(Uuid::from_str(&request.transaction_id)
            .map_err(|_| "Invalid transaction_id".to_string()));
    let db = wallet_db_or_return!(state);
    let repo = CryptoWalletRepository::new(Arc::new(db));

    let transaction = match ok_or_error_response_ctx!(
        repo.get_request_by_id(&request_id).await,
        "Failed to load transaction: {}"
    ) {
        Some(tx) => tx,
        None => return Ok(ApiResponse::error("Transaction not found".to_string())),
    };

    let wallet = match ok_or_error_response_ctx!(
        repo.find_by_id(&transaction.wallet_id).await,
        "Failed to load wallet: {}"
    ) {
        Some(wallet) => wallet,
        None => return Ok(ApiResponse::error("Wallet not found".to_string())),
    };

    let signed = ok_or_error_response!(
        sign_wallet_transaction(
            &repo,
            &wallet,
            &transaction,
            &request.password,
            request.confirm_poisoning_check
        )
        .await
    );
    let value = ok_or_error_response_ctx!(
        serde_json::to_value(&signed),
        "Failed to serialize signed transaction: {}"
    );
    Ok(ApiResponse::success(value))
}

/// 按地址派生签名钥 → 签名 → 本地验签 → 落库。
///
/// 与 CLI `CreateTransaction { sign: true }` 保持一致；验签失败时
/// **拒绝落库**（不产生 signed_transactions 记录）。
pub(crate) async fn sign_wallet_transaction(
    repo: &CryptoWalletRepository,
    wallet: &CryptoWallet,
    request: &persona_core::models::wallet::TransactionRequest,
    password: &str,
    confirmed_poisoning_check: bool,
) -> std::result::Result<persona_core::models::wallet::SignedTransaction, String> {
    use persona_core::crypto::transaction_signing::{
        build_raw_transaction, sign_transaction, verify_ethereum_transaction,
        verify_solana_transaction,
    };
    use persona_core::crypto::wallet_import_export::signing_key_for_address;
    use persona_core::crypto::{detect_address_poisoning, enforce_poisoning_check};
    use persona_core::models::wallet::{BroadcastStatus, SignedTransaction};
    use sha2::Digest;

    // 后端防投毒强制检查（WALLET_DESIGN.md §5 第 3 条）：不只依赖桌面确认
    // 弹窗的启发式——弹窗展示告警后用户再次确认才会带 ack，否则拒绝签名。
    let known_addresses: Vec<String> = wallet.addresses.iter().map(|a| a.address.clone()).collect();
    if let Some(mimicked) = detect_address_poisoning(&request.to_address, &known_addresses) {
        tracing::warn!(
            to_address = %request.to_address,
            mimicked = %mimicked,
            confirmed = confirmed_poisoning_check,
            "backend address-poisoning heuristic hit on wallet sign path"
        );
    }
    enforce_poisoning_check(
        &request.to_address,
        &known_addresses,
        confirmed_poisoning_check,
    )
    .map_err(|e| e.to_string())?;

    let key = signing_key_for_address(wallet, password, &request.from_address)
        .map_err(|e| format!("Failed to derive signing key (wrong password?): {}", e))?;
    let signature = sign_transaction(request, &key)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    // 本地验签：失败一律拒绝落库
    match request.network {
        BlockchainNetwork::Ethereum
        | BlockchainNetwork::Polygon
        | BlockchainNetwork::Arbitrum
        | BlockchainNetwork::Optimism
        | BlockchainNetwork::BinanceSmartChain => {
            let ok = verify_ethereum_transaction(request, &signature)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        BlockchainNetwork::Solana => {
            let message = request
                .raw_transaction_data
                .clone()
                .ok_or_else(|| "Solana signing requires raw_transaction_data".to_string())?;
            let ok = verify_solana_transaction(&signature, &message)
                .map_err(|e| format!("Verification error: {}", e))?;
            if !ok {
                return Err(
                    "Signature verification failed; refusing to store signed transaction"
                        .to_string(),
                );
            }
        }
        _ => {}
    }

    // Bitcoin 等需要 UTXO 集的网络：raw 组装失败时只落审计签名记录
    let (raw_bytes, tx_hash) = match build_raw_transaction(request, &key) {
        Ok(raw) => (raw.raw, raw.hash),
        Err(e) => {
            tracing::warn!(
                "raw transaction not assembled ({}); storing audit-only record",
                e
            );
            let audit_hash = format!(
                "audit:{}",
                hex::encode(sha2::Sha256::digest(&signature.signature))
            );
            (Vec::new(), audit_hash)
        }
    };

    let signed = SignedTransaction {
        id: Uuid::new_v4(),
        request: request.clone(),
        signatures: vec![signature],
        raw_signed_transaction: raw_bytes,
        transaction_hash: tx_hash,
        signed_at: chrono::Utc::now(),
        broadcast_status: BroadcastStatus::NotBroadcast,
    };

    repo.create_signed_transaction(&signed)
        .await
        .map_err(|e| format!("Failed to store signed transaction: {}", e))
}

pub(crate) fn parse_network(network_str: &str) -> std::result::Result<BlockchainNetwork, String> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(BlockchainNetwork::Bitcoin),
        "ethereum" | "eth" => Ok(BlockchainNetwork::Ethereum),
        "solana" | "sol" => Ok(BlockchainNetwork::Solana),
        "bitcoin-cash" | "bitcoin cash" | "bitcoincash" | "bch" => {
            Ok(BlockchainNetwork::BitcoinCash)
        }
        "litecoin" | "ltc" => Ok(BlockchainNetwork::Litecoin),
        "dogecoin" | "doge" => Ok(BlockchainNetwork::Dogecoin),
        "polygon" | "matic" => Ok(BlockchainNetwork::Polygon),
        "arbitrum" | "arb" => Ok(BlockchainNetwork::Arbitrum),
        "optimism" | "op" => Ok(BlockchainNetwork::Optimism),
        "binance" | "bsc" | "bnb" | "binance smart chain" => {
            Ok(BlockchainNetwork::BinanceSmartChain)
        }
        other => Ok(BlockchainNetwork::Custom(other.to_string())),
    }
}

pub(crate) fn serialize_wallet_address(
    addr: persona_core::models::wallet::WalletAddress,
) -> SerializableWalletAddress {
    SerializableWalletAddress {
        address: addr.address,
        address_type: match addr.address_type {
            persona_core::models::wallet::AddressType::P2PKH => "P2PKH".to_string(),
            persona_core::models::wallet::AddressType::P2SH => "P2SH".to_string(),
            persona_core::models::wallet::AddressType::P2WPKH => "P2WPKH".to_string(),
            persona_core::models::wallet::AddressType::P2TR => "P2TR".to_string(),
            persona_core::models::wallet::AddressType::Ethereum => "ETH".to_string(),
            persona_core::models::wallet::AddressType::Solana => "SOL".to_string(),
            persona_core::models::wallet::AddressType::Custom(name) => name,
        },
        index: addr.index,
        used: addr.used,
        balance: addr.balance.unwrap_or_else(|| "-".to_string()),
        derivation_path: addr.derivation_path,
    }
}

pub(crate) fn serialize_wallet_summary(wallet: &CryptoWallet) -> SerializableWallet {
    SerializableWallet {
        id: wallet.id.to_string(),
        name: wallet.name.clone(),
        network: wallet.network.to_string(),
        wallet_type: format!("{:?}", wallet.wallet_type),
        balance: "-".to_string(),
        address_count: wallet.addresses.len(),
        watch_only: wallet.watch_only,
        security_level: wallet.security_level.to_string(),
        created_at: wallet.created_at.to_rfc3339(),
        updated_at: wallet.updated_at.to_rfc3339(),
    }
}

pub(crate) fn import_wallet_from_request(
    identity_id: Uuid,
    request: &WalletImportRequest,
) -> std::result::Result<CryptoWallet, String> {
    if request.password.len() < 8 {
        return Err("Wallet password must be at least 8 characters".to_string());
    }

    let address_count = request.address_count.unwrap_or(5);
    match request.import_type.to_lowercase().as_str() {
        "mnemonic" | "phrase" | "seed" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_mnemonic(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                "",
                network,
                None,
                address_count,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "private_key" | "privatekey" | "key" => {
            let network = parse_network(&request.network)?;
            persona_core::crypto::wallet_import_export::import_from_private_key(
                identity_id,
                request.name.clone(),
                request.data.trim(),
                network,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        "wif" => persona_core::crypto::wallet_import_export::import_from_wif(
            identity_id,
            request.name.clone(),
            request.data.trim(),
            &request.password,
        )
        .map_err(|e| e.to_string()),
        "keystore" => {
            // Keystore JSON is defined over Ethereum-style secp256k1 keys;
            // the format itself carries no network hint.
            let secret = persona_core::crypto::wallet_encryption::import_from_keystore(
                request.data.trim(),
                &request.password,
            )
            .map_err(|e| e.to_string())?;
            persona_core::crypto::wallet_import_export::import_from_private_key(
                identity_id,
                request.name.clone(),
                &hex::encode(secret),
                BlockchainNetwork::Ethereum,
                &request.password,
            )
            .map_err(|e| e.to_string())
        }
        other => Err(format!(
            "Unsupported import_type '{}'. Use 'mnemonic', 'private_key', 'wif', or 'keystore'.",
            other
        )),
    }
}

pub(crate) fn export_wallet_from_request(
    wallet: &CryptoWallet,
    request: &WalletExportRequest,
) -> std::result::Result<String, String> {
    let format = persona_core::crypto::wallet_import_export::parse_export_format(&request.format)
        .map_err(|e| e.to_string())?;

    match format {
        persona_core::crypto::wallet_import_export::ExportFormat::Json => {
            persona_core::crypto::wallet_import_export::export_to_json(
                wallet,
                request.include_private,
                request.password.as_deref(),
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Mnemonic => {
            persona_core::crypto::wallet_import_export::export_mnemonic(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for mnemonic export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Xpub => {
            persona_core::crypto::wallet_import_export::export_xpub(wallet)
                .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::PrivateKey => {
            persona_core::crypto::wallet_import_export::export_private_key(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for private key export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Wif => {
            persona_core::crypto::wallet_import_export::export_to_wif(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for WIF export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
        persona_core::crypto::wallet_import_export::ExportFormat::Keystore => {
            persona_core::crypto::wallet_import_export::export_keystore(
                wallet,
                request
                    .password
                    .as_deref()
                    .ok_or_else(|| "Password required for keystore export".to_string())?,
            )
            .map_err(|e| e.to_string())
        }
    }
}
