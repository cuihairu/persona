use super::*;
use persona_core::models::Identity;

async fn setup_wallet_test_db() -> (tempfile::TempDir, Database, Identity) {
    // 委托共享夹具（test_support.rs），避免每套测试重建样板
    let fixture = crate::test_support::test_db().await;
    (fixture._dir, fixture.db, fixture.identity)
}

#[tokio::test]
async fn wallet_import_request_imports_bitcoin_wif_as_single_address_wallet() {
    let (_dir, _db, identity) = setup_wallet_test_db().await;
    let request = WalletImportRequest {
        name: "BTC WIF".to_string(),
        network: "Bitcoin".to_string(),
        import_type: "wif".to_string(),
        data: "KzgibHVnBeHWb4vnmrqXfJcEcfPQbYC2xPxz932rCiHxSc8u3GhA".to_string(),
        password: "test_password".to_string(),
        address_count: None,
    };

    let wallet = import_wallet_from_request(identity.id, &request).unwrap();

    assert_eq!(wallet.network, BlockchainNetwork::Bitcoin);
    assert!(matches!(
        wallet.wallet_type,
        persona_core::models::wallet::WalletType::SingleAddress
    ));
    assert_eq!(wallet.addresses.len(), 1);
    assert!(!wallet.watch_only);
}

#[tokio::test]
async fn wallet_import_request_rejects_short_passwords() {
    let (_dir, _db, identity) = setup_wallet_test_db().await;
    let request = WalletImportRequest {
        name: "Bad Wallet".to_string(),
        network: "Ethereum".to_string(),
        import_type: "private_key".to_string(),
        data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
        password: "short".to_string(),
        address_count: None,
    };

    let error = import_wallet_from_request(identity.id, &request).unwrap_err();
    assert_eq!(error, "Wallet password must be at least 8 characters");
}

#[tokio::test]
async fn wallet_export_request_requires_password_for_wif() {
    let (_dir, _db, identity) = setup_wallet_test_db().await;
    let import_request = WalletImportRequest {
        name: "BTC WIF".to_string(),
        network: "Bitcoin".to_string(),
        import_type: "private_key".to_string(),
        data: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        password: "test_password".to_string(),
        address_count: None,
    };
    let wallet = import_wallet_from_request(identity.id, &import_request).unwrap();

    let export_request = WalletExportRequest {
        wallet_id: wallet.id.to_string(),
        format: "wif".to_string(),
        include_private: false,
        password: None,
    };

    let error = export_wallet_from_request(&wallet, &export_request).unwrap_err();
    assert_eq!(error, "Password required for WIF export");
}

#[tokio::test]
async fn wallet_delete_removes_wallet_from_repository() {
    let (_dir, db, identity) = setup_wallet_test_db().await;
    let repo = CryptoWalletRepository::new(Arc::new(db));
    let request = WalletImportRequest {
        name: "ETH Wallet".to_string(),
        network: "Ethereum".to_string(),
        import_type: "private_key".to_string(),
        data: "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b".to_string(),
        password: "test_password".to_string(),
        address_count: None,
    };
    let wallet = import_wallet_from_request(identity.id, &request).unwrap();
    let created = repo.create(&wallet).await.unwrap();

    let deleted = repo.delete(&created.id).await.unwrap();
    let fetched = repo.find_by_id(&created.id).await.unwrap();

    assert!(deleted);
    assert!(fetched.is_none());
}

// -------------------------------------------------------------------------
// extract_secret_field：字段 × 类型矩阵
// -------------------------------------------------------------------------

fn password_data() -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: "hunter2".to_string(),
        email: Some("a@b.c".to_string()),
        security_questions: vec![SecurityQuestion {
            question: "Pet?".to_string(),
            answer: "Cat".to_string(),
        }],
    })
}

#[test]
fn reveal_extracts_password_and_questions() {
    let data = password_data();
    assert_eq!(extract_secret_field(&data, "password").unwrap(), "hunter2");
    let qs = extract_secret_field(&data, "security_questions").unwrap();
    assert!(qs.contains("Pet?") && qs.contains("Cat"));
}

#[test]
fn reveal_extracts_ssh_key_and_flags_missing_passphrase() {
    let data = CredentialData::SshKey(SshKeyData {
        private_key: "-----BEGIN".to_string(),
        public_key: "ssh-ed25519 AAA".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: None,
    });
    assert_eq!(
        extract_secret_field(&data, "ssh_private_key").unwrap(),
        "-----BEGIN"
    );
    assert!(extract_secret_field(&data, "ssh_passphrase").is_err());
    // 跨类型取 password 必须失败
    assert!(extract_secret_field(&data, "password").is_err());
}

#[test]
fn reveal_extracts_api_fields_and_flags_missing_ones() {
    let data = CredentialData::ApiKey(ApiKeyData {
        api_key: "key123".to_string(),
        api_secret: Some("secret456".to_string()),
        token: None,
        permissions: vec![],
        expires_at: None,
    });
    assert_eq!(extract_secret_field(&data, "api_key").unwrap(), "key123");
    assert_eq!(
        extract_secret_field(&data, "api_secret").unwrap(),
        "secret456"
    );
    assert!(extract_secret_field(&data, "token").is_err());
}

#[test]
fn reveal_extracts_wallet_secrets_only_when_present() {
    let empty = CredentialData::CryptoWallet(CryptoWalletData {
        wallet_type: "evm".to_string(),
        mnemonic_phrase: None,
        private_key: None,
        public_key: "pub".to_string(),
        address: "0x0".to_string(),
        network: "Ethereum".to_string(),
        bip39_passphrase: None,
        item_password_hash: None,
        item_password_hint: None,
    });
    assert!(extract_secret_field(&empty, "wallet_private_key").is_err());
    assert!(extract_secret_field(&empty, "wallet_mnemonic").is_err());

    let full = CredentialData::CryptoWallet(CryptoWalletData {
        wallet_type: "evm".to_string(),
        mnemonic_phrase: Some("test test".to_string()),
        private_key: Some("0xabc".to_string()),
        public_key: "pub".to_string(),
        address: "0x0".to_string(),
        network: "Ethereum".to_string(),
        bip39_passphrase: Some("tungsten".to_string()),
        item_password_hash: None,
        item_password_hint: None,
    });
    assert_eq!(
        extract_secret_field(&full, "wallet_private_key").unwrap(),
        "0xabc"
    );
}

#[test]
fn item_password_guard_gates_wallet_seed_material_only() {
    use persona_core::crypto::hashing::PasswordHasher;

    let hash = PasswordHasher::new()
        .hash_password("item-pass")
        .expect("hash item password");
    let guarded_data = CryptoWalletData {
        wallet_type: "evm".to_string(),
        mnemonic_phrase: Some("test test".to_string()),
        private_key: Some("0xabc".to_string()),
        public_key: "pub".to_string(),
        address: "0x0".to_string(),
        network: "Ethereum".to_string(),
        bip39_passphrase: Some("tungsten".to_string()),
        item_password_hash: Some(hash),
        item_password_hint: Some("hint".to_string()),
    };
    let guarded = CredentialData::CryptoWallet(guarded_data.clone());
    let unguarded = CredentialData::CryptoWallet(CryptoWalletData {
        item_password_hash: None,
        item_password_hint: None,
        ..guarded_data
    });

    // 未设条目密码：三个种子字段全部放行
    for f in [
        "wallet_mnemonic",
        "wallet_private_key",
        "wallet_bip39_passphrase",
    ] {
        assert!(
            ensure_item_password_ok(&unguarded, f, None).is_none(),
            "{f}"
        );
    }

    // 设了条目密码：缺参 → REQUIRED；对 → 放行；错 → WRONG
    for f in [
        "wallet_mnemonic",
        "wallet_private_key",
        "wallet_bip39_passphrase",
    ] {
        let (code, _) = ensure_item_password_ok(&guarded, f, None)
            .expect("guarded field must require item password");
        assert_eq!(code, crate::error::CODE_ITEM_PASSWORD_REQUIRED);

        assert!(
            ensure_item_password_ok(&guarded, f, Some("item-pass")).is_none(),
            "{f}"
        );

        let (code, _) = ensure_item_password_ok(&guarded, f, Some("wrong"))
            .expect("wrong item password must be rejected");
        assert_eq!(code, crate::error::CODE_ITEM_PASSWORD_WRONG);
    }

    // 非保护字段（登录密码视角的 password）与非钱包类型不受影响
    let password =
        CredentialData::Password(persona_core::models::credential::PasswordCredentialData {
            password: "pw".to_string(),
            email: None,
            security_questions: vec![],
        });
    assert!(ensure_item_password_ok(&guarded, "password", None).is_none());
    assert!(ensure_item_password_ok(&password, "password", None).is_none());
}

#[test]
fn reveal_raw_requires_utf8_and_unknown_field_fails() {
    let raw = CredentialData::Raw("hello".to_string().into_bytes());
    assert_eq!(extract_secret_field(&raw, "raw_data").unwrap(), "hello");
    assert!(extract_secret_field(&raw, "nope").is_err());
    assert!(
        extract_secret_field(&CredentialData::Raw(vec![0xff]), "raw_data").is_err(),
        "非 UTF-8 原始数据必须报错"
    );
}

// -------------------------------------------------------------------------
// build_health_scan_config：扫描参数解析
// -------------------------------------------------------------------------

#[test]
fn health_scan_empty_request_uses_core_defaults() {
    let c = build_health_scan_config(&HealthScanRequest::default());
    assert_eq!(
        c,
        persona_core::HealthScanConfig {
            min_password_score: persona_core::DEFAULT_MIN_PASSWORD_SCORE,
            expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
            stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
        }
    );
}

#[test]
fn health_scan_request_overrides_each_field() {
    let raw = serde_json::json!({
        "min_password_score": 2,
        "expiry_warning_days": 7,
        "stale_after_days": 90
    });
    let request: HealthScanRequest = serde_json::from_value(raw).unwrap();
    let c = build_health_scan_config(&request);
    assert_eq!(c.min_password_score, 2);
    assert_eq!(c.expiry_warning_days, 7);
    assert_eq!(c.stale_after_days, 90);

    // 前端可以只传部分字段，其余回落默认值
    let partial: HealthScanRequest =
        serde_json::from_value(serde_json::json!({ "min_password_score": 1 })).unwrap();
    let c = build_health_scan_config(&partial);
    assert_eq!(c.min_password_score, 1);
    assert_eq!(
        c,
        persona_core::HealthScanConfig {
            min_password_score: 1,
            expiry_warning_days: persona_core::DEFAULT_EXPIRY_WARNING_DAYS,
            stale_after_days: persona_core::DEFAULT_STALE_AFTER_DAYS,
        }
    );
}

#[test]
fn health_scan_check_breaches_flag_parses_with_default_off() {
    // 缺省 = 不查泄露库
    let absent: HealthScanRequest = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(absent.check_breaches, None);

    let on: HealthScanRequest =
        serde_json::from_value(serde_json::json!({ "check_breaches": true })).unwrap();
    assert_eq!(on.check_breaches, Some(true));
    // flag 不影响扫描配置本体
    assert_eq!(build_health_scan_config(&on), HealthScanConfig::default());
}

// -------------------------------------------------------------------------
// build_audit_query：过滤参数解析
// -------------------------------------------------------------------------

#[test]
fn audit_query_empty_request_uses_defaults() {
    let q = build_audit_query(&AuditQueryRequest {
        user_id: None,
        identity_id: None,
        action: None,
        failures_only: None,
        security_sensitive_only: None,
        time_range: None,
        limit: None,
    })
    .unwrap();
    assert!(!q.failures_only);
    assert!(!q.security_sensitive_only);
    assert!(q.time_range.is_none() && q.action.is_none() && q.limit.is_none());
}

#[test]
fn audit_query_parses_action_time_and_rejects_garbage() {
    let q = build_audit_query(&AuditQueryRequest {
        user_id: None,
        identity_id: None,
        action: Some("identity_created".to_string()),
        failures_only: Some(true),
        security_sensitive_only: None,
        time_range: Some((
            "2026-01-01T00:00:00Z".to_string(),
            "2026-02-01T00:00:00Z".to_string(),
        )),
        limit: Some(50),
    })
    .unwrap();
    assert!(q.failures_only);
    assert_eq!(q.limit, Some(50));
    assert!(q.time_range.is_some());

    let mut bad = AuditQueryRequest {
        action: Some("not_a_real_action".to_string()),
        ..AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        }
    };
    // 未知动作名按 core 语义解析为 Custom（查询合法，结果为空），不报错
    assert!(build_audit_query(&bad).is_ok());
    bad.action = None;
    bad.identity_id = Some("not-a-uuid".to_string());
    assert!(build_audit_query(&bad).is_err());
}

/// parse_network 的全部别名臂（大小写不敏感，未知值 → Custom）。
#[test]
fn parse_network_covers_every_alias_arm() {
    use persona_core::models::wallet::BlockchainNetwork;

    let cases: &[(&str, BlockchainNetwork)] = &[
        ("bitcoin", BlockchainNetwork::Bitcoin),
        ("BTC", BlockchainNetwork::Bitcoin),
        ("ethereum", BlockchainNetwork::Ethereum),
        ("ETH", BlockchainNetwork::Ethereum),
        ("solana", BlockchainNetwork::Solana),
        ("SOL", BlockchainNetwork::Solana),
        ("bitcoin-cash", BlockchainNetwork::BitcoinCash),
        ("Bitcoin Cash", BlockchainNetwork::BitcoinCash),
        ("bitcoincash", BlockchainNetwork::BitcoinCash),
        ("BCH", BlockchainNetwork::BitcoinCash),
        ("litecoin", BlockchainNetwork::Litecoin),
        ("LTC", BlockchainNetwork::Litecoin),
        ("dogecoin", BlockchainNetwork::Dogecoin),
        ("DOGE", BlockchainNetwork::Dogecoin),
        ("polygon", BlockchainNetwork::Polygon),
        ("MATIC", BlockchainNetwork::Polygon),
        ("arbitrum", BlockchainNetwork::Arbitrum),
        ("ARB", BlockchainNetwork::Arbitrum),
        ("optimism", BlockchainNetwork::Optimism),
        ("OP", BlockchainNetwork::Optimism),
        ("binance", BlockchainNetwork::BinanceSmartChain),
        ("bsc", BlockchainNetwork::BinanceSmartChain),
        ("BNB", BlockchainNetwork::BinanceSmartChain),
        ("Binance Smart Chain", BlockchainNetwork::BinanceSmartChain),
        (
            "Fancy Chain",
            BlockchainNetwork::Custom("fancy chain".to_string()),
        ),
    ];
    for (input, expected) in cases {
        // to_lowercase 在函数内做，输入大小写自由。
        let got = parse_network(&input.to_lowercase())
            .unwrap_or_else(|e| panic!("parse_network({input}) errored: {e}"));
        assert_eq!(&got, expected, "arm for {input}");
    }
    // 直接传原样输入（不做预 lowercase）再验一次未知臂路径。
    let custom = parse_network("FancyChain").unwrap();
    assert_eq!(custom, BlockchainNetwork::Custom("fancychain".to_string()));
}

/// serialize_wallet_address 的全部 AddressType 标签臂 + 余额缺省。
#[test]
fn serialize_wallet_address_covers_every_address_type() {
    use persona_core::models::wallet::{AddressType, WalletAddress};

    let addr = |address_type: AddressType| WalletAddress {
        address: "addr".to_string(),
        address_type,
        derivation_path: Some("m/0".to_string()),
        index: 3,
        used: true,
        balance: None,
        last_activity: None,
        metadata: std::collections::HashMap::new(),
        created_at: chrono::Utc::now(),
    };

    let cases = [
        (AddressType::P2PKH, "P2PKH"),
        (AddressType::P2SH, "P2SH"),
        (AddressType::P2WPKH, "P2WPKH"),
        (AddressType::P2TR, "P2TR"),
        (AddressType::Ethereum, "ETH"),
        (AddressType::Solana, "SOL"),
    ];
    for (address_type, label) in cases {
        let serialized = serialize_wallet_address(addr(address_type.clone()));
        assert_eq!(serialized.address_type, label);
        assert_eq!(serialized.index, 3);
        assert!(serialized.used);
        assert_eq!(serialized.balance, "-", "missing balance renders as dash");
        assert_eq!(serialized.derivation_path.as_deref(), Some("m/0"));
    }
    let custom = serialize_wallet_address(addr(AddressType::Custom("nft-vault".to_string())));
    assert_eq!(custom.address_type, "nft-vault");
}

/// 一次性丢钥匙（本机 ssh-keygen 生成、无口令），钉住 inspect IPC 的
/// DTO 形状与指纹口径；加密钥解锁路径在 core 的 ssh_import 测试覆盖。
const INSPECT_FIXTURE_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDTgnxCrm1hgMlxbs5yYX4cnGwrKT9YHCAVXEvB83667wAAAJgs0sOrLNLD\nqwAAAAtzc2gtZWQyNTUxOQAAACDTgnxCrm1hgMlxbs5yYX4cnGwrKT9YHCAVXEvB83667w\nAAAEA0dGcgt7qKc5Defecn7TTt7fquyTe6FpXVeshCU6jx49OCfEKubWGAyXFuznJhfhyc\nbCspP1gcIBVcS8HzfrrvAAAAFHBlcnNvbmEtZGVza3RvcC10ZXN0AQ==\n-----END OPENSSH PRIVATE KEY-----\n";

#[tokio::test]
async fn inspect_ssh_key_file_previews_fingerprint_and_dto_shape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id_ed25519");
    std::fs::write(&path, INSPECT_FIXTURE_PEM).unwrap();

    let response = inspect_ssh_key_file(path.to_string_lossy().to_string())
        .await
        .unwrap();
    assert!(response.success, "error: {:?}", response.error);
    let info = response.data.unwrap();
    assert_eq!(info.file_name, "id_ed25519");
    assert_eq!(info.key_type, "ed25519");
    assert_eq!(info.ssh_algorithm, "ssh-ed25519");
    assert_eq!(info.comment, "persona-desktop-test");
    assert_eq!(
        info.fingerprint, "SHA256:Lsw87K5csifD+2RZvvENXB0FG/LEI2+BaBR2gQQSW2Y",
        "指纹与 ssh-keygen -lf 口径一致"
    );
    assert!(info.public_key.starts_with("ssh-ed25519 "));
    assert!(!info.encrypted);
}

#[tokio::test]
async fn inspect_ssh_key_file_missing_file_is_api_error_not_invoke_error() {
    let response = inspect_ssh_key_file("/nonexistent/id_ed25519".to_string())
        .await
        .unwrap();
    assert!(!response.success);
    assert!(
        response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Cannot read key file"),
        "文件缺失走 ApiResponse::error，不逃成 invoke 裸 String"
    );
}
