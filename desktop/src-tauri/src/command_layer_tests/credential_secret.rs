//! Command-layer integration tests — `credential_secret` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn reveal_credential_secret_round_trip_and_unknown_field() {
    let (app, identity_id) = app_with_identity().await;
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    let cred = resp.data.expect("credential created");

    // The password reveals after decryption.
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred.id.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let reveal = resp.data.expect("reveal returned");
    assert_eq!(reveal.field, "password");
    assert_eq!(reveal.value, "s3cret-password");

    // Unknown fields are rejected with a clear message.
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: cred.id.clone(),
            field: "not_a_field".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "unknown field must not reveal");
}
/// `extract_secret_field` 的字段×类型全矩阵（纯函数，无需服务）。
#[test]
fn extract_secret_field_type_matrix() {
    use persona_core::models::credential::{
        ApiKeyData, CryptoWalletData, PasswordCredentialData, SecurityQuestion, SshKeyData,
    };

    // Password：明文密码 + 安全问题 JSON 序列化；跨类型字段拒绝。
    let password = CredentialData::Password(PasswordCredentialData {
        password: "pw-1".to_string(),
        email: None,
        security_questions: vec![SecurityQuestion {
            question: "pet?".to_string(),
            answer: "cat".to_string(),
        }],
    });
    assert_eq!(extract_secret_field(&password, "password").unwrap(), "pw-1");
    let questions = extract_secret_field(&password, "security_questions").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&questions).unwrap();
    assert_eq!(parsed[0]["question"], "pet?");
    assert_eq!(parsed[0]["answer"], "cat");
    assert!(extract_secret_field(&password, "ssh_private_key").is_err());

    // CryptoWallet：私钥/助记词可选，缺失时给出可读错误。
    let wallet = |mnemonic: Option<&str>, key: Option<&str>| {
        CredentialData::CryptoWallet(CryptoWalletData {
            wallet_type: "hd".to_string(),
            mnemonic_phrase: mnemonic.map(str::to_string),
            private_key: key.map(str::to_string),
            public_key: "pub".to_string(),
            address: "addr".to_string(),
            network: "Ethereum".to_string(),
            bip39_passphrase: None,
            item_password_hash: None,
            item_password_hint: None,
        })
    };
    assert_eq!(
        extract_secret_field(&wallet(Some("m words"), Some("0xk")), "wallet_private_key").unwrap(),
        "0xk"
    );
    assert_eq!(
        extract_secret_field(&wallet(Some("m words"), None), "wallet_mnemonic").unwrap(),
        "m words"
    );
    assert_eq!(
        extract_secret_field(&wallet(None, None), "wallet_private_key").unwrap_err(),
        "This wallet has no stored private key"
    );
    assert_eq!(
        extract_secret_field(&wallet(None, None), "wallet_mnemonic").unwrap_err(),
        "This wallet has no stored mnemonic phrase"
    );
    assert!(extract_secret_field(&wallet(None, None), "api_key").is_err());

    // SshKey：私钥必有；口令可选。
    let ssh = |passphrase: Option<&str>| {
        CredentialData::SshKey(SshKeyData {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAA".to_string(),
            key_type: "ed25519".to_string(),
            passphrase: passphrase.map(str::to_string),
        })
    };
    assert!(extract_secret_field(&ssh(None), "ssh_private_key")
        .unwrap()
        .starts_with("-----BEGIN"));
    assert_eq!(
        extract_secret_field(&ssh(Some("pp")), "ssh_passphrase").unwrap(),
        "pp"
    );
    assert_eq!(
        extract_secret_field(&ssh(None), "ssh_passphrase").unwrap_err(),
        "This SSH key has no stored passphrase"
    );

    // ApiKey：secret 与 token 可选。
    let api = |secret: Option<&str>, token: Option<&str>| {
        CredentialData::ApiKey(ApiKeyData {
            api_key: "AK123".to_string(),
            api_secret: secret.map(str::to_string),
            token: token.map(str::to_string),
            permissions: vec![],
            expires_at: None,
        })
    };
    assert_eq!(
        extract_secret_field(&api(None, None), "api_key").unwrap(),
        "AK123"
    );
    assert_eq!(
        extract_secret_field(&api(Some("sec"), None), "api_secret").unwrap(),
        "sec"
    );
    assert_eq!(
        extract_secret_field(&api(None, Some("tok")), "token").unwrap(),
        "tok"
    );
    assert_eq!(
        extract_secret_field(&api(None, None), "api_secret").unwrap_err(),
        "This API credential has no stored secret"
    );
    assert_eq!(
        extract_secret_field(&api(None, None), "token").unwrap_err(),
        "This API credential has no stored token"
    );

    // Raw：必须能按 UTF-8 解码。
    let raw_utf8 = CredentialData::Raw("plain-bytes".as_bytes().to_vec());
    assert_eq!(
        extract_secret_field(&raw_utf8, "raw_data").unwrap(),
        "plain-bytes"
    );
    let raw_binary = CredentialData::Raw(vec![0xff, 0xfe, 0x00]);
    assert_eq!(
        extract_secret_field(&raw_binary, "raw_data").unwrap_err(),
        "Raw data is not valid UTF-8"
    );

    // 未知字段名一律拒绝。
    assert_eq!(
        extract_secret_field(&password, "nonexistent").unwrap_err(),
        "Field 'nonexistent' is not available for this credential type"
    );
}
/// reveal 命令的错误路径 + ApiKey 凭据的成功 reveal（覆盖
/// `CredentialDataRequest::ApiKey` 的转换与序列化链）。
#[tokio::test]
async fn reveal_secret_paths_and_api_key_round_trip() {
    let app = mock_app();

    // 未初始化：服务缺失分支。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: uuid::Uuid::new_v4().to_string(),
            field: "password".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Service not initialized"));

    let (app, identity_id) = app_with_identity().await;

    // 坏 UUID 在拿服务之前就被拒。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: "not-a-uuid".to_string(),
            field: "password".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // ApiKey 凭据：创建 → reveal api_key 命中成功臂。
    let mut req = password_credential_request(&identity_id);
    req.name = "Service API".to_string();
    req.credential_type = "ApiKey".to_string();
    req.credential_data = CredentialDataRequest::ApiKey {
        api_key: "AKIA-example".to_string(),
        api_secret: Some("shhh".to_string()),
        token: None,
        permissions: vec!["read".to_string()],
        expires_at: None,
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let api_cred = resp.data.expect("api credential created");

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: api_cred.id.clone(),
            field: "api_key".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let revealed = resp.data.expect("secret revealed");
    assert_eq!(revealed.field, "api_key");
    assert_eq!(revealed.value, "AKIA-example");

    // 类型不匹配：对 ApiKey 凭据要 password 字段。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: api_cred.id.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("not available for this credential type"));

    // 不存在的凭据 id。
    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: uuid::Uuid::new_v4().to_string(),
            field: "api_key".to_string(),
            item_password: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));
}
/// `credential_data_to_json` 覆盖全部凭据类型的序列化臂，并验证各敏感
/// 字段（密码、私钥、助记词、API secret、完整卡号）一律不出现在 JSON 里。
#[test]
fn credential_data_to_json_type_matrix_and_redaction() {
    use persona_core::models::credential::{
        ApiKeyData, BankCardData, CryptoWalletData, PasswordCredentialData, SecurityQuestion,
        ServerConfigData, SshKeyData, TwoFactorData,
    };

    let password = CredentialData::Password(PasswordCredentialData {
        password: "plain-secret".to_string(),
        email: Some("a@b.c".to_string()),
        security_questions: vec![SecurityQuestion {
            question: "q".to_string(),
            answer: "a".to_string(),
        }],
    });
    let json = credential_data_to_json(&password);
    assert_eq!(json["type"], "Password");
    assert_eq!(json["email"], "a@b.c");
    // 分层契约：登录密码是 UI 主视图数据（get_credential_data 直接携带），
    // 而钱包私钥/SSH 私钥/API secret/TOTP 种子等更高级别的敏感材料一律
    // 不进序列化负载，只能走 reveal_credential_secret。
    assert_eq!(json["password"], "plain-secret");

    let wallet = CredentialData::CryptoWallet(CryptoWalletData {
        wallet_type: "hd".to_string(),
        mnemonic_phrase: Some("never leak".to_string()),
        private_key: Some("never leak".to_string()),
        public_key: "pub".to_string(),
        address: "addr".to_string(),
        network: "Ethereum".to_string(),
        bip39_passphrase: Some("tungsten".to_string()),
        item_password_hash: Some("phc-hash".to_string()),
        item_password_hint: None,
    });
    let json = credential_data_to_json(&wallet);
    assert_eq!(json["type"], "CryptoWallet");
    assert_eq!(json["address"], "addr");
    assert!(
        !json.to_string().contains("never leak"),
        "wallet secret leaked: {json}"
    );

    let ssh = CredentialData::SshKey(SshKeyData {
        private_key: "PRIVATE".to_string(),
        public_key: "ssh-ed25519 AAA".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: Some("pp".to_string()),
    });
    let json = credential_data_to_json(&ssh);
    assert_eq!(json["type"], "SshKey");
    assert_eq!(json["key_type"], "ed25519");
    assert!(!json.to_string().contains("PRIVATE"));

    let api = CredentialData::ApiKey(ApiKeyData {
        api_key: "AKIA-leak".to_string(),
        api_secret: Some("SECRET-leak".to_string()),
        token: Some("TOKEN-leak".to_string()),
        permissions: vec!["read".to_string()],
        expires_at: None,
    });
    let json = credential_data_to_json(&api);
    assert_eq!(json["type"], "ApiKey");
    assert_eq!(json["permissions"][0], "read");
    assert!(!json.to_string().contains("leak"));

    let card = CredentialData::BankCard(BankCardData {
        card_number: "4111 1111 1111 1234".to_string(),
        cardholder_name: "Cred Holder".to_string(),
        expiry_date: "12/30".to_string(),
        cvv: "999".to_string(),
        bank_name: "Example Bank".to_string(),
        card_type: "visa".to_string(),
    });
    let json = credential_data_to_json(&card);
    assert_eq!(json["type"], "BankCard");
    assert_eq!(json["last4"], "1234");
    assert!(
        !json.to_string().contains("4111"),
        "full PAN leaked: {json}"
    );
    assert!(!json.to_string().contains("999"));

    let server = CredentialData::ServerConfig(ServerConfigData {
        hostname: "web01".to_string(),
        ip_address: Some("10.0.0.5".to_string()),
        port: 22,
        protocol: "ssh".to_string(),
        username: "deploy".to_string(),
        password: Some("SERVER-leak".to_string()),
        ssh_key_id: None,
        additional_config: HashMap::new(),
    });
    let json = credential_data_to_json(&server);
    assert_eq!(json["type"], "ServerConfig");
    assert_eq!(json["port"], 22);
    assert!(!json.to_string().contains("SERVER-leak"));

    let totp = CredentialData::TwoFactor(TwoFactorData {
        secret_key: "TOTP-leak".to_string(),
        issuer: "GitHub".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        hotp: None,
        initial_counter: None,
        period: 30,
    });
    let json = credential_data_to_json(&totp);
    assert_eq!(json["type"], "TwoFactor");
    assert_eq!(json["issuer"], "GitHub");
    assert!(!json.to_string().contains("TOTP-leak"));

    let json = credential_data_to_json(&CredentialData::Raw(vec![1, 2, 3]));
    assert_eq!(json["type"], "Raw");
    assert_eq!(json["message"], "Binary data");
}
/// `CredentialDataRequest::to_credential_data` 的剩余转换臂：
/// CryptoWallet / SshKey / Raw，以及 ApiKey 的 expires_at RFC3339 解析。
#[test]
fn credential_data_request_conversion_extras() {
    let wallet = CredentialDataRequest::CryptoWallet {
        wallet_type: "hd".to_string(),
        mnemonic_phrase: Some("words".to_string()),
        private_key: Some("0xk".to_string()),
        public_key: "pub".to_string(),
        address: "addr".to_string(),
        network: "Ethereum".to_string(),
        bip39_passphrase: None,
    };
    match wallet.to_credential_data() {
        CredentialData::CryptoWallet(w) => {
            assert_eq!(w.mnemonic_phrase.as_deref(), Some("words"));
            assert_eq!(w.private_key.as_deref(), Some("0xk"));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    let ssh = CredentialDataRequest::SshKey {
        private_key: "PRIVATE".to_string(),
        public_key: "pub".to_string(),
        key_type: "ed25519".to_string(),
        passphrase: Some("pp".to_string()),
    };
    match ssh.to_credential_data() {
        CredentialData::SshKey(k) => assert_eq!(k.passphrase.as_deref(), Some("pp")),
        other => panic!("wrong variant: {other:?}"),
    }

    let api = CredentialDataRequest::ApiKey {
        api_key: "AK".to_string(),
        api_secret: None,
        token: None,
        permissions: vec![],
        expires_at: Some("2030-01-01T00:00:00Z".to_string()),
    };
    match api.to_credential_data() {
        CredentialData::ApiKey(a) => assert!(a.expires_at.is_some(), "rfc3339 parsed"),
        other => panic!("wrong variant: {other:?}"),
    }

    let raw = CredentialDataRequest::Raw {
        data: vec![9, 9, 9],
    };
    match raw.to_credential_data() {
        CredentialData::Raw(bytes) => assert_eq!(bytes, vec![9, 9, 9]),
        other => panic!("wrong variant: {other:?}"),
    }
}
