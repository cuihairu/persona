//! Command-layer integration tests — `credential_crud` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn credential_commands_round_trip_search_favorite_and_totp() {
    let (app, identity_id) = app_with_identity().await;

    // Create (also normalizes notes/tags whitespace).
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");
    assert_eq!(cred.name, "Example Login");
    assert_eq!(cred.tags, vec!["web".to_string(), "work".to_string()]);
    assert_eq!(cred.notes.as_deref(), Some("note with padding"));

    // List for identity.
    let resp = get_credentials_for_identity(identity_id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 1);

    // Decrypted data round-trips through the encrypted vault.
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Password");
    assert_eq!(data.data["password"], "s3cret-password");

    // Search by name.
    let resp = search_credentials("example".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().iter().any(|c| c.id == cred.id));

    // Toggle favorite twice: on, then off.
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().is_favorite);
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.data.unwrap().is_favorite);

    // TOTP credential: create with an RFC-vector secret and read a code.
    let mut totp_req = password_credential_request(&identity_id);
    totp_req.name = "GitHub TOTP".to_string();
    totp_req.credential_type = "TwoFactor".to_string();
    totp_req.credential_data = CredentialDataRequest::TwoFactor {
        secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
        issuer: "GitHub".to_string(),
        account_name: "alice@example.com".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        hotp: None,
        initial_counter: None,
    };
    let resp = create_credential(totp_req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let totp_cred = resp.data.expect("totp credential created");

    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("totp code returned");
    assert_eq!(code.code.len(), 6);
    assert!(code.remaining_seconds <= 30);

    // Delete both credentials; the identity listing empties out.
    for id in [cred.id, totp_cred.id] {
        let resp = delete_credential(id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
        assert!(resp.data.unwrap());
    }
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.data.unwrap().is_empty());
}
/// G1.5：创建表单路径——CredentialDataRequest::GameToken 经 create_credential
/// 命令入库，读回 GameToken 变体并出码（steam_guard）。
#[tokio::test]
async fn create_credential_accepts_game_token_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Steam Guard (form)".to_string();
    req.credential_type = "TwoFactor".to_string();
    req.credential_data = CredentialDataRequest::GameToken {
        provider: "steam_guard".to_string(),
        secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
        issuer: "Steam".to_string(),
        account_name: "player_one".to_string(),
        url: Some("https://store.steampowered.com".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("game token credential created");

    // 读回：数据是 GameToken 变体（JSON 里不回传 secret_key）。
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "GameToken");
    assert_eq!(data.data["provider"], "steam_guard");
    assert_eq!(data.data["issuer"], "Steam");
    assert_eq!(data.data["account_name"], "player_one");
    assert!(data.data.get("secret_key").is_none());

    // steam_guard 出码经统一调度器。
    let resp = get_totp_code(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("game token code returned");
    assert_eq!(code.code.len(), 5);
    assert_eq!(code.period, 30);

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password 对齐 A 批：Secure Note 创建表单路径——
/// CredentialDataRequest::SecureNote 经 create_credential 入库，credential_type
/// 为真实 SecureNote 变体，读回正文逐字保留（per-item key 加密往返）。
#[tokio::test]
async fn create_credential_accepts_secure_note_request() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Recovery codes (form)".to_string();
    req.credential_type = "SecureNote".to_string();
    req.credential_data = CredentialDataRequest::SecureNote {
        note: "1111-2222\n3333-4444".to_string(),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("secure note created");

    // 读回：类型标签与正文都保留（多行内容不被折叠）。
    let resp = get_credential_data(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SecureNote");
    assert_eq!(data.data["note"], "1111-2222\n3333-4444");

    // 列表读回：credential_type 落库往返不退化为 Custom。
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SecureNote" && c.name == "Recovery codes (form)"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password 对齐 B 批：Identity / Software License 创建表单路径——
/// 两类 CredentialDataRequest 经 create_credential 入库，credential_type
/// 为真实变体，读回字段逐字保留（per-item key 加密往返），不退化为 Custom。
#[tokio::test]
async fn create_credential_accepts_identity_and_license_requests() {
    let (app, identity_id) = app_with_identity().await;

    // Identity：证件号等敏感字段全量读回（get_credential_data 走敏感门禁）。
    let mut req = password_credential_request(&identity_id);
    req.name = "Passport (main)".to_string();
    req.credential_type = "Identity".to_string();
    req.credential_data = CredentialDataRequest::Identity {
        first_name: "Alice".to_string(),
        last_name: "Zhang".to_string(),
        username: None,
        email: Some("alice@example.com".to_string()),
        phone: Some("+86 13800000000".to_string()),
        birthday: Some("1990-01-31".to_string()),
        address: Some("1 Main St\nBeijing".to_string()),
        id_number: Some("110101199001310011".to_string()),
        passport_number: Some("E12345678".to_string()),
        driver_license: None,
        tax_id: None,
        organization: Some("Example Inc".to_string()),
        job_title: Some("Engineer".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let identity_cred = resp.data.expect("identity credential created");

    let resp = get_credential_data(identity_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "Identity");
    assert_eq!(data.data["first_name"], "Alice");
    assert_eq!(data.data["id_number"], "110101199001310011");
    assert_eq!(data.data["passport_number"], "E12345678");
    assert_eq!(data.data["address"], "1 Main St\nBeijing");
    assert_eq!(data.data["seats"], serde_json::Value::Null);

    // SoftwareLicense：license_key 读回、seats 数值往返。
    let mut req = password_credential_request(&identity_id);
    req.name = "JetBrains All Products".to_string();
    req.credential_type = "SoftwareLicense".to_string();
    req.credential_data = CredentialDataRequest::SoftwareLicense {
        license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
        version: Some("2024.2".to_string()),
        publisher: Some("JetBrains".to_string()),
        purchase_date: Some("2024-05-01".to_string()),
        order_number: None,
        support_email: None,
        download_url: Some("https://example.com/dl".to_string()),
        seats: Some(3),
        valid_until: Some("2027-05-01".to_string()),
    };
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let license_cred = resp.data.expect("license credential created");

    let resp = get_credential_data(license_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.expect("credential data returned");
    let data = data.expect("data is present");
    assert_eq!(data.credential_type, "SoftwareLicense");
    assert_eq!(data.data["license_key"], "AAAA-BBBB-CCCC-DDDD");
    assert_eq!(data.data["seats"], serde_json::json!(3));
    assert_eq!(data.data["order_number"], serde_json::Value::Null);

    // 列表读回：两个 credential_type 落库往返不退化为 Custom。
    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "Identity" && c.name == "Passport (main)"));
    assert!(creds
        .iter()
        .any(|c| c.credential_type == "SoftwareLicense" && c.name == "JetBrains All Products"));

    let resp = delete_credential(identity_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = delete_credential(license_cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 桌面稳定化：编辑凭据闭环——update_credential 改元数据、
/// update_credential_data 换密文 payload（复用原 item key，wrapped key 不变），
/// 两路读回逐字校验；不存在的 id 报错。
#[tokio::test]
async fn update_credential_metadata_and_payload_round_trip() {
    let (app, identity_id) = app_with_identity().await;

    let req = password_credential_request(&identity_id);
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let created = resp.data.expect("credential created");
    assert_eq!(created.username.as_deref(), Some("alice"));

    // 元数据编辑：改名 + username/notes/tags 更新（url 传空串 = 清空）。
    let resp = update_credential(
        UpdateCredentialRequest {
            id: created.id.clone(),
            name: "Renamed login".to_string(),
            security_level: Some("Critical".to_string()),
            url: Some("  ".to_string()),
            username: Some("newuser".to_string()),
            notes: Some("edited note".to_string()),
            tags: Some(vec!["work".to_string(), " ".to_string()]),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let meta = resp.data.expect("metadata updated");
    assert_eq!(meta.name, "Renamed login");
    assert_eq!(meta.security_level, "Critical");
    assert_eq!(meta.url, None, "blank url must clear");
    assert_eq!(meta.username.as_deref(), Some("newuser"));
    assert_eq!(meta.notes.as_deref(), Some("edited note"));
    assert_eq!(meta.tags, vec!["work".to_string()]);

    // payload 编辑：换密码（复用原 item key 重封）。
    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: created.id.clone(),
            credential_data: CredentialDataRequest::Password {
                password: "rotated-secret".to_string(),
                email: Some("edited@example.com".to_string()),
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let payload = resp.data.expect("payload updated");
    assert_eq!(
        payload.name, "Renamed login",
        "metadata survives payload edit"
    );
    // item key 复用不变量（wrapped key 字节不动）在 core 层专测断言；
    // SerializableCredential 不回传密钥材料，命令层不重复覆盖。

    // 读回：新密码逐字保留、元数据编辑结果都在。
    let resp = get_credential_data(created.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp
        .data
        .expect("credential data returned")
        .expect("present");
    assert_eq!(data.data["password"], "rotated-secret");
    assert_eq!(data.data["email"], "edited@example.com");

    let resp = get_credentials_for_identity(identity_id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let creds = resp.data.expect("credentials returned");
    let stored = creds
        .iter()
        .find(|c| c.id == created.id)
        .expect("credential listed");
    assert_eq!(stored.name, "Renamed login");
    assert_eq!(stored.username.as_deref(), Some("newuser"));
    assert_eq!(stored.notes.as_deref(), Some("edited note"));

    // 不存在的 id：两命令都显式报错。
    let ghost = uuid::Uuid::new_v4().to_string();
    let resp = update_credential(
        UpdateCredentialRequest {
            id: ghost.clone(),
            name: "x".to_string(),
            security_level: None,
            url: None,
            username: None,
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not found"));

    let resp = update_credential_data(
        UpdateCredentialDataRequest {
            credential_id: ghost,
            credential_data: CredentialDataRequest::Password {
                password: "x".to_string(),
                email: None,
                security_questions: vec![],
            },
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);

    let resp = delete_credential(created.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// 1Password 对齐 B 批：item history——创建与 favorite 切换自动落历史行，
/// get_credential_history 返回时间线（新版本在前）与字段级 diff。
#[tokio::test]
async fn credential_history_tracks_create_and_favorite_toggle() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Historied".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 初始：created (v1) + 紧随的元数据补写 updated (v2)——
    // 桌面 create 命令是 create-then-update 架构，两次写库即两条真实历史
    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 2);
    // 补写 diff = 表单的 url/username/notes/tags 四个元数据字段
    assert_eq!(history[0].changes.len(), 4);
    assert!(history[0]
        .changes
        .iter()
        .all(|c| c.field != "encrypted_data"));
    assert_eq!(history[1].change_type, "created");
    assert_eq!(history[1].version, 1);

    // favorite 切换 → updated 行，diff 只含 is_favorite
    let resp = toggle_credential_favorite(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].change_type, "updated");
    assert_eq!(history[0].version, 3);
    assert_eq!(history[0].changes.len(), 1);
    assert_eq!(history[0].changes[0].field, "is_favorite");
    assert_eq!(history[0].changes[0].old_value, "false");
    assert_eq!(history[0].changes[0].new_value, "true");

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// restore-to-version：元数据回滚到目标版本并落 restored 历史行；
/// 秘密不回滚（历史快照不含密文）。
#[tokio::test]
async fn restore_credential_version_reverts_metadata() {
    let (app, identity_id) = app_with_identity().await;

    let mut req = password_credential_request(&identity_id);
    req.name = "Versioned".to_string();
    let resp = create_credential(req, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let cred = resp.data.expect("credential created");

    // 再改一次元数据 → 多一个版本
    let resp = update_credential(
        UpdateCredentialRequest {
            id: cred.id.clone(),
            name: "Renamed".to_string(),
            security_level: None,
            url: Some("https://renamed.example.com".to_string()),
            username: Some("bob".to_string()),
            notes: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // 恢复到 v1（创建态）：表单补写与改名一并回滚
    let resp = restore_credential_version(cred.id.clone(), 1, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let restored = resp.data.expect("restored");
    assert_eq!(restored.name, "Versioned");
    assert_eq!(restored.username, None);
    assert_eq!(restored.url, None);

    let resp = get_credential_history(cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    let history = resp.data.expect("history returned");
    assert_eq!(history[0].change_type, "restored");
    assert!(
        history[0].restorable,
        "restore rows carry a restorable state"
    );
    assert!(history[1].restorable);

    // 未知版本 → 业务错误而非 panic
    let resp = restore_credential_version(cred.id.clone(), 99, app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap_or_default().contains("99"));

    let resp = delete_credential(cred.id, app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
}
/// create_credential 的 credential_type/security_level 字符串臂矩阵，
/// 以及 url/username/notes/tags 的归一化臂。
#[tokio::test]
async fn create_credential_type_and_security_level_matrix() {
    let (app, identity_id) = app_with_identity().await;

    let base = |name: &str, type_str: &str, level: &str| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: type_str.to_string(),
        security_level: level.to_string(),
        url: Some("https://matrix.example".to_string()),
        username: Some("alice".to_string()),
        notes: Some("  kept  ".to_string()),
        tags: Some(vec!["a".to_string(), "  ".to_string(), "b".to_string()]),
        credential_data: CredentialDataRequest::Raw {
            data: vec![1, 2, 3],
        },
    };

    // credential_type 的非 Password 臂（Password/TwoFactor 已有测试覆盖）。
    for type_str in [
        "CryptoWallet",
        "SshKey",
        "ApiKey",
        "BankCard",
        "GameAccount",
        "ServerConfig",
        "Certificate",
        "CustomStyle",
    ] {
        let resp = create_credential(
            base("Matrix", type_str, "Critical"),
            app.state::<AppState>(),
        )
        .await
        .unwrap();
        assert!(resp.success, "{type_str}: {:?}", resp.error);
        let cred = resp.data.expect("credential created");
        assert_eq!(cred.credential_type, type_str);
        assert_eq!(cred.security_level, "Critical");
        assert_eq!(cred.url.as_deref(), Some("https://matrix.example"));
        assert_eq!(cred.username.as_deref(), Some("alice"));
        assert_eq!(cred.notes.as_deref(), Some("kept"));
        assert_eq!(cred.tags, vec!["a".to_string(), "b".to_string()]);

        // security_level 的其余臂 + 未知值回落 Medium。
        for (level, expected) in [("High", "High"), ("Low", "Low"), ("Bogus", "Medium")] {
            let mut req = base("Levels", type_str, level);
            req.name = format!("Levels-{type_str}-{level}");
            let resp = create_credential(req, app.state::<AppState>())
                .await
                .unwrap();
            assert!(resp.success, "{type_str}/{level}: {:?}", resp.error);
            assert_eq!(resp.data.expect("credential").security_level, expected);
        }

        let resp = delete_credential(cred.id, app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{:?}", resp.error);
    }

    // 坏 identity UUID 在 get_credentials_for_identity 上同样失败关闭。
    let resp = get_credentials_for_identity("not-a-uuid".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}
/// get_credential_data 对全部 8 种 CredentialData 变体输出正确的类型标签。
/// BankCard/ServerConfig 没有对应的命令层请求变体，直接经 service 构造。
#[tokio::test]
async fn get_credential_data_returns_type_labels_for_all_variants() {
    use persona_core::models::credential::{BankCardData, ServerConfigData};

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    // 经命令层建 6 种（Password/CryptoWallet/SshKey/ApiKey/TwoFactor/Raw）。
    let request_for = |name: &str, data: CredentialDataRequest| CreateCredentialRequest {
        identity_id: identity_id.clone(),
        name: name.to_string(),
        credential_type: "Raw".to_string(),
        security_level: "Medium".to_string(),
        url: None,
        username: None,
        notes: None,
        tags: None,
        credential_data: data,
    };
    let mut ids: Vec<(String, String)> = Vec::new();
    let variants: Vec<(&str, CredentialDataRequest)> = vec![
        (
            "PW",
            CredentialDataRequest::Password {
                password: "s3cret".to_string(),
                email: None,
                security_questions: vec![],
            },
        ),
        (
            "CW",
            CredentialDataRequest::CryptoWallet {
                wallet_type: "hd".to_string(),
                mnemonic_phrase: None,
                private_key: None,
                public_key: "pub".to_string(),
                address: "0xabc".to_string(),
                network: "Ethereum".to_string(),
                bip39_passphrase: Some("tungsten".to_string()),
            },
        ),
        (
            "SSH",
            CredentialDataRequest::SshKey {
                private_key: "priv".to_string(),
                public_key: "pub".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            },
        ),
        (
            "API",
            CredentialDataRequest::ApiKey {
                api_key: "key".to_string(),
                api_secret: None,
                token: None,
                permissions: vec![],
                expires_at: None,
            },
        ),
        (
            "TOTP",
            CredentialDataRequest::TwoFactor {
                secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                issuer: "i".to_string(),
                account_name: "a".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                period: 30,
                hotp: None,
                initial_counter: None,
            },
        ),
        ("RAW", CredentialDataRequest::Raw { data: vec![9] }),
    ];
    for (name, data) in variants {
        let resp = create_credential(request_for(name, data), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{name}: {:?}", resp.error);
        ids.push((resp.data.expect("created").id, name.to_string()));
    }

    // BankCard/ServerConfig 直经 service 建（命令层请求枚举没有这两种）。
    {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        for data in [
            persona_core::models::credential::CredentialData::BankCard(BankCardData {
                card_number: "4111111111111111".to_string(),
                cardholder_name: "Alice".to_string(),
                expiry_date: "12/30".to_string(),
                cvv: "123".to_string(),
                bank_name: "Test Bank".to_string(),
                card_type: "visa".to_string(),
            }),
            persona_core::models::credential::CredentialData::ServerConfig(ServerConfigData {
                hostname: "server.example".to_string(),
                ip_address: None,
                port: 22,
                protocol: "ssh".to_string(),
                username: "root".to_string(),
                password: None,
                ssh_key_id: None,
                additional_config: std::collections::HashMap::new(),
            }),
        ] {
            let cred = service
                .create_credential(
                    identity_uuid,
                    format!("direct-{}", ids.len()),
                    persona_core::models::credential::CredentialType::Custom("Direct".into()),
                    persona_core::models::credential::SecurityLevel::Medium,
                    &data,
                )
                .await
                .unwrap();
            ids.push((cred.id.to_string(), "DIRECT".to_string()));
        }
    }

    // 逐一读回：类型标签与存储变体一一对应。
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        assert!(resp.success, "{id}: {:?}", resp.error);
        let wrapper = resp.data.expect("data returned").expect("data present");
        assert!(
            [
                "Password",
                "CryptoWallet",
                "SshKey",
                "ApiKey",
                "TwoFactor",
                "Raw",
                "BankCard",
                "ServerConfig"
            ]
            .contains(&wrapper.credential_type.as_str()),
            "unexpected label {}",
            wrapper.credential_type
        );
    }
    // 8 个凭据的标签合计必须覆盖全部 8 种。
    let mut labels = std::collections::HashSet::new();
    for (id, _) in &ids {
        let resp = get_credential_data(id.clone(), app.state::<AppState>())
            .await
            .unwrap();
        labels.insert(resp.data.unwrap().unwrap().credential_type);
    }
    assert_eq!(labels.len(), 8, "all 8 variant labels covered: {labels:?}");

    // 坏 UUID 仍是格式错误。
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));
}
/// 锁定态下凭据/身份命令的 service 错误臂（这批臂输出普通错误消息，
/// 不映射错误码）+ 审计三命令的映射错误码臂。
#[tokio::test]
async fn locked_service_credential_error_surface() {
    let (app, identity_id) = app_with_identity().await;
    let existing = uuid::Uuid::new_v4().to_string();
    lock_service(app.state::<AppState>()).await.unwrap();

    // update_identity 的 get_identity Err 臂。
    let resp = update_identity(
        UpdateIdentityRequest {
            id: existing.clone(),
            name: "n".to_string(),
            identity_type: "personal".to_string(),
            description: None,
            email: None,
            phone: None,
            tags: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get identity"),
        "got: {:?}",
        resp.error
    );

    // toggle_credential_favorite 的 get_credential Err 臂。
    let resp = toggle_credential_favorite(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    // delete_credential 的 delete Err 臂。
    let resp = delete_credential(existing.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    // 审计三命令的 query/statistics/cleanup Err 臂。
    let resp = audit_query(
        AuditQueryRequest {
            user_id: None,
            identity_id: None,
            action: None,
            failures_only: None,
            security_sensitive_only: None,
            time_range: None,
            limit: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    let resp = audit_cleanup(30, app.state::<AppState>()).await.unwrap();
    assert_eq!(resp.error_code.as_deref(), Some("SERVICE_LOCKED"));

    // 解锁恢复后统计可正常返回（保证上面的失败只来自锁定）。
    let resp = reauth_verify(
        ReauthRequest {
            master_password: "correct-horse".to_string(),
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = audit_statistics(app.state::<AppState>()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    // identity_id 仍在（上述操作都失败回滚）。
    let resp = get_identities(app.state::<AppState>()).await.unwrap();
    assert!(resp.data.unwrap().iter().any(|i| i.id == identity_id));
}
#[tokio::test]
async fn credential_commands_surface_db_errors_from_garbage_vault() {
    let app = app_with_garbage_db_service().await;
    let state = app.state::<AppState>();
    let bogus = "00000000-0000-0000-0000-000000000000".to_string();

    let resp = get_credentials_for_identity(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credentials"),
        "got: {:?}",
        resp.error
    );

    let resp = create_credential(password_credential_request(&bogus), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to create credential"),
        "got: {:?}",
        resp.error
    );

    let resp = toggle_credential_favorite(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to get credential"),
        "got: {:?}",
        resp.error
    );

    let resp = delete_credential(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to delete credential"),
        "got: {:?}",
        resp.error
    );

    let resp = get_credential_data(bogus.clone(), state.clone())
        .await
        .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("Failed to get credential data"),
        "got: {:?}",
        resp.error
    );

    // totp 与其他命令同纪律：基础设施错误落 Ok(ApiResponse::error)。
    let resp = get_totp_code(bogus.clone(), state.clone()).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("file is not a database")),
        "expected sqlite error, got: {:?}",
        resp.error
    );

    let resp = reveal_credential_secret(
        RevealSecretRequest {
            credential_id: bogus.clone(),
            field: "password".to_string(),
            item_password: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .starts_with("Failed to reveal secret"),
        "got: {:?}",
        resp.error
    );

    // 扫描靠 repo 拉全量凭据，坏库必须给出错误报告（Ok 包错误体）。
    let resp = health_scan(None, state).await.unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .unwrap_or_default()
            .contains("file is not a database"),
        "got: {:?}",
        resp.error
    );
}
