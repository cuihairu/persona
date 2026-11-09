//! Command-layer integration tests — `credential_totp` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// get_totp_code / get_credential_data 的拒绝路径 + search 行为。
#[tokio::test]
async fn totp_and_credential_data_rejections() {
    let (app, identity_id) = app_with_identity().await;

    // 密码凭据（非 TOTP）。
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let password_cred = resp.data.expect("password credential");

    // TOTP 凭据。
    let mut totp_req = password_credential_request(&identity_id);
    totp_req.name = "GitHub TOTP".to_string();
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
    let totp_cred = resp.data.expect("totp credential");

    // get_credential_data：坏 UUID（ApiResponse）。
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // get_totp_code：坏 UUID / 未知凭据 —— 同纪律落 ApiResponse 错误。
    let resp = get_totp_code("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    let resp = get_totp_code(uuid::Uuid::new_v4().to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("Credential not found"));

    let resp = get_totp_code(password_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(
        resp.error.as_deref(),
        Some("Credential is not a TwoFactor entry")
    );

    // 正常 TOTP 出码（RFC 向量 secret）。
    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.expect("totp code").code.len(), 6);

    // 搜索：空查询返回全部，精确子串过滤。
    let resp = search_credentials(String::new(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().len(), 2);

    let resp = search_credentials("GitHub TOTP".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let hits = resp.data.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "GitHub TOTP");
}
/// get_totp_code 对 GameToken 凭据（Steam Guard）走 core 调度器臂：
/// 5 位码 / 30 秒周期 / algorithm=provider 大写；绑定型 provider 报错
/// 而不是伪造码。凭据经 service 直建（命令层请求枚举的 GameToken
/// 变体在 G1.5 登记）。
#[tokio::test]
async fn get_totp_code_supports_game_token_provider() {
    use persona_core::models::credential::GameTokenData;

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    let steam_cred_id = {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        let cred = service
            .create_credential(
                identity_uuid,
                "Steam Guard".to_string(),
                persona_core::models::credential::CredentialType::TwoFactor,
                persona_core::models::credential::SecurityLevel::High,
                &persona_core::models::credential::CredentialData::GameToken(GameTokenData {
                    provider: "steam_guard".to_string(),
                    secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
                    issuer: "Steam".to_string(),
                    account_name: "player_one".to_string(),
                    url: Some("https://store.steampowered.com".to_string()),
                    identity_secret: None,
                    device_id: None,
                }),
            )
            .await
            .unwrap();
        cred.id
    };

    let resp = get_totp_code(steam_cred_id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let code = resp.data.expect("game token code returned");
    assert_eq!(code.code.len(), 5, "steam guard code is five chars");
    assert!(
        code.code
            .bytes()
            .all(|c| b"23456789BCDFGHJKMNPQRTVWXY".contains(&c)),
        "code {} outside the Steam alphabet",
        code.code
    );
    assert_eq!(code.period, 30);
    assert_eq!(code.digits, 5);
    assert_eq!(code.algorithm, "STEAM_GUARD");
    assert_eq!(code.issuer, "Steam");
    assert_eq!(code.account_name, "player_one");

    // 绑定型 provider：命令层报错信息，绝不返回码。
    let bound_cred_id = {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        let cred = service
            .create_credential(
                identity_uuid,
                "Vendor bound token".to_string(),
                persona_core::models::credential::CredentialType::TwoFactor,
                persona_core::models::credential::SecurityLevel::High,
                &persona_core::models::credential::CredentialData::GameToken(GameTokenData {
                    provider: "tencent_security".to_string(),
                    secret_key: "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=".to_string(),
                    issuer: "Tencent".to_string(),
                    account_name: "player_one".to_string(),
                    url: None,
                    identity_secret: None,
                    device_id: None,
                }),
            )
            .await
            .unwrap();
        cred.id
    };

    // 绑定型 provider：与 TOTP 生成错误同路径，落 ApiResponse 错误消息，绝不返回码。
    let resp = get_totp_code(bound_cred_id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(
        resp.error
            .as_deref()
            .is_some_and(|e| e.contains("Unsupported game token provider")),
        "unexpected error: {:?}",
        resp.error
    );
}
/// get_totp_code 对 HOTP（计数器型）条目必须显式拒绝：桌面端没有计数器
/// 概念，按时间窗静默出码等于给用户错码。错误消息指向 CLI 的 --counter
/// 用法（与 core 调度器、CLI、bridge 同一口径）。
#[tokio::test]
async fn get_totp_code_rejects_hotp_entries() {
    use persona_core::models::credential::TwoFactorData;

    let (app, identity_id) = app_with_identity().await;
    let identity_uuid = uuid::Uuid::parse_str(&identity_id).unwrap();

    let hotp_cred_id = {
        let state = app.state::<AppState>();
        let guard = state.service.lock().await;
        let service = guard.as_ref().expect("service initialized");
        let cred = service
            .create_credential(
                identity_uuid,
                "HOTP token".to_string(),
                persona_core::models::credential::CredentialType::TwoFactor,
                persona_core::models::credential::SecurityLevel::High,
                &CredentialData::TwoFactor(TwoFactorData {
                    secret_key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                    issuer: "Example".to_string(),
                    account_name: "alice".to_string(),
                    algorithm: "SHA1".to_string(),
                    digits: 6,
                    period: 30,
                    hotp: Some(true),
                    initial_counter: Some(3),
                }),
            )
            .await
            .unwrap();
        cred.id
    };

    let resp = get_totp_code(hotp_cred_id.to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(!resp.success, "HOTP must not return a code");
    assert!(
        resp.data.is_none(),
        "rejected HOTP must not carry data: {:?}",
        resp.data
    );
    let err = resp.error.expect("error message");
    assert!(
        err.contains("--counter"),
        "error should point at the CLI counter flag: {err}"
    );
}
