//! Command-layer integration tests — `credential_totp` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

/// get_totp_code / get_credential_data rejection paths + search behavior.
#[tokio::test]
async fn totp_and_credential_data_rejections() {
    let (app, identity_id) = app_with_identity().await;

    // Password credential (not TOTP).
    let resp = create_credential(
        password_credential_request(&identity_id),
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let password_cred = resp.data.expect("password credential");

    // TOTP credential.
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

    // get_credential_data: bad UUID (ApiResponse).
    let resp = get_credential_data("nope".to_string(), app.state::<AppState>())
        .await
        .unwrap();
    assert_eq!(resp.error.as_deref(), Some("Invalid UUID format"));

    // get_totp_code: bad UUID / unknown credential — the same discipline, landing as an ApiResponse error.
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

    // Normal TOTP code generation (RFC vector secret).
    let resp = get_totp_code(totp_cred.id.clone(), app.state::<AppState>())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.expect("totp code").code.len(), 6);

    // Search: an empty query returns everything, an exact substring filters.
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
/// get_totp_code routes GameToken credentials (Steam Guard) through the core
/// dispatcher arm: 5-digit code / 30s period / algorithm = uppercased provider;
/// a bound provider reports an error instead of fabricating a code. Credentials
/// are created directly via the service (the command-layer request enum's
/// GameToken variant is tracked in G1.5).
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

    // Bound provider: the command layer reports the error, never returns a code.
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

    // Bound provider: the same path as the TOTP generation error, landing as an
    // ApiResponse error message — never a code.
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
/// get_totp_code must explicitly reject HOTP (counter-based) entries: the
/// desktop has no counter concept, and silently emitting a code for a time
/// window would hand the user a wrong code. The error message points at the
/// CLI's --counter usage (the same stance as the core dispatcher, the CLI, and
/// the bridge).
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
