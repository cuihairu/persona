//! Command-layer integration tests — `account` family.
//!
//! Extracted from the former single-file `command_layer_tests` (LAY-001).
//! Shared fixtures live in `mod.rs`; each file pulls them in via `use super::*`.

use super::*;

#[tokio::test]
async fn account_commands_gate_before_any_network_or_crypto() {
    let app = mock_app();

    // service not initialized -> reject (before any config/network access)
    let resp = account_register(
        AccountRegisterRequest {
            username: "alice@example.com".to_string(),
            display_name: None,
        },
        app.state::<AppState>(),
    )
    .await
    .unwrap();
    assert!(!resp.success, "must reject before init");
    assert!(resp.error.unwrap().contains("not initialized"));

    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    // initialized but server not configured -> reject (accounts and sync
    // share server_url; unset = feature disabled; public and Bearer
    // endpoints pass the same gate)
    let resp = account_register(
        AccountRegisterRequest {
            username: "alice@example.com".to_string(),
            display_name: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .unwrap()
        .contains("Sync server URL is not configured"));
    let resp = account_list_devices("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp
        .error
        .unwrap()
        .contains("Sync server URL is not configured"));

    // server configured (unreachable port) -> Bearer endpoints reject first
    // for lack of an account token (fail-closed, no network touch); public
    // endpoints clear the gate and fail at the network layer
    let resp = set_sync_config(
        true,
        "http://127.0.0.1:1".to_string(),
        "tok-1".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = account_list_devices("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert!(
        err.contains("Account session is not configured"),
        "no bearer yet -> account session gate, got: {err}"
    );
    let resp = account_register(
        AccountRegisterRequest {
            username: "alice@example.com".to_string(),
            display_name: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert!(
        !err.contains("Account session"),
        "public endpoint must not require a bearer, got: {err}"
    );

    // bootstrap semantics of the guided commands: account_srp_login uses the
    // public endpoint chain (no Bearer gate);
    // account_srp_register_with_password falls back to the static server
    // token when no account session exists (set_sync_config already wrote
    // the keyring) — both clear the gate and only fail at the network layer
    // (unreachable-host error, not a gate error)
    let resp = account_srp_login(
        "acct-1".to_string(),
        AccountSrpLoginRequest {
            device_name: "laptop".to_string(),
            password: "pw".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert!(
        !err.contains("Account session") && !err.contains("not configured"),
        "srp_login 是公开端点链，门禁只到解锁/配置，got: {err}"
    );
    let resp = account_srp_register_with_password(
        "acct-1".to_string(),
        AccountSrpRegisterWithPasswordRequest {
            device_name: "laptop".to_string(),
            password: "pw".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert!(
        !err.contains("Account session") && !err.contains("No account session"),
        "注册引导须回退静态服务器令牌并触网，got: {err}"
    );

    // inject an account bearer -> Bearer endpoints clear the token gate and
    // fail at the network layer (unreachable-host error, not a gate error)
    state.account_token_store.set(&db_path, "tok-acct").unwrap();
    let resp = account_list_devices("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert!(
        !err.contains("Account session is not configured"),
        "gate should pass with a bearer, got: {err}"
    );

    // after locking -> reject (the gate precedes orchestration)
    let resp = lock_service(state.clone()).await.unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let resp = account_register(
        AccountRegisterRequest {
            username: "alice@example.com".to_string(),
            display_name: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("locked"));
}
#[tokio::test]
async fn account_token_lifecycle_persists_overwrites_and_clears() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    let url = spawn_account_mock(|req| match req.path.as_str() {
        "/api/v1/accounts/acct-1/srp/verify" => {
            assert!(
                req.auth.is_none(),
                "srp/verify is public: bearer must not be sent"
            );
            (
                200,
                r#"{"server_proof":"cHJvb2Y=","token":"tok-15m","expires_in_secs":900}"#
                    .to_string(),
            )
        }
        "/api/v1/accounts/acct-1/sessions" => (
            200,
            r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
        ),
        "/api/v1/accounts/acct-1/sessions/sess-24h" => (204, String::new()),
        "/api/v1/accounts/acct-1/sessions/other-sess" => (204, String::new()),
        other => panic!("unexpected path {other}"),
    });
    let resp = set_sync_config(true, url, "tok-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // srp verify succeeds -> the 15-minute token lands in the keyring (Bearer source)
    let resp = account_srp_verify(
        "acct-1".to_string(),
        AccountSrpVerifyRequest {
            session_id: "s1".to_string(),
            client_proof: "cA==".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().token, "tok-15m");
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("tok-15m")
    );

    // create session succeeds -> the 24h session token overwrites it (local session switch)
    let resp = account_create_session(
        "acct-1".to_string(),
        AccountSessionEvidence {
            srp_token: Some("tok-15m".to_string()),
            passkey_assertion: None,
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().session_token, "sess-24h");
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("sess-24h")
    );

    // revoking our own local session -> keyring cleared (local account sign-out)
    let resp = account_revoke_session("acct-1".to_string(), "sess-24h".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(state.account_token_store.get(&db_path).unwrap(), None);

    // revoking someone else's session leaves the local token alone
    state.account_token_store.set(&db_path, "mine").unwrap();
    let resp = account_revoke_session(
        "acct-1".to_string(),
        "other-sess".to_string(),
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("mine")
    );
}
/// `account_srp_login` end to end: the mock performs **real SRP server-side
/// math** (cross-checked against the core login orchestration), asserting
/// that M2 verification passes, the token only goes into the keyring and
/// never into the response, and a wrong passphrase fails without touching
/// an existing token.
#[tokio::test]
async fn account_srp_login_command_round_trip_persists_keyring_token() {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    use persona_core::auth::srp;
    const DEVICE: &str = "laptop";
    const PASSWORD: &str = "wizard-pw-123";
    let reg = srp::register_verifier(DEVICE, PASSWORD).unwrap();
    // (salt, verifier) + pending-handshake session_id -> (b_priv, A) + session counter
    let server = Arc::new(StdMutex::new((
        (reg.salt, reg.verifier),
        HashMap::<String, (Vec<u8>, Vec<u8>)>::new(),
        0u32,
    )));
    let url = spawn_account_mock(move |req| {
        let mut st = server.lock().unwrap();
        match req.path.as_str() {
            "/api/v1/accounts/acct-1/srp/challenge" => {
                let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                let client_public = decode_b64(body["client_public"].as_str().unwrap());
                let hc = srp::server_challenge(&st.0 .1).unwrap();
                let session_id = format!("sess-{}", st.2);
                st.2 += 1;
                st.1.insert(session_id.clone(), (hc.b_priv, client_public));
                let salt = encode_b64(&st.0 .0);
                let server_public = encode_b64(&hc.b_pub);
                (
                    200,
                    serde_json::json!({
                        "session_id": session_id,
                        "salt": salt,
                        "server_public": server_public,
                    })
                    .to_string(),
                )
            }
            "/api/v1/accounts/acct-1/srp/verify" => {
                let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                let session_id = body["session_id"].as_str().unwrap().to_string();
                let client_proof = decode_b64(body["client_proof"].as_str().unwrap());
                let Some((b_priv, client_public)) = st.1.remove(&session_id) else {
                    return (401, r#"{"error":{"code":"unauthorized"}}"#.to_string());
                };
                match srp::server_verify(&b_priv, &st.0 .1, &client_public, &client_proof) {
                    Ok(outcome) => (
                        200,
                        serde_json::json!({
                            "server_proof": encode_b64(&outcome.server_proof),
                            "token": "tok-15m",
                            "expires_in_secs": 900,
                        })
                        .to_string(),
                    ),
                    Err(_) => (401, r#"{"error":{"code":"unauthorized"}}"#.to_string()),
                }
            }
            other => panic!("unexpected path {other}"),
        }
    });
    let resp = set_sync_config(true, url, "tok-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // correct passphrase: success + response carries no token material + token lands in the keyring
    let resp = account_srp_login(
        "acct-1".to_string(),
        AccountSrpLoginRequest {
            device_name: DEVICE.to_string(),
            password: PASSWORD.to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    let data = resp.data.unwrap();
    assert_eq!(data.expires_in_secs, 900);
    assert!(!data.session_key_fingerprint.is_empty());
    assert!(
        !serde_json::to_string(&data).unwrap().contains("tok-15m"),
        "响应不得携带令牌本体"
    );
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("tok-15m")
    );

    // wrong passphrase: the command fails and the keyring token stays intact (no accidental clear)
    let resp = account_srp_login(
        "acct-1".to_string(),
        AccountSrpLoginRequest {
            device_name: DEVICE.to_string(),
            password: "wrong-password".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Account SRP login failed"));
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("tok-15m")
    );
}
/// `account_srp_register_with_password` bootstrap chain: the account keyring
/// is empty (never logged in) -> fall back to the static server token as
/// Bearer; registration never persists a token.
#[tokio::test]
async fn account_srp_register_with_password_falls_back_to_sync_server_token() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    let url = spawn_account_mock(|req| match req.path.as_str() {
        "/api/v1/accounts/acct-1/srp/register" => {
            assert_eq!(
                req.auth.as_deref(),
                Some("Bearer tok-sync"),
                "引导回退必须携带静态服务器令牌"
            );
            (200, r#"{"device_name":"laptop"}"#.to_string())
        }
        other => panic!("unexpected path {other}"),
    });
    let resp = set_sync_config(true, url, "tok-sync".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    let resp = account_srp_register_with_password(
        "acct-1".to_string(),
        AccountSrpRegisterWithPasswordRequest {
            device_name: "laptop".to_string(),
            password: "pw".to_string(),
        },
        state.clone(),
    )
    .await
    .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().device_name, "laptop");
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap(),
        None,
        "凭证注册不是登录，不落地令牌"
    );
}
/// `account_exchange_session`: the keyring's 15-minute token is the evidence
/// traded for a 24h session; the session token is written straight to the
/// keyring and the response carries no token material.
#[tokio::test]
async fn account_exchange_session_overwrites_keyring_with_session() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    let url = spawn_account_mock(|req| match req.path.as_str() {
        "/api/v1/accounts/acct-1/sessions" => {
            assert_eq!(
                req.auth.as_deref(),
                Some("Bearer tok-15m"),
                "Bearer 与证据是同一枚 keyring 令牌"
            );
            (
                200,
                r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
            )
        }
        other => panic!("unexpected path {other}"),
    });
    let resp = set_sync_config(true, url, "tok-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    state.account_token_store.set(&db_path, "tok-15m").unwrap();

    let resp = account_exchange_session("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert_eq!(resp.data.unwrap().expires_in_secs, 86400);
    assert_eq!(
        state.account_token_store.get(&db_path).unwrap().as_deref(),
        Some("sess-24h")
    );
}
/// `account_sign_out`: best-effort server revoke plus a mandatory local
/// keyring clear; a server 401 (expired token) does not block sign-out; with
/// no token present the operation is idempotently successful.
#[tokio::test]
async fn account_sign_out_clears_keyring_best_effort_revoke() {
    let app = mock_app();
    let db_path = init_service_ok(&app, "master-pw-123").await;
    let state = app.state::<AppState>();

    let url = spawn_account_mock(|req| match req.method.as_str() {
        "DELETE" if req.path == "/api/v1/accounts/acct-1/sessions/tok-15m" => {
            assert_eq!(req.auth.as_deref(), Some("Bearer tok-15m"));
            (204, String::new())
        }
        "DELETE" if req.path == "/api/v1/accounts/acct-1/sessions/expired" => {
            (401, r#"{"error":{"code":"unauthorized"}}"#.to_string())
        }
        other => panic!("unexpected request {other}"),
    });
    let resp = set_sync_config(true, url, "tok-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);

    // happy path: revoke + clear keyring
    state.account_token_store.set(&db_path, "tok-15m").unwrap();
    let resp = account_sign_out("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(resp.data.unwrap().revoked_on_server);
    assert_eq!(state.account_token_store.get(&db_path).unwrap(), None);

    // server 401 (expired): still signs out successfully, keyring still cleared
    state.account_token_store.set(&db_path, "expired").unwrap();
    let resp = account_sign_out("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(!resp.data.unwrap().revoked_on_server);
    assert_eq!(state.account_token_store.get(&db_path).unwrap(), None);

    // no token: idempotent success (no network touch)
    let resp = account_sign_out("acct-1".to_string(), state.clone())
        .await
        .unwrap();
    assert!(resp.success, "{:?}", resp.error);
    assert!(!resp.data.unwrap().revoked_on_server);
}
