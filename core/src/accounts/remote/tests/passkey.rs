use super::{b64v, spawn_mock};
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::{
    PasskeyCreateOptionsRequest, PasskeyLoginOptionsRequest, PasskeyRegisterRequest,
};

#[tokio::test]
async fn passkey_create_options_returns_bare_options_json() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/create-options");
        assert!(req.auth.is_none());
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["rp_id"], "example.com");
        assert_eq!(body["user_handle"], b64v(&[1u8; 32]));
        (
            200,
            r#"{"rp":{"id":"example.com","name":"example.com"},"user":{"id":"a","name":"n","displayName":"d"},"challenge":"ch","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"preferred"},"timeout":60000,"attestation":"none"}"#.to_string(),
        )
    });
    let client = AccountsApi::new(url).unwrap();
    let options = client
        .passkey_create_options(
            "acct-1",
            &PasskeyCreateOptionsRequest {
                rp_id: "example.com".to_string(),
                rp_name: None,
                user_handle: b64v(&[1u8; 32]),
                user_name: None,
                user_display_name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(options["challenge"], "ch");
    assert_eq!(options["rp"]["id"], "example.com");
    assert_eq!(options["pubKeyCredParams"][0]["alg"], -7);
}

#[tokio::test]
async fn passkey_register_relays_attestation_value_and_parses_passkey_id() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/register");
        assert!(req.auth.is_none());
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["attestation_response"]["credentialId"], "cid");
        assert_eq!(body["origin"], "https://account.example.com");
        (200, r#"{"passkey_id":"pk-1"}"#.to_string())
    });
    let client = AccountsApi::new(url).unwrap();
    let resp = client
        .passkey_register(
            "acct-1",
            &PasskeyRegisterRequest {
                attestation_response: serde_json::json!({"credentialId": "cid", "attestationObject": "ao"}),
                client_data_json: b64v(b"{}"),
                origin: "https://account.example.com".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.passkey_id, "pk-1");
}

#[tokio::test]
async fn passkey_login_options_parses_challenge() {
    let url = spawn_mock(|req| {
        assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/login-options");
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["credential_id"], "pk-1");
        (
            200,
            r#"{"challenge":"ch","rp_id":"example.com"}"#.to_string(),
        )
    });
    let client = AccountsApi::new(url).unwrap();
    let resp = client
        .passkey_login_options(
            "acct-1",
            &PasskeyLoginOptionsRequest {
                credential_id: "pk-1".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.rp_id, "example.com");
}
