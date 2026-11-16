use super::{empty_json, spawn_mock};
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::{CreateAccountSessionRequest, PasskeyAssertionRequest};

#[tokio::test]
async fn create_session_relays_each_evidence_variant() {
    // srp_token 证据
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/sessions");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["srp_token"], "tok-15m");
        assert!(body.get("passkey_assertion").is_none());
        (
            200,
            r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
        )
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let resp = client
        .create_account_session(
            "acct-1",
            &CreateAccountSessionRequest {
                srp_token: Some("tok-15m".to_string()),
                passkey_assertion: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.session_token, "sess-24h");
    assert_eq!(resp.expires_in_secs, 86400);

    // passkey_assertion 证据
    let url = spawn_mock(|req| {
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        let assertion = &body["passkey_assertion"];
        assert!(body.get("srp_token").is_none());
        assert_eq!(assertion["credential_id"], "pk-1");
        assert_eq!(assertion["signature"], "c2ln");
        (
            200,
            r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
        )
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    client
        .create_account_session(
            "acct-1",
            &CreateAccountSessionRequest {
                srp_token: None,
                passkey_assertion: Some(PasskeyAssertionRequest {
                    credential_id: "pk-1".to_string(),
                    client_data_json: "Y2Rq".to_string(),
                    origin: "https://account.example.com".to_string(),
                    authenticator_data: "YXV0aA==".to_string(),
                    signature: "c2ln".to_string(),
                }),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn revoke_session_204_returns_true() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/sessions/sess-24h");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        (204, empty_json())
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let ok = client
        .revoke_account_session("acct-1", "sess-24h")
        .await
        .unwrap();
    assert!(ok);
}
