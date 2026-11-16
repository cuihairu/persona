use super::{b64v, spawn_mock};
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::{SrpChallengeRequest, SrpRegisterRequest, SrpVerifyRequest};

#[tokio::test]
async fn srp_register_requires_bearer_and_relays_credential_material() {
    let url = spawn_mock(|req| {
        assert_eq!(req.path, "/api/v1/accounts/acct-1/srp/register");
        assert_eq!(
            req.auth.as_deref(),
            Some("Bearer bearer-1"),
            "srp register is a Bearer endpoint"
        );
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["device_name"], "laptop");
        assert_eq!(body["salt"], b64v(&[7u8; 16]));
        assert_eq!(body["verifier"], b64v(&[9u8; 96]));
        (200, r#"{"device_name":"laptop"}"#.to_string())
    });
    let client = AccountsApi::with_bearer(url, "bearer-1").unwrap();
    let resp = client
        .srp_register(
            "acct-1",
            &SrpRegisterRequest {
                device_name: "laptop".to_string(),
                salt: b64v(&[7u8; 16]),
                verifier: b64v(&[9u8; 96]),
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.device_name, "laptop");
}

#[tokio::test]
async fn srp_challenge_and_verify_are_public_and_parse_handshake() {
    let url = spawn_mock(|req| match req.path.as_str() {
        "/api/v1/accounts/acct-1/srp/challenge" => {
            assert!(req.auth.is_none());
            assert_eq!(req.method, "POST");
            (
                200,
                r#"{"session_id":"s1","salt":"c2FsdA==","server_public":"cHVibGlj"}"#.to_string(),
            )
        }
        "/api/v1/accounts/acct-1/srp/verify" => {
            assert!(req.auth.is_none());
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["session_id"], "s1");
            assert_eq!(body["client_proof"], "cHJvb2Y=");
            (
                200,
                r#"{"server_proof":"cHJvb2Y=","token":"tok-15m","expires_in_secs":900}"#
                    .to_string(),
            )
        }
        other => panic!("unexpected path {other}"),
    });
    let client = AccountsApi::new(url).unwrap();
    let challenge = client
        .srp_challenge(
            "acct-1",
            &SrpChallengeRequest {
                device_name: "laptop".to_string(),
                client_public: "cHVibGlj".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(challenge.session_id, "s1");
    assert_eq!(challenge.salt, "c2FsdA==");

    let verify = client
        .srp_verify(
            "acct-1",
            &SrpVerifyRequest {
                session_id: "s1".to_string(),
                client_proof: "cHJvb2Y=".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(verify.server_proof, "cHJvb2Y=");
    assert_eq!(verify.token, "tok-15m");
    assert_eq!(verify.expires_in_secs, 900);
}
