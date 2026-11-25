use super::spawn_mock;
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::{RegisterAccountRequest, SrpChallengeRequest};

#[tokio::test]
async fn http_error_surfaces_status_and_server_message() {
    let url = spawn_mock(|_| {
        (
            401,
            r#"{"error":{"code":"unauthorized","message":"session expired"}}"#.to_string(),
        )
    });
    let client = AccountsApi::new(url).unwrap();
    let err = client
        .srp_challenge(
            "acct-1",
            &SrpChallengeRequest {
                device_name: "laptop".to_string(),
                client_public: "cA==".to_string(),
            },
        )
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("401"), "got: {msg}");
    assert!(msg.contains("session expired"), "got: {msg}");
}

#[tokio::test]
async fn non_json_error_body_omits_detail() {
    // The status line carries its own canonical reason phrase (including "Bad Gateway"); the
    // assertion should target the body — a non-JSON body must not appear in the error message.
    let url = spawn_mock(|_| (502, "upstream exploded".to_string()));
    let client = AccountsApi::new(url).unwrap();
    let err = client
        .srp_challenge(
            "acct-1",
            &SrpChallengeRequest {
                device_name: "laptop".to_string(),
                client_public: "cA==".to_string(),
            },
        )
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("502"), "got: {msg}");
    assert!(
        !msg.contains("upstream exploded"),
        "non-JSON body must be omitted: {msg}"
    );
}

#[tokio::test]
async fn trailing_slash_on_base_url_is_tolerated() {
    let inner = spawn_mock(|req| {
        assert_eq!(req.path, "/api/v1/accounts/register");
        (
            201,
            r#"{"account_id":"a1","username":"u","display_name":null}"#.to_string(),
        )
    });
    let url = format!("{inner}/");
    let client = AccountsApi::new(url).unwrap();
    let resp = client
        .register_account(&RegisterAccountRequest {
            username: "u".to_string(),
            display_name: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.account_id, "a1");
}
