use super::spawn_mock;
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::RegisterAccountRequest;

#[tokio::test]
async fn register_posts_public_endpoint_and_relays_name_fields() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/register");
        assert!(req.auth.is_none(), "public endpoint must not send Bearer");
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["username"], "alice@example.com");
        assert_eq!(body["display_name"], "Alice");
        (
            201,
            r#"{"account_id":"acct-1","username":"alice@example.com","display_name":"Alice"}"#
                .to_string(),
        )
    });
    let client = AccountsApi::new(url).unwrap();
    let resp = client
        .register_account(&RegisterAccountRequest {
            username: "alice@example.com".to_string(),
            display_name: Some("Alice".to_string()),
        })
        .await
        .unwrap();
    assert_eq!(resp.account_id, "acct-1");
    assert_eq!(resp.username, "alice@example.com");
    assert_eq!(resp.display_name.as_deref(), Some("Alice"));
}
