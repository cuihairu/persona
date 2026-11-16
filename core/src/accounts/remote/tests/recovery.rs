use super::spawn_mock;
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::VerifyRecoveryCodeRequest;

#[tokio::test]
async fn generate_recovery_codes_requires_bearer_and_parses_codes() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/recovery-codes");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        assert_eq!(
            req.body.trim(),
            "",
            "recovery-codes generation sends no body"
        );
        (
            200,
            r#"{"codes":["aabb","ccdd","eeff","0011","2233","4455","6677","8899"]}"#.to_string(),
        )
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let resp = client.generate_recovery_codes("acct-1").await.unwrap();
    assert_eq!(resp.codes.len(), 8);
    assert_eq!(resp.codes[0], "aabb");
}

#[tokio::test]
async fn verify_recovery_code_is_public() {
    let url = spawn_mock(|req| {
        assert_eq!(req.path, "/api/v1/accounts/acct-1/recovery-codes/verify");
        assert!(req.auth.is_none());
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["code"], "aabb");
        (200, r#"{"success":true}"#.to_string())
    });
    let client = AccountsApi::new(url).unwrap();
    let resp = client
        .verify_recovery_code(
            "acct-1",
            &VerifyRecoveryCodeRequest {
                code: "aabb".to_string(),
            },
        )
        .await
        .unwrap();
    assert!(resp.success);
}
