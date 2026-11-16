use super::{b64v, empty_json, spawn_mock};
use crate::accounts::remote::AccountsApi;
use crate::accounts::remote::AuthorizeDeviceRequest;

#[tokio::test]
async fn authorize_device_requires_bearer_and_relays_key_material() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/devices");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body["device_id"], "dev-9");
        assert_eq!(body["public_key"], b64v(&[3u8; 32]));
        (201, r#"{"id":"ad-1","status":"authorized"}"#.to_string())
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let resp = client
        .authorize_device(
            "acct-1",
            &AuthorizeDeviceRequest {
                device_id: "dev-9".to_string(),
                public_key: b64v(&[3u8; 32]),
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, "authorized");
}

#[tokio::test]
async fn list_devices_get_with_bearer_parses_nested_list() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/devices");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        assert_eq!(req.body.trim(), "");
        (
            200,
            r#"{"devices":[{"id":"ad-1","device_id":"dev-9","device_name":"laptop","public_key":"cA==","status":"authorized","authorized_by":"laptop","authorized_at":"2026-10-01T00:00:00Z","revoked_at":null,"revoked_by":null,"created_at":"2026-09-30T00:00:00Z"}]}"#.to_string(),
        )
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let resp = client.list_account_devices("acct-1").await.unwrap();
    assert_eq!(resp.devices.len(), 1);
    let dev = &resp.devices[0];
    assert_eq!(dev.device_name, "laptop");
    assert_eq!(dev.status, "authorized");
    assert!(dev.revoked_at.is_none());
}

#[tokio::test]
async fn revoke_device_204_returns_true() {
    let url = spawn_mock(|req| {
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/api/v1/accounts/acct-1/devices/dev-9");
        assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
        (204, empty_json())
    });
    let client = AccountsApi::with_bearer(url, "tok").unwrap();
    let ok = client
        .revoke_account_device("acct-1", "dev-9")
        .await
        .unwrap();
    assert!(ok);
}
