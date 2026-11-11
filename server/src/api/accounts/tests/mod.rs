use super::*;
use crate::test_support::{request, send, setup};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

const TOKEN: &str = "test-token";

async fn router() -> axum::Router {
    let (router, _) = setup(Some(TOKEN)).await;
    router
}

fn req(method: &str, uri: &str, body: &str) -> axum::http::Request<String> {
    request(
        method,
        uri,
        Some(&format!("Bearer {TOKEN}")),
        Some("application/json"),
        body,
    )
}

fn get_req(uri: &str) -> axum::http::Request<String> {
    request("GET", uri, Some(&format!("Bearer {TOKEN}")), None, "")
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
// ---- M2 验证链第一批：账号 SRP 真握手 / passkey 真 attestation / sessions 证据 ----

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use persona_core::crypto::passkey;

const SRP_DEVICE: &str = "primary";
const SRP_PASSWORD: &str = "correct horse battery staple";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

async fn setup_state() -> (axum::Router, crate::state::AppState) {
    crate::test_support::setup(Some(TOKEN)).await
}

async fn create_account(router: &axum::Router, username: &str) -> String {
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            "/api/v1/accounts/register",
            None,
            Some("application/json"),
            &json!({"username": username}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["account_id"].as_str().unwrap().to_string()
}

async fn register_account_srp(router: &axum::Router, account_id: &str) {
    let reg = srp::register_verifier(SRP_DEVICE, SRP_PASSWORD).unwrap();
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/register"),
            &json!({
                "device_name": SRP_DEVICE,
                "salt": b64(&reg.salt),
                "verifier": b64(&reg.verifier),
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// 发起账号 SRP challenge，返回 (session_id, salt, server_public)。
async fn account_srp_challenge(
    router: &axum::Router,
    account_id: &str,
) -> (String, Vec<u8>, Vec<u8>) {
    let login = srp::SrpClientLogin::new().unwrap();
    let a_pub = login.public_ephemeral().to_vec();
    let (status, resp) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/challenge"),
            None,
            Some("application/json"),
            &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    (
        resp["session_id"].as_str().unwrap().to_owned(),
        B64.decode(resp["salt"].as_str().unwrap()).unwrap(),
        B64.decode(resp["server_public"].as_str().unwrap()).unwrap(),
    )
}

/// 完整账号 SRP 握手一次；密码错时 verify 落 401（SRP 数学上客户端
/// 总能算出 M1，拒绝发生在服务器侧的 server_verify）。
async fn attempt_account_srp_login(
    router: &axum::Router,
    account_id: &str,
    password: &str,
) -> (StatusCode, serde_json::Value) {
    let login = srp::SrpClientLogin::new().unwrap();
    let a_pub = login.public_ephemeral().to_vec();
    let (status, resp) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/challenge"),
            None,
            Some("application/json"),
            &json!({"device_name": SRP_DEVICE, "client_public": b64(&a_pub)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let salt = B64.decode(resp["salt"].as_str().unwrap()).unwrap();
    let server_public = B64.decode(resp["server_public"].as_str().unwrap()).unwrap();
    let session_id = resp["session_id"].as_str().unwrap().to_owned();

    let proof = login
        .process(SRP_DEVICE, password, &salt, &server_public)
        .unwrap();
    send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/srp/verify"),
            None,
            Some("application/json"),
            &json!({"session_id": session_id, "client_proof": b64(proof.client_proof())})
                .to_string(),
        ),
    )
    .await
}

async fn account_session_count(state: &crate::state::AppState, account_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM account_sessions WHERE account_id = ?")
        .bind(account_id)
        .fetch_one(&state.pool)
        .await
        .unwrap()
}

async fn account_passkey_count(state: &crate::state::AppState, account_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM account_passkeys WHERE account_id = ?")
        .bind(account_id)
        .fetch_one(&state.pool)
        .await
        .unwrap()
}

// ---- 账号 SRP：challenge 出真 B、verify 验 client_proof ----

/// 走 create-options（返回带服务器挑战的 options JSON）。
async fn get_create_options(router: &axum::Router, account_id: &str) -> serde_json::Value {
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/create-options"),
            None,
            Some("application/json"),
            &json!({
                "rp_id": RP_ID,
                "rp_name": "Example",
                "user_handle": B64URL.encode(b"user-1"),
                "user_name": "alice@example.com",
                "user_display_name": "Alice",
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn create_client_data(challenge: &str) -> String {
    format!(r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{ORIGIN}"}}"#)
}

/// 以服务器签发的挑战完成软件认证器注册（返回注册产物）。
async fn register_account_passkey(
    router: &axum::Router,
    account_id: &str,
) -> passkey::RegistrationOutput {
    let options = get_create_options(router, account_id).await;
    let challenge = options["challenge"].as_str().unwrap();
    let client_data = create_client_data(challenge);
    let reg = passkey::register_passkey(RP_ID, ORIGIN, client_data.as_bytes(), false).unwrap();

    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/register"),
            None,
            Some("application/json"),
            &json!({
                "attestation_response": {
                    "credentialId": B64URL.encode(&reg.credential_id),
                    "attestationObject": B64URL.encode(&reg.attestation_object),
                },
                "client_data_json": B64URL.encode(client_data.as_bytes()),
                "origin": ORIGIN,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["passkey_id"].as_str().unwrap(),
        B64URL.encode(&reg.credential_id)
    );
    reg
}
/// 走 login-options 并用返回的挑战完成一次断言。
async fn login_options_and_assert(
    router: &axum::Router,
    account_id: &str,
    reg: &passkey::RegistrationOutput,
) -> (String, passkey::AssertionOutput) {
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            &format!("/api/v1/accounts/{account_id}/passkeys/login-options"),
            None,
            Some("application/json"),
            &json!({"credential_id": B64URL.encode(&reg.credential_id)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rp_id"].as_str().unwrap(), RP_ID);
    let challenge = body["challenge"].as_str().unwrap().to_owned();

    let client_data =
        format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#);
    let out = passkey::assert_passkey(
        RP_ID,
        ORIGIN,
        client_data.as_bytes(),
        &reg.signing_key,
        false,
    )
    .unwrap();
    (client_data, out)
}

fn assertion_body(passkey_id: &str, client_data: &str, out: &passkey::AssertionOutput) -> String {
    json!({
        "passkey_assertion": {
            "credential_id": passkey_id,
            "client_data_json": B64URL.encode(client_data.as_bytes()),
            "origin": ORIGIN,
            "authenticator_data": B64URL.encode(&out.authenticator_data),
            "signature": B64URL.encode(&out.signature_der),
        }
    })
    .to_string()
}

mod account_srp;
mod edge;
mod flow;
mod passkey_ep;
mod sessions;
