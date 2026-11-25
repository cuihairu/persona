use super::*;
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use persona_core::connect::{ConnectItemType, ConnectTokenScope, ConnectVerb};
use persona_core::models::{
    CredentialData, CredentialType, IdentityType, PasswordCredentialData, SecurityLevel,
    SshKeyData, TwoFactorData,
};
use persona_core::storage::Database;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower::ServiceExt;

struct Fixture {
    router: Router,
    state: ConnectServerState,
    token: String,
    token_row_id: Uuid,
    identity_id: Uuid,
    cred_id: Uuid,
    /// Salt used for unlocking (re-unlocking restores the session -- lock() clears
    /// the in-memory key).
    salt: [u8; 32],
    /// Connection pool handle: the rate-limit / DB failure paths must be able to
    /// actively `close()` the pool.
    db: Database,
}

async fn fixture() -> Fixture {
    let db = Database::in_memory().await.unwrap();
    db.migrate().await.unwrap();
    let mut service = PersonaService::new(db.clone()).await.unwrap();
    let salt = service.generate_salt();
    service.unlock("test_password", &salt).unwrap();
    let identity = service
        .create_identity("work".to_string(), IdentityType::Personal)
        .await
        .unwrap();
    let cred = service
        .create_credential(
            identity.id,
            "login".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &CredentialData::Password(PasswordCredentialData {
                password: "secret".to_string(),
                email: Some("a@b.c".to_string()),
                security_questions: vec![],
            }),
        )
        .await
        .unwrap();
    let scope = ConnectTokenScope {
        identities: vec![],
        item_types: vec![],
        verbs: vec![ConnectVerb::Read],
    };
    let (token, row) = service
        .create_connect_token("test token".to_string(), scope, None, None)
        .await
        .unwrap();

    // The service itself (including the in-memory master key) moves into the shared
    // slot: the data plane goes through the router, while administrative actions
    // (revocation / lock / unlock) call the state.service slot directly.
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(Some(service))));
    let router = build_router(state.clone());
    Fixture {
        router,
        state,
        token,
        token_row_id: row.id,
        identity_id: identity.id,
        cred_id: cred.id,
        salt,
        db,
    }
}

/// Read-permission scope constructor. Empty `identities`/`item_types` mean all
/// (semantics in core's `ConnectTokenScope`).
fn read_scope(identities: Vec<Uuid>, item_types: Vec<ConnectItemType>) -> ConnectTokenScope {
    ConnectTokenScope {
        identities,
        item_types,
        verbs: vec![ConnectVerb::Read],
    }
}

/// Mint another token on the same service: the router and rate table are
/// shared, but counters are bucketed per row.id -- this is what verifies "the
/// rate limit is per token, not global".
async fn mint_token(fx: &Fixture, label: &str, token_scope: ConnectTokenScope) -> String {
    let guard = fx.state.service.lock().await;
    guard
        .as_ref()
        .unwrap()
        .create_connect_token(label.to_string(), token_scope, None, None)
        .await
        .unwrap()
        .0
}

async fn add_identity(fx: &Fixture, name: &str) -> Uuid {
    let guard = fx.state.service.lock().await;
    guard
        .as_ref()
        .unwrap()
        .create_identity(name.to_string(), IdentityType::Personal)
        .await
        .unwrap()
        .id
}

async fn add_credential(
    fx: &Fixture,
    identity_id: Uuid,
    name: &str,
    credential_type: CredentialType,
    data: CredentialData,
) -> Uuid {
    let guard = fx.state.service.lock().await;
    guard
        .as_ref()
        .unwrap()
        .create_credential(
            identity_id,
            name.to_string(),
            credential_type,
            SecurityLevel::High,
            &data,
        )
        .await
        .unwrap()
        .id
}

fn password_data() -> CredentialData {
    CredentialData::Password(PasswordCredentialData {
        password: "pw".to_string(),
        email: None,
        security_questions: vec![],
    })
}

fn totp_data() -> CredentialData {
    CredentialData::TwoFactor(TwoFactorData {
        secret_key: "JBSWY3DPEHPK3PXP".to_string(),
        issuer: "ACME".to_string(),
        account_name: "a@b.c".to_string(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        hotp: None,
        initial_counter: None,
    })
}

/// Convenience call with a default loopback `Host`: all that matters is the
/// status code + envelope JSON.
async fn send(
    router: Router,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> (StatusCode, serde_json::Value) {
    let mut with_host: Vec<(&str, String)> = Vec::with_capacity(headers.len() + 1);
    with_host.push(("host", "127.0.0.1:17000".to_string()));
    with_host.extend_from_slice(headers);
    let (status, _, json) = send_capture(router, method, path, &with_host).await;
    (status, json)
}

/// Full-fidelity call: response headers are preserved, and a **non**-JSON body
/// is tolerated (defensively: framework 4xx are already enveloped by
/// `normalize_framework_error`, but a third-party layer could in principle still
/// produce a non-JSON body; a parse failure collapses to Null rather than
/// blowing up the assertion).
/// `headers` does not fill in Host -- a missing Host is itself the path under
/// test.
async fn send_capture(
    router: Router,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut builder = HttpRequest::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, v);
    }
    let req = builder.body(Body::empty()).unwrap();
    let response = router.oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// Send one HTTP/1.1 request over real TCP and read back the entire response
/// text (`Connection: close` guarantees the server closes once it has sent
/// everything, so `read_to_end` cannot hang). Used to drive the listener started
/// by [`start_connect_server`], verifying the defenses exist beyond oneshot.
async fn http_over_tcp(port: u16, method: &str, path: &str, host: &str, extra: &str) -> String {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("listener 未在 5s 内应答")
        .unwrap();
    String::from_utf8(buf).expect("响应非 UTF-8")
}

fn auth_header(token: &str) -> [(&'static str, String); 1] {
    [("authorization", format!("Bearer {token}"))]
}

/// `send_capture` does not fill in Host; cases needing Host + Bearer go through
/// this instead (hand-assembling an array tuple would clash with the fixed-size
/// array type returned by `auth_header`).
fn host_and_auth(token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("host", "127.0.0.1:17000".to_string()),
        ("authorization", format!("Bearer {token}")),
    ]
}

mod endpoints;
mod guard;
mod rate;
mod transport;
mod wire;

async fn body_json(response: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn response_parts(response: Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    (status, body_json(response).await)
}
