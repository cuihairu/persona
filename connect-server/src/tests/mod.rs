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
    /// unlock 用的盐（重新解锁恢复会话用——lock() 清内存密钥）。
    salt: [u8; 32],
    /// 连接池句柄：限额/DB 故障路径要能主动 `close()` 掉池子。
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

    // service 本体（含内存主密钥）移入共享槽位：数据面经 router 走，
    // 管理动作（吊销/锁定/解锁）经 state.service 槽位直调。
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

/// 读权限 scope 构造器。`identities`/`item_types` 传空 = 全部（语义见
/// core `ConnectTokenScope`）。
fn read_scope(identities: Vec<Uuid>, item_types: Vec<ConnectItemType>) -> ConnectTokenScope {
    ConnectTokenScope {
        identities,
        item_types,
        verbs: vec![ConnectVerb::Read],
    }
}

/// 同一 service 上再签一个 token：共用 router 与限额表，但按 row.id
/// 分列计数——用来验「限额是 per-token 而非全局」。
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

/// 带默认 loopback `Host` 的便捷调用：只关心状态码 + 包络 JSON。
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

/// 全保真调用：保留响应头，并容忍**非** JSON 正文（防御性：框架
/// 4xx 已由 `normalize_framework_error` 统一包络，但第三方 layer
/// 理论上仍可能产非 JSON 正文，解析失败折成 Null 不炸断言）。
/// `headers` 不自动补 Host——缺 Host 本身就是被测路径。
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

/// 真 TCP 上发一条 HTTP/1.1 请求并读回全部响应文本（`Connection: close`
/// 保证服务端发完即关，`read_to_end` 不会挂）。用于驱动
/// [`start_connect_server`] 起的 listener，验证防线不只存在于 oneshot。
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

/// `send_capture` 不补 Host，需要 Host + Bearer 的用例走这个（数组元组
/// 手拼会撞上 `auth_header` 返回的定长数组类型）。
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
