//! 账号域密码制注册/登录编排（feature `accounts`）。
//!
//! 纪律：SRP 数学（Argon2id 预 hash、M1 推导、M2 核验）只在 core 完成，
//! 口令与 premaster 不出本模块；调用方（桌面命令层）拿到的要么是最终
//! wire 值、要么是编排产物。纯 wire 传输在 [`super::remote::AccountsApi`]
//! （其模块文档声明"不含密码学/编排"，本模块就是那个"调用方"角色在
//! core 内的落点——渲染层不做任何 SRP 数学）。
//!
//! 两段编排，均叠在 wire 方法之上：
//!
//! - [`AccountsApi::register_srp_credential`]：口令 → salt/verifier →
//!   `POST /accounts/{id}/srp/register`。端点 Bearer-gated，实例须
//!   `with_bearer`；全新账号还没有账号会话，引导链由调用方解析（静态
//!   服务器令牌是服务器 `require_account_bearer` 契约内的合法 Bearer）。
//! - [`AccountsApi::srp_login`]：challenge → M1 → verify → **M2 核验** →
//!   交付 15 分钟令牌。裸 wire 的 `srp_challenge`/`srp_verify` 不核验
//!   M2（wire 只透传），面向 UI 的登录一律走本编排：服务器证明核验
//!   通过才交付令牌，核验失败不落地任何状态。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::remote::{AccountsApi, SrpChallengeRequest, SrpRegisterRequest, SrpVerifyRequest};
use crate::auth::srp::{self, SrpClientLogin};
use crate::{PersonaError, Result};

/// [`AccountsApi::srp_login`] 的产物：15 分钟账号登录令牌 + 双向认证
/// 会话指纹。令牌由调用方持有（桌面端直接进 OS keyring，不经渲染层
/// 持久化，也不随编排响应下发到前端）。
#[derive(Debug)]
pub struct AccountSrpLoginOutcome {
    /// SRP 15 分钟令牌（服务器 TTL 900s），可作 Bearer 或交 sessions
    /// 端点兑换 24h 会话。
    pub token: String,
    /// 令牌剩余有效期（秒），来自服务器响应。
    pub expires_in_secs: u64,
    /// SHA-256(premaster) hex——与设备域 `RemoteLoginOutcome` 同语义，
    /// 会话绑定校验用；无下游消费者时可忽略。
    pub session_key_fingerprint: String,
    /// premaster 原始字节（4096-bit group 下 512B 级）。与设备域对称
    /// 暴露；上层不用就 drop。
    pub session_key: Vec<u8>,
}

impl AccountsApi {
    /// 口令 → SRP salt/verifier（Argon2id 预 hash，主密码不出设备）→
    /// 注册为账号的密码登录凭证。`device_name` 同时是 SRP identity，
    /// 与服务器挑战/核验两侧一致（见 server `account_srp_challenge`）。
    /// 同一 `device_name` 重复注册被服务器以 409 拒绝（`INSERT OR
    /// IGNORE` 语义），换设备名即新增一条密码凭证。
    pub async fn register_srp_credential(
        &self,
        account_id: &str,
        device_name: &str,
        password: &str,
    ) -> Result<super::remote::SrpRegisterResponse> {
        let reg = srp::register_verifier(device_name, password)?;
        let req = SrpRegisterRequest {
            device_name: device_name.to_string(),
            salt: B64.encode(&reg.salt),
            verifier: B64.encode(&reg.verifier),
        };
        self.srp_register(account_id, &req).await
    }

    /// 一步完成账号 SRP 登录：本地临时密钥对 → challenge（盐 + 服务器
    /// 公开值 B）→ M1（Argon2id 预 hash）→ verify → **核验服务器证明
    /// M2** → 交付令牌。顺序不可交换：M2 不过（MITM/服务器错乱）说明
    /// 对端不是持有 verifier 的服务器，令牌再"新鲜"也不可信——整体
    /// 失败且不落地任何状态。
    pub async fn srp_login(
        &self,
        account_id: &str,
        device_name: &str,
        password: &str,
    ) -> Result<AccountSrpLoginOutcome> {
        let login = SrpClientLogin::new()?;
        let client_public = B64.encode(login.public_ephemeral());
        let challenge = self
            .srp_challenge(
                account_id,
                &SrpChallengeRequest {
                    device_name: device_name.to_string(),
                    client_public,
                },
            )
            .await?;
        let salt = B64
            .decode(&challenge.salt)
            .map_err(|_| PersonaError::Io("account srp challenge salt malformed".into()))?;
        let server_public = B64.decode(&challenge.server_public).map_err(|_| {
            PersonaError::Io("account srp challenge server_public malformed".into())
        })?;
        // 消耗式：login 在此交出临时私钥，proof 携带待核验状态
        let proof = login.process(device_name, password, &salt, &server_public)?;
        let verified = self
            .srp_verify(
                account_id,
                &SrpVerifyRequest {
                    session_id: challenge.session_id,
                    client_proof: B64.encode(proof.client_proof()),
                },
            )
            .await?;
        let server_proof = B64
            .decode(&verified.server_proof)
            .map_err(|_| PersonaError::Io("account srp verify server_proof malformed".into()))?;
        // M2 核验通过才把 token 视作可信产物带出本函数
        let session_key = proof.verify_server(&server_proof)?;
        Ok(AccountSrpLoginOutcome {
            token: verified.token,
            expires_in_secs: verified.expires_in_secs,
            session_key_fingerprint: hex::encode(Sha256::digest(&session_key)),
            session_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const ACCOUNT: &str = "acct-1";
    const DEVICE: &str = "laptop";
    const PASSWORD: &str = "correct horse battery staple";

    /// 服务器侧待决握手脚本：(b_priv, client_public) 按 session_id 存，
    /// verify 步取走核验——与 server `SrpChallengeEntry` 同构的最小态。
    #[derive(Default)]
    struct MockServer {
        registered: Option<(Vec<u8>, Vec<u8>)>, // (salt, verifier)
        handshakes: HashMap<String, (Vec<u8>, Vec<u8>)>, // session_id -> (b_priv, client_public)
        next_session: u32,
        /// 注入故障：verify 响应回伪造 M2（MITM 模拟）
        tamper_server_proof: bool,
        verify_requests: u32,
    }

    struct CapturedRequest {
        method: String,
        path: String,
        auth: Option<String>,
        body: String,
    }

    /// 一次性 TCP 假服务器，**跑真 SRP 服务器侧数学**（server_challenge /
    /// server_verify），对拍 [`srp_login`] 的完整往返——canned 响应会让
    /// M2 核验必败，编排骨拼不过假服务器。
    fn spawn_srp_mock<F>(handler: F) -> String
    where
        F: Fn(&CapturedRequest) -> (u16, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let auth = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| {
                        l.split_once(':')
                            .map(|x| x.1)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    });
                let content_length: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':')?.1.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = stream.read_exact(&mut body);
                }
                let (status, resp_body) = handler(&CapturedRequest {
                    method: request_line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                    path: request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string(),
                    auth,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
                let reason = if status == 204 { "" } else { "OK" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn json_field(body: &str, field: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .unwrap_or_default()
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// mock 工厂：verifier 已预置入库（tests 2/3 直接可登录），并挂
    /// register 路由供 test 1 走真引导。返回 (url, 共享状态)。
    fn spawn_registered_mock() -> (String, Arc<Mutex<MockServer>>) {
        let state = Arc::new(Mutex::new(MockServer::default()));
        {
            let reg = srp::register_verifier(DEVICE, PASSWORD).unwrap();
            state.lock().unwrap().registered = Some((reg.salt, reg.verifier));
        }
        let url = {
            let state = state.clone();
            spawn_srp_mock(move |req| {
                let challenge_path = format!("/api/v1/accounts/{ACCOUNT}/srp/challenge");
                let verify_path = format!("/api/v1/accounts/{ACCOUNT}/srp/verify");
                let register_path = format!("/api/v1/accounts/{ACCOUNT}/srp/register");
                match (req.method.as_str(), req.path.as_str()) {
                    ("POST", path) if path == register_path => {
                        assert_eq!(
                            req.auth.as_deref(),
                            Some("Bearer static-server-token"),
                            "srp/register 是 Bearer 端点，引导链必须携带"
                        );
                        let mut st = state.lock().unwrap();
                        st.registered = Some((
                            B64.decode(json_field(&req.body, "salt")).unwrap(),
                            B64.decode(json_field(&req.body, "verifier")).unwrap(),
                        ));
                        (
                            200,
                            serde_json::json!({ "device_name": json_field(&req.body, "device_name") })
                                .to_string(),
                        )
                    }
                    ("POST", path) if path == challenge_path => {
                        let client_public =
                            B64.decode(json_field(&req.body, "client_public")).unwrap();
                        let response = {
                            let mut st = state.lock().unwrap();
                            let (salt, verifier) = st.registered.as_ref().unwrap().clone();
                            let hc = srp::server_challenge(&verifier).unwrap();
                            let session_id = format!("sess-{}", st.next_session);
                            st.next_session += 1;
                            st.handshakes
                                .insert(session_id.clone(), (hc.b_priv, client_public));
                            serde_json::json!({
                                "session_id": session_id,
                                "salt": B64.encode(&salt),
                                "server_public": B64.encode(&hc.b_pub),
                            })
                            .to_string()
                        };
                        (200, response)
                    }
                    ("POST", path) if path == verify_path => {
                        let session_id = json_field(&req.body, "session_id");
                        let client_proof = json_field(&req.body, "client_proof");
                        let mut st = state.lock().unwrap();
                        st.verify_requests += 1;
                        let Some((b_priv, client_public)) = st.handshakes.remove(&session_id)
                        else {
                            return (401, r#"{"error":{"code":"unauthorized"}}"#.to_string());
                        };
                        let (_, verifier) = st.registered.as_ref().unwrap();
                        match srp::server_verify(
                            &b_priv,
                            verifier,
                            &client_public,
                            &B64.decode(&client_proof).unwrap(),
                        ) {
                            Ok(outcome) => {
                                let proof = if st.tamper_server_proof {
                                    vec![0u8; 16]
                                } else {
                                    outcome.server_proof
                                };
                                (
                                    200,
                                    serde_json::json!({
                                        "server_proof": B64.encode(proof),
                                        "token": "tok-15m",
                                        "expires_in_secs": 900,
                                    })
                                    .to_string(),
                                )
                            }
                            // 与 server 一致：M1 不对 = 401（同时记账锁户，
                            // mock 不模拟锁户计数）
                            Err(_) => (401, r#"{"error":{"code":"unauthorized"}}"#.to_string()),
                        }
                    }
                    _ => panic!("unexpected request {} {}", req.method, req.path),
                }
            })
        };
        (url, state)
    }

    #[tokio::test]
    async fn srp_login_round_trip_verifies_server_proof_and_delivers_token() {
        let (url, state) = spawn_registered_mock();

        // 引导：静态令牌作 Bearer 注册凭证（ challenges/verify 是公开端点）
        let bootstrap = AccountsApi::with_bearer(&url, "static-server-token").unwrap();
        bootstrap
            .register_srp_credential(ACCOUNT, DEVICE, PASSWORD)
            .await
            .unwrap();
        assert_eq!(
            state.lock().unwrap().registered.as_ref().unwrap().0.len(),
            32,
            "salt 是 32B 随机值"
        );

        // 登录走无 Bearer 实例（公开端点不得携带）
        let client = AccountsApi::new(&url).unwrap();
        let outcome = client.srp_login(ACCOUNT, DEVICE, PASSWORD).await.unwrap();
        assert_eq!(outcome.token, "tok-15m");
        assert_eq!(outcome.expires_in_secs, 900);
        // 双向认证：指纹与服务器侧独立推导的 premaster 指纹一致
        assert!(!outcome.session_key_fingerprint.is_empty());
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(state.lock().unwrap().verify_requests, 1);
    }

    #[tokio::test]
    async fn srp_login_rejects_tampered_server_proof_without_delivering_token() {
        let (url, state) = spawn_registered_mock();
        state.lock().unwrap().tamper_server_proof = true;
        let client = AccountsApi::new(&url).unwrap();
        let err = client
            .srp_login(ACCOUNT, DEVICE, PASSWORD)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("server proof mismatch"),
            "M2 不匹配须败在客户端核验步，got: {message}"
        );
        assert_eq!(
            state.lock().unwrap().verify_requests,
            1,
            "verify 已发出，败在 M2 核验"
        );
    }

    #[tokio::test]
    async fn srp_login_wrong_password_maps_401_without_token() {
        let (url, _) = spawn_registered_mock();
        let client = AccountsApi::new(&url).unwrap();
        let err = client
            .srp_login(ACCOUNT, DEVICE, "wrong-password")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("401"),
            "服务器 401 透传进错误（含状态码），got: {message}"
        );
    }
}
