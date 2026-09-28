//! SRP 设备认证的 HTTP 客户端编排（feature `remote-auth`）：把 [`super::srp`]
//! 的 SRP-6a 数学接到 persona-server 的 `/api/v1/auth/*` 三端点。wire 契约的
//! 权威定义在 `server/src/api/auth.rs`：base64 STANDARD、错误包络
//! `{"error":{"code","message",…}}`、锁户 423。
//!
//! 与 [`super::remote`] 的 mock trait（UI seam）分工：mock 的两步形状
//! （begin/finalize 收发 proof 字符串）装不下真实 SRP 的状态流——M1 的计算
//! 需要口令，且 `a_priv` 必须由单一持有者从生成 A 贯穿到 M2 核验，中途不能
//! 经 trait 边界拆散。真实客户端因此是独立类型：登录会话状态由
//! [`PendingRemoteLogin`] 显式持有（含传输句柄），`finish` 消耗它。未来
//! OPAQUE 迁移（E2EE_SYNC_DESIGN DR-2）替换的正是这个文件的编排；数学层
//! 与调用方语义不动。
//!
//! fail-closed 口径：非 2xx 一律 [`PersonaError::AuthenticationFailed`]，
//! 消息只带 HTTP 状态与服务器 error 摘要——未注册设备与握手失败在服务器
//! 侧已同形 401，客户端不叠加猜测；423（锁户）单独点名，便于上层决定是否
//! 提示等待。服务器证明 M2 未通过核验时**不**向上层交付 token（先核验后
//! 使用，server VerifyResponse 字段注释的客户端侧对应实现）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::{PersonaError, Result};

use super::srp::{register_verifier, SrpClientLogin, SrpClientProof};

/// POST /api/v1/auth/challenge 响应（只取所需字段）。
#[derive(serde::Deserialize)]
struct ChallengeWire {
    session_id: String,
    salt: String,
    server_public: String,
}

/// POST /api/v1/auth/verify 响应。
#[derive(serde::Deserialize)]
struct VerifyWire {
    server_proof: String,
    token: String,
    expires_in_secs: u64,
}

/// 对 persona-server `/api/v1/auth/*` 的 SRP 客户端。无内部可变状态：
/// 登录会话状态在 [`PendingRemoteLogin`] 里，token 由调用方持有。
#[derive(Clone, Debug)]
pub struct HttpRemoteAuthProvider {
    base_url: String,
    http: reqwest::Client,
}

impl HttpRemoteAuthProvider {
    /// `base_url` 形如 `http://127.0.0.1:8080`（尾部 `/` 容忍）。
    /// 请求超时 30s：握手含 Argon2id 预 hash（19 MiB），远小于备份链的
    /// 300s，但要覆盖慢速服务器往返。
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("HTTP client init failed: {e}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// 引导注册：生成 salt/verifier 并 `POST /auth/register`。要求既有
    /// Bearer（引导链的 token）——服务器侧注册是认证体系的引导入口，
    /// 不是免认证操作。
    pub async fn register_device(
        &self,
        bearer: &str,
        device_name: &str,
        password: &str,
    ) -> Result<()> {
        let reg = register_verifier(device_name, password)?;
        let resp = self
            .post("/auth/register", Some(bearer))
            .json(&serde_json::json!({
                "device_name": device_name,
                "salt": B64.encode(&reg.salt),
                "verifier": B64.encode(&reg.verifier),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("register request failed: {e}"))
            })?;
        ensure_success(resp, "register").await.map(|_| ())
    }

    /// 登录第一步：本地生成临时密钥对，带公开值 `A` 请求 challenge，
    /// 服务器回盐与 `B`。服务器侧握手缓存 120s 且一次性——返回的
    /// [`PendingRemoteLogin`] 绑定该 session，`finish` 必须在窗口内完成。
    pub async fn begin_login(&self, device_name: &str) -> Result<PendingRemoteLogin> {
        let login = SrpClientLogin::new()?;
        let resp = self
            .post("/auth/challenge", None)
            .json(&serde_json::json!({
                "device_name": device_name,
                "client_public": B64.encode(login.public_ephemeral()),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("challenge request failed: {e}"))
            })?;
        let resp = ensure_success(resp, "challenge").await?;
        let wire: ChallengeWire = resp
            .json()
            .await
            .map_err(|_| malformed_wire("challenge response"))?;
        Ok(PendingRemoteLogin {
            provider: self.clone(),
            device_name: device_name.to_string(),
            login,
            session_id: wire.session_id,
            salt_b64: wire.salt,
            server_public_b64: wire.server_public,
        })
    }

    /// 统一请求构造（路径挂在 `/api/v1` 下；`bearer` 仅注册步有）。
    fn post(&self, path: &str, bearer: Option<&str>) -> reqwest::RequestBuilder {
        let builder = self.http.post(format!("{}/api/v1{}", self.base_url, path));
        match bearer {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }
}

/// 进行中的 SRP 登录会话：`finish` 消耗自身（`SrpClientLogin` 一次性），
/// 成功后状态清零；超时/失败后丢弃重建即可（服务器侧握手缓存一并过期）。
#[derive(Debug)]
pub struct PendingRemoteLogin {
    provider: HttpRemoteAuthProvider,
    device_name: String,
    login: SrpClientLogin,
    session_id: String,
    salt_b64: String,
    server_public_b64: String,
}

impl PendingRemoteLogin {
    /// 登录完成步：口令 → SRP 私钥 x（Argon2id 预 hash）→ M1 →
    /// `POST /verify` → 核验服务器证明 M2 → 交付短期 token 与会话密钥。
    /// 顺序不可交换：token 只有在 M2 核验通过后才算可信。
    pub async fn finish(self, password: &str) -> Result<RemoteLoginOutcome> {
        let salt = B64
            .decode(&self.salt_b64)
            .map_err(|_| malformed_wire("salt"))?;
        let server_public = B64
            .decode(&self.server_public_b64)
            .map_err(|_| malformed_wire("server_public"))?;
        let proof: SrpClientProof =
            self.login
                .process(&self.device_name, password, &salt, &server_public)?;
        let resp = self
            .provider
            .post("/auth/verify", None)
            .json(&serde_json::json!({
                "session_id": self.session_id,
                "client_proof": B64.encode(proof.client_proof()),
            }))
            .send()
            .await
            .map_err(|e| {
                PersonaError::AuthenticationFailed(format!("verify request failed: {e}"))
            })?;
        let resp = ensure_success(resp, "verify").await?;
        let wire: VerifyWire = resp
            .json()
            .await
            .map_err(|_| malformed_wire("verify response"))?;
        let server_proof = B64
            .decode(&wire.server_proof)
            .map_err(|_| malformed_wire("server_proof"))?;
        // M2 核验失败（MITM/服务器错乱）——premaster 拿不到，token 不交付
        let session_key = proof.verify_server(&server_proof)?;
        let fingerprint = hex::encode(Sha256::digest(&session_key));
        Ok(RemoteLoginOutcome {
            token: wire.token,
            expires_in_secs: wire.expires_in_secs,
            session_key_fingerprint: fingerprint,
            session_key,
        })
    }
}

/// 登录成功产物：短期 Bearer token + 双方各自可推导的会话指纹。
#[derive(Debug)]
pub struct RemoteLoginOutcome {
    /// 短期 Bearer token（服务器 TTL 15min），调用方持有并在过期前重登。
    pub token: String,
    /// token 剩余有效期（秒），来自服务器响应。
    pub expires_in_secs: u64,
    /// SHA-256(premaster) hex——客户端与服务器对同一 premaster 独立计算，
    /// 可作会话绑定校验（mock trait `session_key_fingerprint` 语义的实化）。
    pub session_key_fingerprint: String,
    /// premaster 原始字节（4096-bit group = 512B），上层需要会话密钥时用；
    /// 不需要就丢弃，指纹足够。
    pub session_key: Vec<u8>,
}

/// 非 2xx 统一转 [`PersonaError::AuthenticationFailed`]：423 点名锁户，
/// 其余带状态码与服务器 error.message 摘要（无则省略）。成功时原样归还
/// Response 供调用方继续解码 JSON。
async fn ensure_success(resp: reqwest::Response, step: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    if status.as_u16() == 423 {
        return Err(PersonaError::AuthenticationFailed(
            "remote auth failed: device locked (HTTP 423); retry later".to_string(),
        )
        .into());
    }
    match detail {
        Some(message) => Err(PersonaError::AuthenticationFailed(format!(
            "remote auth {step} failed (HTTP {status}): {message}"
        ))
        .into()),
        None => Err(PersonaError::AuthenticationFailed(format!(
            "remote auth {step} failed (HTTP {status})"
        ))
        .into()),
    }
}

fn malformed_wire(field: &str) -> PersonaError {
    PersonaError::AuthenticationFailed(format!("remote auth: malformed wire field {field:?}"))
}

#[cfg(all(test, feature = "remote-auth"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::super::srp::{server_challenge, server_verify, SRP_SALT_LEN};

    /// mock 服务器收到的一次请求（路径 + 原始头 + JSON body）。
    struct CapturedRequest {
        path: String,
        headers: String,
        body: serde_json::Value,
    }

    /// 手写 HTTP mock：真 TCP 上回放固定编排。core 的 dev-deps 没有现成
    /// HTTP mock（wiremock 等），而 reqwest 对手写 TCP 响应完全够用——
    /// 每连接读一个请求、按 handler 回一个 `Connection: close` 响应。
    /// handler 返回 (HTTP 状态码, JSON body 字符串)；状态码 0 = 不回包
    /// 直接断开（模拟服务器在请求中途失联）。
    type Handler = Arc<dyn Fn(CapturedRequest) -> (u16, String) + Send + Sync>;

    /// challenge ↔ verify 之间 mock 服务器持有的 SRP 会话：(b_priv, a_pub)。
    type SrpServerState = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

    /// 起本地 mock 服务器，返回 base_url（`http://127.0.0.1:<port>`）。
    /// accept loop 挂在 multi_thread runtime 的后台 task 上，测试结束
    /// 时随 runtime 一起丢弃（listener 未显式关闭，端口由 OS 回收）。
    async fn spawn_mock(handler: Handler) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Some(req) = read_request(&mut stream).await {
                        let (status, body) = handler(req);
                        // 约定 status 0：不给响应直接断开（请求发送失败路径）
                        if status == 0 {
                            return;
                        }
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {body}",
                            body.len(),
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// 读一个完整 HTTP 请求（头 + Content-Length 定长的 body）。
    /// reqwest 每个 `Connection: close` 请求一条连接，单请求即够。
    async fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end;
        loop {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let path = headers.split_whitespace().nth(1)?.to_string();
        let content_length: usize = headers
            .to_ascii_lowercase()
            .lines()
            .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let body = serde_json::from_str(&String::from_utf8_lossy(&buf[header_end..]))
            .unwrap_or(serde_json::Value::Null);
        Some(CapturedRequest {
            path,
            headers,
            body,
        })
    }

    /// 已注册设备的 (salt, verifier)，供 mock 服务器扮演 SRP 侧。
    fn fixture_verifier(password: &str) -> (Vec<u8>, Vec<u8>) {
        let reg = register_verifier("laptop", password).unwrap();
        (reg.salt, reg.verifier)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_posts_verifier_with_bearer_and_tolerates_trailing_slash() {
        let captured: std::sync::Arc<Mutex<Vec<CapturedRequest>>> = Default::default();
        let sink = captured.clone();
        // base_url 尾部 `/` 容忍：mock 地址故意带斜杠
        let base = format!(
            "{}/",
            spawn_mock(Arc::new(move |req| {
                sink.lock().unwrap().push(req);
                (200, "{}".to_string())
            }))
            .await
        );
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        provider
            .register_device("bootstrap-tok", "laptop", "pw")
            .await
            .unwrap();

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        // 引导注册必须带既有 Bearer（注册是认证体系的入口，不是免认证操作）
        assert!(
            req.headers.contains("authorization: Bearer bootstrap-tok"),
            "missing bearer: {}",
            req.headers
        );
        assert_eq!(req.path, "/api/v1/auth/register");
        assert_eq!(req.body["device_name"], "laptop");
        // salt/verifier 都是 base64 STANDARD 编码的原始字节
        assert_eq!(
            B64.decode(req.body["salt"].as_str().unwrap())
                .unwrap()
                .len(),
            SRP_SALT_LEN
        );
        assert!(!B64
            .decode(req.body["verifier"].as_str().unwrap())
            .unwrap()
            .is_empty());
    }

    /// 非 2xx 统一转 AuthenticationFailed，并带上步骤名、状态码与服务器
    /// error.message 摘要（wire 契约的客户端侧口径）。
    #[tokio::test(flavor = "multi_thread")]
    async fn http_error_surfaces_step_status_and_server_message() {
        let base = spawn_mock(Arc::new(|_req| {
            (
                401,
                r#"{"error":{"code":"unknown_device","message":"no such device"}}"#.to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("register"), "{msg}");
        assert!(msg.contains("HTTP 401"), "{msg}");
        assert!(msg.contains("no such device"), "{msg}");
    }

    /// 423（锁户）单独点名，供上层决定是否提示等待——不透传服务器消息。
    #[tokio::test(flavor = "multi_thread")]
    async fn device_lock_is_called_out_on_423() {
        let base = spawn_mock(Arc::new(|_req| {
            (423, r#"{"error":{"message":"locked"}}"#.to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("device locked (HTTP 423)"), "{msg}");
        // 点名锁户的固定文案不掺服务器摘要
        assert!(!msg.contains("locked\""), "{msg}");
    }

    /// 服务器响应不是 JSON 包络（如反代 502 HTML）时省略摘要，只留状态。
    #[tokio::test(flavor = "multi_thread")]
    async fn non_json_error_body_omits_detail() {
        let base = spawn_mock(Arc::new(|_req| {
            (502, "<html>bad gateway</html>".to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("HTTP 502"), "{msg}");
        assert!(!msg.contains("bad gateway"), "{msg}");
    }

    /// challenge 响应缺字段/坏 JSON：fail-closed，不进入 finish。
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_challenge_response_is_rejected() {
        let base = spawn_mock(Arc::new(|_req| {
            (200, "{\"session_id\":\"s1\"}".to_string())
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let err = provider.begin_login("laptop").await.unwrap_err();
        assert!(err.to_string().contains("malformed wire field"), "{err}");
    }

    /// B 非法（合法 base64，但 B mod N = 0——srp 层唯一拒绝的形态）：
    /// 编排层原样透传为 AuthenticationFailed（防恶意服务器降级）。
    #[tokio::test(flavor = "multi_thread")]
    async fn illegal_server_public_value_is_rejected() {
        let (salt, _verifier) = fixture_verifier("pw");
        let illegal_b = super::super::srp::srp_group().n.to_bytes_be();
        let base = spawn_mock(Arc::new(move |_req| {
            (
                200,
                serde_json::json!({
                    "session_id": "s1",
                    "salt": B64.encode(&salt),
                    "server_public": B64.encode(&illegal_b),
                })
                .to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish("pw").await.unwrap_err();
        assert!(
            err.to_string().contains("rejected server public value"),
            "{err}"
        );
    }

    /// 全流程（mock 服务器真跑 SRP 服务器侧）：token 交付 + 指纹 =
    /// sha256(session_key) hex + premaster 512B（4096-bit group）。
    #[tokio::test(flavor = "multi_thread")]
    async fn full_login_delivers_token_with_matching_fingerprint() {
        use sha2::Digest as _;

        let password = "correct horse battery staple";
        let (salt, verifier) = fixture_verifier(password);
        // challenge 与 verify 之间的服务器会话：(b_priv, a_pub)
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                "/api/v1/auth/verify" => {
                    let (b_priv, a) = st.take().unwrap();
                    assert_eq!(req.body["session_id"], "sess-1");
                    let m1 = B64
                        .decode(req.body["client_proof"].as_str().unwrap())
                        .unwrap();
                    match server_verify(&b_priv, &verifier, &a, &m1) {
                        Ok(out) => (
                            200,
                            serde_json::json!({
                                "server_proof": B64.encode(out.server_proof),
                                "token": "tok-1",
                                "expires_in_secs": 900,
                            })
                            .to_string(),
                        ),
                        Err(_) => (
                            401,
                            r#"{"error":{"message":"client proof mismatch"}}"#.to_string(),
                        ),
                    }
                }
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let outcome = provider
            .begin_login("laptop")
            .await
            .unwrap()
            .finish(password)
            .await
            .unwrap();

        assert_eq!(outcome.token, "tok-1");
        assert_eq!(outcome.expires_in_secs, 900);
        assert_eq!(outcome.session_key.len(), 512);
        assert_eq!(
            outcome.session_key_fingerprint,
            hex::encode(Sha256::digest(&outcome.session_key))
        );
    }

    /// M2 被篡改（MITM/服务器错乱）：核心安全语义——token 不交付。
    #[tokio::test(flavor = "multi_thread")]
    async fn tampered_server_proof_withholds_token() {
        let password = "another stable passphrase";
        let (salt, verifier) = fixture_verifier(password);
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                "/api/v1/auth/verify" => {
                    let (b_priv, a) = st.take().unwrap();
                    let m1 = B64
                        .decode(req.body["client_proof"].as_str().unwrap())
                        .unwrap();
                    let mut out = server_verify(&b_priv, &verifier, &a, &m1).unwrap();
                    out.server_proof[0] ^= 0xFF; // 单字节翻转即核验失败
                    (
                        200,
                        serde_json::json!({
                            "server_proof": B64.encode(out.server_proof),
                            "token": "must-not-be-delivered",
                            "expires_in_secs": 900,
                        })
                        .to_string(),
                    )
                }
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("server proof mismatch"), "{err}");
    }

    /// challenge 下发的 salt 不是合法 base64：finish 侧 fail-closed。
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_salt_b64_is_rejected() {
        let base = spawn_mock(Arc::new(|_req| {
            (
                200,
                serde_json::json!({
                    "session_id": "s1",
                    "salt": "!!not-base64!!",
                    "server_public": B64.encode([0x02u8; 8]),
                })
                .to_string(),
            )
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish("pw").await.unwrap_err();
        assert!(
            err.to_string().contains(r#"malformed wire field "salt""#),
            "{err}"
        );
    }

    /// 连接被拒：三步各自的 send 失败都带步骤名的 AuthenticationFailed
    /// （fail-closed，错误不吞）。register 与 challenge 指向未监听端口，
    /// verify 用"challenge 正常回、verify 时断连"的 mock 触发。
    #[tokio::test(flavor = "multi_thread")]
    async fn connection_failures_surface_with_step_names() {
        // 未监听端口：bind 后立即 drop，端口必然无服务
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);
        let provider = HttpRemoteAuthProvider::new(format!("http://{dead_addr}")).unwrap();

        let err = provider
            .register_device("tok", "laptop", "pw")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("register request failed"), "{err}");

        let err = provider.begin_login("laptop").await.unwrap_err();
        assert!(
            err.to_string().contains("challenge request failed"),
            "{err}"
        );

        // verify 步：challenge 正常，verify 连接被服务器直接断开
        let password = "pw-verify-drop";
        let (salt, verifier) = fixture_verifier(password);
        let base = spawn_mock(Arc::new(move |req| match req.path.as_str() {
            "/api/v1/auth/challenge" => (
                200,
                serde_json::json!({
                    "session_id": "sess-1",
                    "salt": B64.encode(&salt),
                    "server_public": B64.encode(server_challenge(&verifier).unwrap().b_pub),
                })
                .to_string(),
            ),
            _ => (0, String::new()),
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();
        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("verify request failed"), "{err}");
    }

    /// verify 响应缺字段：M1 都发出去了也拿不到 token（fail-closed）。
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_verify_response_is_rejected() {
        let password = "pw-for-wire";
        let (salt, verifier) = fixture_verifier(password);
        let state: SrpServerState = Default::default();
        let srv = state.clone();
        let base = spawn_mock(Arc::new(move |req| {
            let mut st = srv.lock().unwrap();
            match req.path.as_str() {
                "/api/v1/auth/challenge" => {
                    let a = B64
                        .decode(req.body["client_public"].as_str().unwrap())
                        .unwrap();
                    let ch = server_challenge(&verifier).unwrap();
                    *st = Some((ch.b_priv, a));
                    (
                        200,
                        serde_json::json!({
                            "session_id": "sess-1",
                            "salt": B64.encode(&salt),
                            "server_public": B64.encode(ch.b_pub),
                        })
                        .to_string(),
                    )
                }
                // M1 合法但响应缺 server_proof/token 字段
                "/api/v1/auth/verify" => (200, "{}".to_string()),
                other => panic!("unexpected path {other}"),
            }
        }))
        .await;
        let provider = HttpRemoteAuthProvider::new(base).unwrap();

        let pending = provider.begin_login("laptop").await.unwrap();
        let err = pending.finish(password).await.unwrap_err();
        assert!(err.to_string().contains("malformed wire field"), "{err}");
    }
}
