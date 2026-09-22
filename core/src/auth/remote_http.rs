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
#[derive(Clone)]
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
