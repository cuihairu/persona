//! 账号域 HTTP 客户端（feature `accounts`）：persona-server
//! `/api/v1/accounts/*`。wire 契约的权威定义在 `server/src/api/accounts.rs`：
//! 错误包络 `{"error":{"code","message",…}}`，正文为 JSON，204 为无体成功。
//!
//! 纪律与 `sync/remote.rs` 一致：本模块只做 wire（URL/方法/JSON/状态码/错误
//! 映射），不含任何密码学或会话编排——SRP 数学、WebAuthn 仪式由调用方
//! 完成后把最终值交过来。端点按服务器契约分两类：
//!
//! - 公开端点（[`AccountsApi::new`]）：register / passkeys create·register·
//!   login-options / srp challenge·verify / recovery-codes verify；
//! - Bearer 端点（[`AccountsApi::with_bearer`]）：srp register / recovery-codes
//!   生成 / devices 三件套 / sessions 两件套。
//!
//! Bearer 三选一（服务器 `require_account_bearer`）：静态服务器令牌、SRP 15
//! 分钟短期令牌、账号 24h 会话令牌——本模块不判定哪个有效，只负责原样携带。

use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{PersonaError, Result};

// ---- wire 类型（字段名与 server/src/api/accounts.rs 对齐）----

#[derive(Debug, Serialize)]
pub struct RegisterAccountRequest {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAccountResponse {
    pub account_id: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyCreateOptionsRequest {
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    /// base64url，1-64 字节
    pub user_handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
}

/// 响应是**裸** WebAuthn creation options JSON（服务器用 `serde_json::json!`
/// 组装的非类型化对象），客户端原样透传。
pub type PasskeyCreationOptions = serde_json::Value;

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterRequest {
    /// 认证器 attestation 响应（`{credentialId, attestationObject}`，均
    /// base64url 串）——服务器按 `serde_json::Value` 接收，原样透传。
    pub attestation_response: serde_json::Value,
    /// base64url
    pub client_data_json: String,
    pub origin: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterResponse {
    pub passkey_id: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyLoginOptionsRequest {
    pub credential_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
}

#[derive(Debug, Serialize)]
pub struct SrpRegisterRequest {
    pub device_name: String,
    /// base64
    pub salt: String,
    /// base64
    pub verifier: String,
}

#[derive(Debug, Deserialize)]
pub struct SrpRegisterResponse {
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct SrpChallengeRequest {
    pub device_name: String,
    /// base64
    pub client_public: String,
}

#[derive(Debug, Deserialize)]
pub struct SrpChallengeResponse {
    pub session_id: String,
    pub salt: String,
    pub server_public: String,
}

#[derive(Debug, Serialize)]
pub struct SrpVerifyRequest {
    pub session_id: String,
    /// base64 的 M1
    pub client_proof: String,
}

#[derive(Debug, Deserialize)]
pub struct SrpVerifyResponse {
    pub server_proof: String,
    /// 15 分钟账号登录令牌（可作 Bearer 或换 24h 会话）
    pub token: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyRecoveryCodeRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRecoveryCodeResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeDeviceRequest {
    /// sync_devices.id
    pub device_id: String,
    /// base64，32 字节 X25519
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountDeviceInfo {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub status: String,
    #[serde(default)]
    pub authorized_by: Option<String>,
    #[serde(default)]
    pub authorized_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountDevicesList {
    pub devices: Vec<AccountDeviceInfo>,
}

/// passkey 断言证据（sessions 端点；字段全为 base64url 编码）。
#[derive(Debug, Serialize)]
pub struct PasskeyAssertionRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub origin: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// sessions 端点证据：SRP 15 分钟令牌或 passkey 断言，**恰好一种**
/// （服务器两者同给/都缺 = 422，不猜语义）。
#[derive(Debug, Default, Serialize)]
pub struct CreateAccountSessionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srp_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkey_assertion: Option<PasskeyAssertionRequest>,
}

#[derive(Debug, Deserialize)]
pub struct AccountSessionInfo {
    pub session_token: String,
    pub expires_in_secs: u64,
}

// ---- 共享 HTTP 底座 ----

/// base URL 归一、可选 bearer 注入、非 2xx 统一转错。与 `sync/remote.rs`
/// 的 `SyncHttp` 同构，但账号与 sync 是两套服务器认证面，不复用互串。
#[derive(Clone)]
struct AccountHttp {
    base_url: String,
    bearer: Option<String>,
    http: reqwest::Client,
}

impl AccountHttp {
    fn new(base_url: impl Into<String>, bearer: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                PersonaError::ConfigurationError(format!("HTTP client init failed: {e}"))
            })?;
        Ok(Self {
            base_url: base_url.into(),
            bearer,
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/accounts{path}",
            self.base_url.trim_end_matches('/')
        )
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let mut builder = self.http.request(method, self.url(path));
        if let Some(bearer) = &self.bearer {
            builder = builder.bearer_auth(bearer);
        }
        builder
    }
}

/// 对 persona-server `/api/v1/accounts/*` 的客户端。公开端点免认证；
/// Bearer 端点（见模块文档清单）用 [`Self::with_bearer`] 构造。
#[derive(Clone)]
pub struct AccountsApi {
    http: AccountHttp,
}

impl AccountsApi {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: AccountHttp::new(base_url, None)?,
        })
    }

    /// 非 2xx 统一转 [`PersonaError::Io`]：带状态码与服务器 error.message
    /// 摘要（无则省略）。204 等无体成功直接放行。
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
        match detail {
            Some(message) => Err(PersonaError::Io(format!(
                "account {step} failed (HTTP {status}): {message}"
            ))
            .into()),
            None => Err(PersonaError::Io(format!("account {step} failed (HTTP {status})")).into()),
        }
    }

    /// 携带 Bearer 的客户端。Bearer 由宿主提供（静态服务器令牌 / SRP 短期
    /// 令牌 / 账号会话令牌——本层不判定，原样携带，服务器裁决）。
    pub fn with_bearer(base_url: impl Into<String>, bearer: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: AccountHttp::new(base_url, Some(bearer.into()))?,
        })
    }

    /// POST /accounts/register（公开）。201 返回账号基本信息。
    pub async fn register_account(
        &self,
        req: &RegisterAccountRequest,
    ) -> Result<RegisterAccountResponse> {
        let resp = self
            .http
            .request(Method::POST, "/register")
            .json(req)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account register request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "register").await?;
        let value: RegisterAccountResponse = resp
            .json()
            .await
            .map_err(|e| PersonaError::Io(format!("account register response malformed: {e}")))?;
        Ok(value)
    }

    /// POST /accounts/{id}/passkeys/create-options（公开）。响应是裸
    /// creation options（含服务器签发的 120s 一次性挑战）。
    pub async fn passkey_create_options(
        &self,
        account_id: &str,
        req: &PasskeyCreateOptionsRequest,
    ) -> Result<PasskeyCreationOptions> {
        let resp = self
            .http
            .request(
                Method::POST,
                &format!("/{account_id}/passkeys/create-options"),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!(
                    "account passkey create-options request failed: {e}"
                ))
            })?;
        let resp = Self::ensure_success(resp, "passkey create-options").await?;
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            PersonaError::Io(format!(
                "account passkey create-options response malformed: {e}"
            ))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/passkeys/register（公开）。提交认证器
    /// attestation；服务器做 RP 侧完整验证后存公钥材料。
    pub async fn passkey_register(
        &self,
        account_id: &str,
        req: &PasskeyRegisterRequest,
    ) -> Result<PasskeyRegisterResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/passkeys/register"))
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account passkey register request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "passkey register").await?;
        let value: PasskeyRegisterResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account passkey register response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/passkeys/login-options（公开，登录仪式第一步）。
    pub async fn passkey_login_options(
        &self,
        account_id: &str,
        req: &PasskeyLoginOptionsRequest,
    ) -> Result<PasskeyLoginOptionsResponse> {
        let resp = self
            .http
            .request(
                Method::POST,
                &format!("/{account_id}/passkeys/login-options"),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account passkey login-options request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "passkey login-options").await?;
        let value: PasskeyLoginOptionsResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!(
                "account passkey login-options response malformed: {e}"
            ))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/srp/register（Bearer）。登记账号内设备的 SRP
    /// salt+verifier（密码登录的兜底凭据）。
    pub async fn srp_register(
        &self,
        account_id: &str,
        req: &SrpRegisterRequest,
    ) -> Result<SrpRegisterResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/srp/register"))
            .json(req)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account srp register request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "srp register").await?;
        let value: SrpRegisterResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account srp register response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/srp/challenge（公开，登录握手第一步）。
    pub async fn srp_challenge(
        &self,
        account_id: &str,
        req: &SrpChallengeRequest,
    ) -> Result<SrpChallengeResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/srp/challenge"))
            .json(req)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account srp challenge request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "srp challenge").await?;
        let value: SrpChallengeResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account srp challenge response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/srp/verify（公开，登录握手完成）。返回 15 分钟
    /// 账号登录令牌（可作 Bearer，或交 sessions 端点兑换 24h 会话）。
    pub async fn srp_verify(
        &self,
        account_id: &str,
        req: &SrpVerifyRequest,
    ) -> Result<SrpVerifyResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/srp/verify"))
            .json(req)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account srp verify request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "srp verify").await?;
        let value: SrpVerifyResponse = resp
            .json()
            .await
            .map_err(|e| PersonaError::Io(format!("account srp verify response malformed: {e}")))?;
        Ok(value)
    }

    /// POST /accounts/{id}/recovery-codes（Bearer）。每次调用生成新一组
    /// （8 个），旧未用的作废。
    pub async fn generate_recovery_codes(&self, account_id: &str) -> Result<RecoveryCodesResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/recovery-codes"))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account recovery-codes request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "recovery-codes").await?;
        let value: RecoveryCodesResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account recovery-codes response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/recovery-codes/verify（公开）。一次性消费。
    pub async fn verify_recovery_code(
        &self,
        account_id: &str,
        req: &VerifyRecoveryCodeRequest,
    ) -> Result<VerifyRecoveryCodeResponse> {
        let resp = self
            .http
            .request(
                Method::POST,
                &format!("/{account_id}/recovery-codes/verify"),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account recovery-codes verify request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "recovery-codes verify").await?;
        let value: VerifyRecoveryCodeResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!(
                "account recovery-codes verify response malformed: {e}"
            ))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/devices（Bearer）。把已登记的 sync 设备（按
    /// device_id + 公钥比对）关联到账号。
    pub async fn authorize_device(
        &self,
        account_id: &str,
        req: &AuthorizeDeviceRequest,
    ) -> Result<AuthorizeDeviceResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/devices"))
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account authorize-device request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "authorize device").await?;
        let value: AuthorizeDeviceResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account authorize-device response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// GET /accounts/{id}/devices（Bearer）。账号下的已授权设备列表。
    pub async fn list_account_devices(&self, account_id: &str) -> Result<AccountDevicesList> {
        let resp = self
            .http
            .request(Method::GET, &format!("/{account_id}/devices"))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account list-devices request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "list devices").await?;
        let value: AccountDevicesList = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account list-devices response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// DELETE /accounts/{id}/devices/{device_id}（Bearer）。204 无体成功。
    pub async fn revoke_account_device(&self, account_id: &str, device_id: &str) -> Result<bool> {
        let resp = self
            .http
            .request(
                Method::DELETE,
                &format!("/{account_id}/devices/{device_id}"),
            )
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account revoke-device request failed: {e}")))?;
        Self::ensure_success(resp, "revoke device").await?;
        Ok(true)
    }

    /// POST /accounts/{id}/sessions（Bearer）。凭恰好一种登录证据（SRP 15
    /// 分钟令牌或 passkey 断言）兑换 24h 账号会话令牌。
    pub async fn create_account_session(
        &self,
        account_id: &str,
        req: &CreateAccountSessionRequest,
    ) -> Result<AccountSessionInfo> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/sessions"))
            .json(req)
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account create-session request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "create session").await?;
        let value: AccountSessionInfo = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account create-session response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// DELETE /accounts/{id}/sessions/{session_token}（Bearer）。登出该
    /// 会话令牌。204 无体成功。
    pub async fn revoke_account_session(
        &self,
        account_id: &str,
        session_token: &str,
    ) -> Result<bool> {
        let resp = self
            .http
            .request(
                Method::DELETE,
                &format!("/{account_id}/sessions/{session_token}"),
            )
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account revoke-session request failed: {e}")))?;
        Self::ensure_success(resp, "revoke session").await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct CapturedRequest {
        method: String,
        path: String,
        auth: Option<String>,
        body: String,
    }

    /// 起一个一次性 TCP 假服务器：读请求（head + Content-Length 体），
    /// 调 handler 得 (状态码, 响应体)，回写极简 HTTP/1.1 响应。
    fn spawn_mock<F>(handler: F) -> String
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
                // head 到 \r\n\r\n
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

    fn b64v(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn empty_json() -> String {
        "{}".to_string()
    }

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

    #[tokio::test]
    async fn passkey_create_options_returns_bare_options_json() {
        let url = spawn_mock(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/create-options");
            assert!(req.auth.is_none());
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["rp_id"], "example.com");
            assert_eq!(body["user_handle"], b64v(&[1u8; 32]));
            (
                200,
                r#"{"rp":{"id":"example.com","name":"example.com"},"user":{"id":"a","name":"n","displayName":"d"},"challenge":"ch","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"preferred"},"timeout":60000,"attestation":"none"}"#.to_string(),
            )
        });
        let client = AccountsApi::new(url).unwrap();
        let options = client
            .passkey_create_options(
                "acct-1",
                &PasskeyCreateOptionsRequest {
                    rp_id: "example.com".to_string(),
                    rp_name: None,
                    user_handle: b64v(&[1u8; 32]),
                    user_name: None,
                    user_display_name: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(options["challenge"], "ch");
        assert_eq!(options["rp"]["id"], "example.com");
        assert_eq!(options["pubKeyCredParams"][0]["alg"], -7);
    }

    #[tokio::test]
    async fn passkey_register_relays_attestation_value_and_parses_passkey_id() {
        let url = spawn_mock(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/register");
            assert!(req.auth.is_none());
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["attestation_response"]["credentialId"], "cid");
            assert_eq!(body["origin"], "https://account.example.com");
            (200, r#"{"passkey_id":"pk-1"}"#.to_string())
        });
        let client = AccountsApi::new(url).unwrap();
        let resp = client
            .passkey_register(
                "acct-1",
                &PasskeyRegisterRequest {
                    attestation_response: serde_json::json!({"credentialId": "cid", "attestationObject": "ao"}),
                    client_data_json: b64v(b"{}"),
                    origin: "https://account.example.com".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.passkey_id, "pk-1");
    }

    #[tokio::test]
    async fn passkey_login_options_parses_challenge() {
        let url = spawn_mock(|req| {
            assert_eq!(req.path, "/api/v1/accounts/acct-1/passkeys/login-options");
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["credential_id"], "pk-1");
            (
                200,
                r#"{"challenge":"ch","rp_id":"example.com"}"#.to_string(),
            )
        });
        let client = AccountsApi::new(url).unwrap();
        let resp = client
            .passkey_login_options(
                "acct-1",
                &PasskeyLoginOptionsRequest {
                    credential_id: "pk-1".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.rp_id, "example.com");
    }

    #[tokio::test]
    async fn srp_register_requires_bearer_and_relays_credential_material() {
        let url = spawn_mock(|req| {
            assert_eq!(req.path, "/api/v1/accounts/acct-1/srp/register");
            assert_eq!(
                req.auth.as_deref(),
                Some("Bearer bearer-1"),
                "srp register is a Bearer endpoint"
            );
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["device_name"], "laptop");
            assert_eq!(body["salt"], b64v(&[7u8; 16]));
            assert_eq!(body["verifier"], b64v(&[9u8; 96]));
            (200, r#"{"device_name":"laptop"}"#.to_string())
        });
        let client = AccountsApi::with_bearer(url, "bearer-1").unwrap();
        let resp = client
            .srp_register(
                "acct-1",
                &SrpRegisterRequest {
                    device_name: "laptop".to_string(),
                    salt: b64v(&[7u8; 16]),
                    verifier: b64v(&[9u8; 96]),
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.device_name, "laptop");
    }

    #[tokio::test]
    async fn srp_challenge_and_verify_are_public_and_parse_handshake() {
        let url = spawn_mock(|req| match req.path.as_str() {
            "/api/v1/accounts/acct-1/srp/challenge" => {
                assert!(req.auth.is_none());
                assert_eq!(req.method, "POST");
                (
                    200,
                    r#"{"session_id":"s1","salt":"c2FsdA==","server_public":"cHVibGlj"}"#
                        .to_string(),
                )
            }
            "/api/v1/accounts/acct-1/srp/verify" => {
                assert!(req.auth.is_none());
                let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                assert_eq!(body["session_id"], "s1");
                assert_eq!(body["client_proof"], "cHJvb2Y=");
                (
                    200,
                    r#"{"server_proof":"cHJvb2Y=","token":"tok-15m","expires_in_secs":900}"#
                        .to_string(),
                )
            }
            other => panic!("unexpected path {other}"),
        });
        let client = AccountsApi::new(url).unwrap();
        let challenge = client
            .srp_challenge(
                "acct-1",
                &SrpChallengeRequest {
                    device_name: "laptop".to_string(),
                    client_public: "cHVibGlj".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(challenge.session_id, "s1");
        assert_eq!(challenge.salt, "c2FsdA==");

        let verify = client
            .srp_verify(
                "acct-1",
                &SrpVerifyRequest {
                    session_id: "s1".to_string(),
                    client_proof: "cHJvb2Y=".to_string(),
                },
            )
            .await
            .unwrap();
        assert_eq!(verify.server_proof, "cHJvb2Y=");
        assert_eq!(verify.token, "tok-15m");
        assert_eq!(verify.expires_in_secs, 900);
    }

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
                r#"{"codes":["aabb","ccdd","eeff","0011","2233","4455","6677","8899"]}"#
                    .to_string(),
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

    #[tokio::test]
    async fn create_session_relays_each_evidence_variant() {
        // srp_token 证据
        let url = spawn_mock(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/api/v1/accounts/acct-1/sessions");
            assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(body["srp_token"], "tok-15m");
            assert!(body.get("passkey_assertion").is_none());
            (
                200,
                r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
            )
        });
        let client = AccountsApi::with_bearer(url, "tok").unwrap();
        let resp = client
            .create_account_session(
                "acct-1",
                &CreateAccountSessionRequest {
                    srp_token: Some("tok-15m".to_string()),
                    passkey_assertion: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.session_token, "sess-24h");
        assert_eq!(resp.expires_in_secs, 86400);

        // passkey_assertion 证据
        let url = spawn_mock(|req| {
            let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            let assertion = &body["passkey_assertion"];
            assert!(body.get("srp_token").is_none());
            assert_eq!(assertion["credential_id"], "pk-1");
            assert_eq!(assertion["signature"], "c2ln");
            (
                200,
                r#"{"session_token":"sess-24h","expires_in_secs":86400}"#.to_string(),
            )
        });
        let client = AccountsApi::with_bearer(url, "tok").unwrap();
        client
            .create_account_session(
                "acct-1",
                &CreateAccountSessionRequest {
                    srp_token: None,
                    passkey_assertion: Some(PasskeyAssertionRequest {
                        credential_id: "pk-1".to_string(),
                        client_data_json: "Y2Rq".to_string(),
                        origin: "https://account.example.com".to_string(),
                        authenticator_data: "YXV0aA==".to_string(),
                        signature: "c2ln".to_string(),
                    }),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoke_session_204_returns_true() {
        let url = spawn_mock(|req| {
            assert_eq!(req.method, "DELETE");
            assert_eq!(req.path, "/api/v1/accounts/acct-1/sessions/sess-24h");
            assert_eq!(req.auth.as_deref(), Some("Bearer tok"));
            (204, empty_json())
        });
        let client = AccountsApi::with_bearer(url, "tok").unwrap();
        let ok = client
            .revoke_account_session("acct-1", "sess-24h")
            .await
            .unwrap();
        assert!(ok);
    }

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
        // 状态行自带规范原因短语（含 "Bad Gateway"），断言应针对 body——
        // body 非 JSON 时不得出现在错误消息里。
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
}
