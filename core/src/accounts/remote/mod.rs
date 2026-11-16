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
use std::time::Duration;

use crate::{PersonaError, Result};
mod devices;
mod passkey;
mod recovery;
mod register;
mod sessions;
mod srp;
pub use devices::{
    AccountDeviceInfo, AccountDevicesList, AuthorizeDeviceRequest, AuthorizeDeviceResponse,
};
pub use passkey::{
    PasskeyAssertionRequest, PasskeyCreateOptionsRequest, PasskeyCreationOptions,
    PasskeyLoginOptionsRequest, PasskeyLoginOptionsResponse, PasskeyRegisterRequest,
    PasskeyRegisterResponse,
};
pub use recovery::{RecoveryCodesResponse, VerifyRecoveryCodeRequest, VerifyRecoveryCodeResponse};
pub use register::{RegisterAccountRequest, RegisterAccountResponse};
pub use sessions::{AccountSessionInfo, CreateAccountSessionRequest};
pub use srp::{
    SrpChallengeRequest, SrpChallengeResponse, SrpRegisterRequest, SrpRegisterResponse,
    SrpVerifyRequest, SrpVerifyResponse,
};
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
}
#[cfg(test)]
mod tests;
