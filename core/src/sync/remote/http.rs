//! 共享 HTTP 底座：base URL 归一、bearer 注入、非 2xx 统一转错。

use std::time::Duration;

use crate::{PersonaError, Result};

/// 共享 HTTP 底座：base URL 归一、bearer 注入、非 2xx 统一转错。
/// [`HttpSyncRemote`]（oplog 推拉）与 [`SyncAdminApi`]（设备/信封管理）共用。
#[derive(Clone)]
pub(super) struct SyncHttp {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl SyncHttp {
    /// `base_url` 形如 `http://127.0.0.1:8080`（尾部 `/` 容忍）。请求超时
    /// 60s：单批最多 500 条 KB 级密文，要覆盖慢速链路，但远小于备份链的
    /// 300s。
    pub(super) fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                PersonaError::ConfigurationError(format!("HTTP client init failed: {e}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
        })
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}/api/v1/sync{path}", self.base_url)
    }

    pub(super) fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, self.url(path))
            .bearer_auth(&self.token)
    }

    /// 非 2xx 统一转 [`PersonaError::Io`]：带状态码与服务器 error.message
    /// 摘要（无则省略）。401/503 语义（令牌过期 / API 未配置）由调用方按
    /// 状态码字符串自行提示——本层不区分重试策略。
    pub(super) async fn ensure_success(
        resp: reqwest::Response,
        step: &str,
    ) -> Result<reqwest::Response> {
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
                "sync {step} failed (HTTP {status}): {message}"
            ))
            .into()),
            None => Err(PersonaError::Io(format!("sync {step} failed (HTTP {status})")).into()),
        }
    }
}
