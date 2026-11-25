//! Shared HTTP foundation: base URL normalization, bearer injection, and a uniform mapping of non-2xx to errors.

use std::time::Duration;

use crate::{PersonaError, Result};

/// Shared HTTP foundation: base URL normalization, bearer injection, and a uniform mapping of non-2xx to errors.
/// Used by both [`HttpSyncRemote`] (oplog pull/push) and [`SyncAdminApi`] (device/envelope management).
#[derive(Clone)]
pub(super) struct SyncHttp {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl SyncHttp {
    /// `base_url` looks like `http://127.0.0.1:8080` (a trailing `/` is tolerated). The request timeout is
    /// 60s: a single batch holds at most 500 KB-scale ciphertexts, which must cover slow links while staying
    /// far below the backup chain's 300s.
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

    /// Non-2xx is mapped to [`PersonaError::Io`]: the status code plus the server's error.message
    /// summary (omitted when absent). The 401/503 semantics (expired token / API not configured) are
    /// reported by the caller from the status code string — this layer does not distinguish retry policies.
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
