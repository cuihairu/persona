//! Account-domain HTTP client (feature `accounts`): persona-server
//! `/api/v1/accounts/*`. The authoritative definition of the wire contract is
//! in `server/src/api/accounts.rs`: error envelope
//! `{"error":{"code","message",…}}`, JSON bodies, and a bodyless 204 for success.
//!
//! The discipline matches `sync/remote.rs`: this module only does wire work
//! (URL / method / JSON / status code / error mapping) and contains no
//! cryptography or session orchestration — SRP math and the WebAuthn
//! ceremony are completed by the caller, who hands over the final values.
//! Endpoints fall into two classes under the server contract:
//!
//! - Public endpoints ([`AccountsApi::new`]): register / passkeys create·register·
//!   login-options / srp challenge·verify / recovery-codes verify;
//! - Bearer endpoints ([`AccountsApi::with_bearer`]): srp register / recovery-codes
//!   generation / the three device endpoints / the two session endpoints.
//!
//! Bearer is one of three (server `require_account_bearer`): the static server
//! token, the SRP 15-minute short-lived token, or the account 24h session token —
//! this module does not decide which is valid, it only carries it through as-is.
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
// ---- Shared HTTP foundation ----

/// Base-URL normalization, optional bearer injection, and a uniform error
/// conversion for non-2xx. Isomorphic to `SyncHttp` in `sync/remote.rs`, but
/// accounts and sync are two separate server authentication surfaces, so they
/// do not share an implementation.
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
/// Client for persona-server `/api/v1/accounts/*`. Public endpoints need no
/// authentication; Bearer endpoints (see the list in the module docs) are built
/// with [`Self::with_bearer`].
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

    /// Non-2xx is uniformly converted to [`PersonaError::Io`]: carries the status code and
    /// a digest of the server's error.message (omitted when absent). Bodyless successes
    /// such as 204 pass straight through.
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

    /// A client that carries a Bearer. The Bearer is supplied by the host (the
    /// static server token / the SRP short-lived token / the account session token —
    /// this layer does not decide; it carries it through as-is and the server adjudicates).
    pub fn with_bearer(base_url: impl Into<String>, bearer: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: AccountHttp::new(base_url, Some(bearer.into()))?,
        })
    }
}
#[cfg(test)]
mod tests;
