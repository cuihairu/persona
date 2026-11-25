use super::passkey::PasskeyAssertionRequest;
use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// Evidence for the sessions endpoint: an SRP 15-minute token or a passkey
/// assertion — **exactly one** (the server returns 422 if both are given or
/// both are missing; we do not guess at the semantics).
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

impl AccountsApi {
    /// POST /accounts/{id}/sessions (Bearer). Redeems a 24h account session token using
    /// exactly one piece of login evidence (an SRP 15-minute token or a passkey assertion).
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

    /// DELETE /accounts/{id}/sessions/{session_token} (Bearer). Logs that session token
    /// out. A bodyless 204 means success.
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
