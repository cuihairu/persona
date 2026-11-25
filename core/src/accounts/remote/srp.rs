use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

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
    /// M1 in base64
    pub client_proof: String,
}

#[derive(Debug, Deserialize)]
pub struct SrpVerifyResponse {
    pub server_proof: String,
    /// The 15-minute account login token (usable as a Bearer or redeemable for a 24h session)
    pub token: String,
    pub expires_in_secs: u64,
}

impl AccountsApi {
    /// POST /accounts/{id}/srp/register (Bearer). Registers the SRP salt+verifier for a
    /// device inside the account (the fallback credential for password login).
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

    /// POST /accounts/{id}/srp/challenge (public; the first step of the login handshake).
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

    /// POST /accounts/{id}/srp/verify (public; completes the login handshake). Returns the
    /// 15-minute account login token (usable as a Bearer, or redeemable at the sessions
    /// endpoint for a 24h session).
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
}
