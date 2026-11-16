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

impl AccountsApi {
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
}
