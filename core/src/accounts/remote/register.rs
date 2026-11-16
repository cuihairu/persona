use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

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

impl AccountsApi {
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
}
