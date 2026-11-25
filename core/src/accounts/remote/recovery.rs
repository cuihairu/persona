use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

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

impl AccountsApi {
    /// POST /accounts/{id}/recovery-codes (Bearer). Each call generates a fresh set
    /// (8 codes); previously unused ones are invalidated.
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

    /// POST /accounts/{id}/recovery-codes/verify (public). Single-use consumption.
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
}
