use super::passkey::PasskeyAssertionRequest;
use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

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

impl AccountsApi {
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
