use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PasskeyCreateOptionsRequest {
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    /// base64url，1-64 字节
    pub user_handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
}

/// 响应是**裸** WebAuthn creation options JSON（服务器用 `serde_json::json!`
/// 组装的非类型化对象），客户端原样透传。
pub type PasskeyCreationOptions = serde_json::Value;

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterRequest {
    /// 认证器 attestation 响应（`{credentialId, attestationObject}`，均
    /// base64url 串）——服务器按 `serde_json::Value` 接收，原样透传。
    pub attestation_response: serde_json::Value,
    /// base64url
    pub client_data_json: String,
    pub origin: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterResponse {
    pub passkey_id: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyLoginOptionsRequest {
    pub credential_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
}

/// passkey 断言证据（sessions 端点；字段全为 base64url 编码）。
#[derive(Debug, Serialize)]
pub struct PasskeyAssertionRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub origin: String,
    pub authenticator_data: String,
    pub signature: String,
}

impl AccountsApi {
    /// POST /accounts/{id}/passkeys/create-options（公开）。响应是裸
    /// creation options（含服务器签发的 120s 一次性挑战）。
    pub async fn passkey_create_options(
        &self,
        account_id: &str,
        req: &PasskeyCreateOptionsRequest,
    ) -> Result<PasskeyCreationOptions> {
        let resp = self
            .http
            .request(
                Method::POST,
                &format!("/{account_id}/passkeys/create-options"),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!(
                    "account passkey create-options request failed: {e}"
                ))
            })?;
        let resp = Self::ensure_success(resp, "passkey create-options").await?;
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            PersonaError::Io(format!(
                "account passkey create-options response malformed: {e}"
            ))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/passkeys/register（公开）。提交认证器
    /// attestation；服务器做 RP 侧完整验证后存公钥材料。
    pub async fn passkey_register(
        &self,
        account_id: &str,
        req: &PasskeyRegisterRequest,
    ) -> Result<PasskeyRegisterResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/passkeys/register"))
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account passkey register request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "passkey register").await?;
        let value: PasskeyRegisterResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account passkey register response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// POST /accounts/{id}/passkeys/login-options（公开，登录仪式第一步）。
    pub async fn passkey_login_options(
        &self,
        account_id: &str,
        req: &PasskeyLoginOptionsRequest,
    ) -> Result<PasskeyLoginOptionsResponse> {
        let resp = self
            .http
            .request(
                Method::POST,
                &format!("/{account_id}/passkeys/login-options"),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account passkey login-options request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "passkey login-options").await?;
        let value: PasskeyLoginOptionsResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!(
                "account passkey login-options response malformed: {e}"
            ))
        })?;
        Ok(value)
    }
}
