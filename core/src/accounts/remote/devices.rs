use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct AuthorizeDeviceRequest {
    /// sync_devices.id
    pub device_id: String,
    /// base64，32 字节 X25519
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountDeviceInfo {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub status: String,
    #[serde(default)]
    pub authorized_by: Option<String>,
    #[serde(default)]
    pub authorized_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountDevicesList {
    pub devices: Vec<AccountDeviceInfo>,
}

impl AccountsApi {
    /// POST /accounts/{id}/devices（Bearer）。把已登记的 sync 设备（按
    /// device_id + 公钥比对）关联到账号。
    pub async fn authorize_device(
        &self,
        account_id: &str,
        req: &AuthorizeDeviceRequest,
    ) -> Result<AuthorizeDeviceResponse> {
        let resp = self
            .http
            .request(Method::POST, &format!("/{account_id}/devices"))
            .json(req)
            .send()
            .await
            .map_err(|e| {
                PersonaError::Io(format!("account authorize-device request failed: {e}"))
            })?;
        let resp = Self::ensure_success(resp, "authorize device").await?;
        let value: AuthorizeDeviceResponse = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account authorize-device response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// GET /accounts/{id}/devices（Bearer）。账号下的已授权设备列表。
    pub async fn list_account_devices(&self, account_id: &str) -> Result<AccountDevicesList> {
        let resp = self
            .http
            .request(Method::GET, &format!("/{account_id}/devices"))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account list-devices request failed: {e}")))?;
        let resp = Self::ensure_success(resp, "list devices").await?;
        let value: AccountDevicesList = resp.json().await.map_err(|e| {
            PersonaError::Io(format!("account list-devices response malformed: {e}"))
        })?;
        Ok(value)
    }

    /// DELETE /accounts/{id}/devices/{device_id}（Bearer）。204 无体成功。
    pub async fn revoke_account_device(&self, account_id: &str, device_id: &str) -> Result<bool> {
        let resp = self
            .http
            .request(
                Method::DELETE,
                &format!("/{account_id}/devices/{device_id}"),
            )
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("account revoke-device request failed: {e}")))?;
        Self::ensure_success(resp, "revoke device").await?;
        Ok(true)
    }
}
