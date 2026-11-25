use super::AccountsApi;
use crate::{PersonaError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PasskeyCreateOptionsRequest {
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    /// base64url, 1-64 bytes
    pub user_handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
}

/// The response is the **raw** WebAuthn creation options JSON (an untyped object the server
/// assembles with `serde_json::json!`); the client passes it through verbatim.
pub type PasskeyCreationOptions = serde_json::Value;

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterRequest {
    /// The authenticator attestation response (`{credentialId, attestationObject}`, both
    /// base64url strings) — the server accepts it as `serde_json::Value` and passes it through verbatim.
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

/// Passkey assertion evidence (sessions endpoint; all fields are base64url-encoded).
#[derive(Debug, Serialize)]
pub struct PasskeyAssertionRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub origin: String,
    pub authenticator_data: String,
    pub signature: String,
}

impl AccountsApi {
    /// POST /accounts/{id}/passkeys/create-options (public). The response is the raw
    /// creation options (including the server-issued 120s one-time challenge).
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

    /// POST /accounts/{id}/passkeys/register (public). Submits the authenticator
    /// attestation; after full RP-side verification the server stores the public key material.
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

    /// POST /accounts/{id}/passkeys/login-options (public; the first step of the login ceremony).
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
