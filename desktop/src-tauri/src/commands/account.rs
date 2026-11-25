use super::*;

/// settings.sync.server_url (the account and sync share the same server
/// address). Uses only the url, never reads the token — the account bearer is
/// stored separately in the account token store.
pub(crate) async fn account_server_for(
    state: &State<'_, AppState>,
) -> std::result::Result<String, String> {
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    let sync_config = match read_sync_config(state, &db_path).await {
        Some(config) => config,
        None => return Err("Sync server URL is not configured".to_string()),
    };
    let server_url = sync_config.server_url.trim().to_string();
    if server_url.is_empty() {
        return Err("Sync server URL is not configured".to_string());
    }
    Ok(server_url)
}

/// Client for public account endpoints (no Bearer).
pub(crate) async fn account_api_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::accounts::remote::AccountsApi, String> {
    let server_url = account_server_for(state).await?;
    persona_core::accounts::remote::AccountsApi::new(&server_url)
        .map_err(|e| format!("Invalid account server configuration: {e}"))
}

/// Client for Bearer account endpoints: resolves the account bearer from the
/// keyring (fail-closed).
pub(crate) async fn account_api_with_bearer_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::accounts::remote::AccountsApi, String> {
    let server_url = account_server_for(state).await?;
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    let bearer = state
        .account_token_store
        .get(&db_path)
        .map_err(|e| format!("OS keyring read failed: {e}"))?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            "Account session is not configured — finish the account login first".to_string()
        })?;
    persona_core::accounts::remote::AccountsApi::with_bearer(&server_url, &bearer)
        .map_err(|e| format!("Invalid account server configuration: {e}"))
}

/// Bearer resolution (bootstrap-chain-closing version): prefer the account
/// session token; with no account session, fall back to the static server
/// token (the one the sync config writes into `token_store`). The server's
/// `require_account_bearer` treats the static token and the account token
/// alike — when a brand-new account registers its first SRP credential there
/// is no account session yet, and the static token is a contract-legal
/// bootstrap Bearer; without the fallback the SRP credential could never be
/// created (deadlock). Used only by the bootstrap-style command
/// (`account_srp_register_with_password`); regular Bearer commands still go
/// through [`account_api_with_bearer_for`], keeping the "account session
/// fail-closed" semantics.
pub(crate) async fn account_api_with_bearer_or_bootstrap_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::accounts::remote::AccountsApi, String> {
    let server_url = account_server_for(state).await?;
    let db_path = require_db_path(state)
        .await
        .ok_or_else(|| "Database path unavailable. Initialize the service first.".to_string())?;
    let bearer = match state
        .account_token_store
        .get(&db_path)
        .map_err(|e| format!("OS keyring read failed: {e}"))?
        .filter(|t| !t.trim().is_empty())
    {
        Some(token) => token,
        None => state
            .token_store
            .get(&db_path)
            .map_err(|e| format!("OS keyring read failed: {e}"))?
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| {
                "No account session and no server token — configure sync first".to_string()
            })?,
    };
    persona_core::accounts::remote::AccountsApi::with_bearer(&server_url, &bearer)
        .map_err(|e| format!("Invalid account server configuration: {e}"))
}

impl From<AccountRegisterRequest> for persona_core::accounts::remote::RegisterAccountRequest {
    fn from(req: AccountRegisterRequest) -> Self {
        Self {
            username: req.username,
            display_name: req.display_name,
        }
    }
}

impl From<AccountPasskeyCreateOptionsRequest>
    for persona_core::accounts::remote::PasskeyCreateOptionsRequest
{
    fn from(req: AccountPasskeyCreateOptionsRequest) -> Self {
        Self {
            rp_id: req.rp_id,
            rp_name: req.rp_name,
            user_handle: req.user_handle,
            user_name: req.user_name,
            user_display_name: req.user_display_name,
        }
    }
}

impl From<AccountPasskeyRegisterRequest>
    for persona_core::accounts::remote::PasskeyRegisterRequest
{
    fn from(req: AccountPasskeyRegisterRequest) -> Self {
        Self {
            attestation_response: req.attestation_response,
            client_data_json: req.client_data_json,
            origin: req.origin,
        }
    }
}

impl From<AccountPasskeyLoginOptionsRequest>
    for persona_core::accounts::remote::PasskeyLoginOptionsRequest
{
    fn from(req: AccountPasskeyLoginOptionsRequest) -> Self {
        Self {
            credential_id: req.credential_id,
        }
    }
}

impl From<AccountSrpRegisterRequest> for persona_core::accounts::remote::SrpRegisterRequest {
    fn from(req: AccountSrpRegisterRequest) -> Self {
        Self {
            device_name: req.device_name,
            salt: req.salt,
            verifier: req.verifier,
        }
    }
}

impl From<AccountSrpChallengeRequest> for persona_core::accounts::remote::SrpChallengeRequest {
    fn from(req: AccountSrpChallengeRequest) -> Self {
        Self {
            device_name: req.device_name,
            client_public: req.client_public,
        }
    }
}

impl From<AccountSrpVerifyRequest> for persona_core::accounts::remote::SrpVerifyRequest {
    fn from(req: AccountSrpVerifyRequest) -> Self {
        Self {
            session_id: req.session_id,
            client_proof: req.client_proof,
        }
    }
}

impl From<AccountVerifyRecoveryCodeRequest>
    for persona_core::accounts::remote::VerifyRecoveryCodeRequest
{
    fn from(req: AccountVerifyRecoveryCodeRequest) -> Self {
        Self { code: req.code }
    }
}

impl From<AccountAuthorizeDeviceRequest>
    for persona_core::accounts::remote::AuthorizeDeviceRequest
{
    fn from(req: AccountAuthorizeDeviceRequest) -> Self {
        Self {
            device_id: req.device_id,
            public_key: req.public_key,
        }
    }
}

impl From<AccountSessionEvidence> for persona_core::accounts::remote::CreateAccountSessionRequest {
    fn from(req: AccountSessionEvidence) -> Self {
        Self {
            srp_token: req.srp_token,
            passkey_assertion: req.passkey_assertion.map(|assertion| {
                persona_core::accounts::remote::PasskeyAssertionRequest {
                    credential_id: assertion.credential_id,
                    client_data_json: assertion.client_data_json,
                    origin: assertion.origin,
                    authenticator_data: assertion.authenticator_data,
                    signature: assertion.signature,
                }
            }),
        }
    }
}

impl From<persona_core::accounts::remote::AccountSessionInfo> for AccountSessionInfo {
    fn from(info: persona_core::accounts::remote::AccountSessionInfo) -> Self {
        Self {
            session_token: info.session_token,
            expires_in_secs: info.expires_in_secs,
        }
    }
}

impl From<persona_core::accounts::remote::AccountDeviceInfo> for AccountDeviceInfo {
    fn from(dev: persona_core::accounts::remote::AccountDeviceInfo) -> Self {
        Self {
            id: dev.id,
            device_id: dev.device_id,
            device_name: dev.device_name,
            public_key: dev.public_key,
            status: dev.status,
            authorized_by: dev.authorized_by,
            authorized_at: dev.authorized_at,
            revoked_at: dev.revoked_at,
            revoked_by: dev.revoked_by,
            created_at: dev.created_at,
        }
    }
}

/// Writes the account-domain binding (explicit action): `Some` = bind (called
/// by the frontend after a wizard signup/login succeeds), `None` = unbind
/// (together with revoke_session when signing out of the account).
/// Non-sensitive identifiers are stored in the vault JSON
/// (`WorkspaceSettings.account`); the token's real value lives in the OS
/// keyring (ACCOUNT_SERVICE) and never passes through this command. Reads go
/// through `get_workspace_settings` (the same settings are served directly).
#[command(rename_all = "snake_case")]
pub async fn set_account_binding(
    binding: Option<persona_core::models::workspace::AccountBinding>,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<WorkspaceSettings>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = db_path_or_return!(state);
    let db = open_db_or_return!(db_path);
    let workspace_path = workspace_path_for_db_path(&db_path);
    let repo = WorkspaceRepository::new(db.clone());
    let mut ws = workspace_or_return!(db, workspace_path);
    ws.settings.account = binding;
    ws.touch();
    let updated = ok_or_error_response!(repo.update(&ws).await);
    Ok(ApiResponse::success(updated.settings))
}

/// Register a new account publicly (no authentication required).
#[command(rename_all = "snake_case")]
pub async fn account_register(
    request: AccountRegisterRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountRegistrationResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.register_account(&request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountRegistrationResponse {
            account_id: resp.account_id,
            username: resp.username,
            display_name: resp.display_name,
        })),
        Err(e) => Ok(ApiResponse::error(format!("Account register failed: {e}"))),
    }
}

/// Passkey registration options (public endpoint). The response is the bare
/// WebAuthn creation options issued by the server (a 120s one-time challenge),
/// passed through unchanged.
#[command(rename_all = "snake_case")]
pub async fn account_passkey_create_options(
    account_id: String,
    request: AccountPasskeyCreateOptionsRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<serde_json::Value>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api
        .passkey_create_options(&account_id, &request.into())
        .await
    {
        Ok(options) => Ok(ApiResponse::success(options)),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account passkey create-options failed: {e}"
        ))),
    }
}

/// Passkey registration completion (public endpoint). Submits the
/// authenticator's attestation; after the server performs full RP-side
/// verification it stores the public key material.
#[command(rename_all = "snake_case")]
pub async fn account_passkey_register(
    account_id: String,
    request: AccountPasskeyRegisterRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountPasskeyRegisterResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.passkey_register(&account_id, &request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountPasskeyRegisterResponse {
            passkey_id: resp.passkey_id,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account passkey register failed: {e}"
        ))),
    }
}

/// Passkey login options (public endpoint, first step of the login ceremony).
/// Exchanges the credential id for the server challenge (120s one-time),
/// consumed at assertion time.
#[command(rename_all = "snake_case")]
pub async fn account_passkey_login_options(
    account_id: String,
    request: AccountPasskeyLoginOptionsRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountPasskeyLoginOptionsResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api
        .passkey_login_options(&account_id, &request.into())
        .await
    {
        Ok(resp) => Ok(ApiResponse::success(AccountPasskeyLoginOptionsResponse {
            challenge: resp.challenge,
            rp_id: resp.rp_id,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account passkey login-options failed: {e}"
        ))),
    }
}

/// SRP credential registration (Bearer endpoint). Registers the SRP
/// salt+verifier for a device within the account (the fallback credential for
/// password login).
#[command(rename_all = "snake_case")]
pub async fn account_srp_register(
    account_id: String,
    request: AccountSrpRegisterRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSrpRegisterResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.srp_register(&account_id, &request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountSrpRegisterResponse {
            device_name: resp.device_name,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account SRP register failed: {e}"
        ))),
    }
}

/// SRP challenge request (public endpoint, login step). Starts the account SRP login handshake.
#[command(rename_all = "snake_case")]
pub async fn account_srp_challenge(
    account_id: String,
    request: AccountSrpChallengeRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSrpChallengeResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.srp_challenge(&account_id, &request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountSrpChallengeResponse {
            session_id: resp.session_id,
            salt: resp.salt,
            server_public: resp.server_public,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account SRP challenge failed: {e}"
        ))),
    }
}

/// SRP verification completion (public endpoint, login step). Finishes the handshake and returns
/// the 15-minute SRP login token; besides passing the result through, this command writes the
/// token into the keyring as the resolution source for the account bearer (so later
/// Bearer-gated commands don't need the frontend to send it back).
#[command(rename_all = "snake_case")]
pub async fn account_srp_verify(
    account_id: String,
    request: AccountSrpVerifyRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSrpVerifyResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let resp = match api.srp_verify(&account_id, &request.into()).await {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Account SRP verify failed: {e}"
            )))
        }
    };
    if let Err(e) = state.account_token_store.set(&db_path, &resp.token) {
        return Ok(ApiResponse::error(format!(
            "Account login succeeded but storing the session token failed: {e}"
        )));
    }
    Ok(ApiResponse::success(AccountSrpVerifyResponse {
        server_proof: resp.server_proof,
        token: resp.token,
        expires_in_secs: resp.expires_in_secs,
    }))
}

/// Wizard-style SRP credential registration (bootstrap command): the password is derived into
/// salt/verifier in core and registered on the account, and neither the wire values nor the
/// password ever round-trip through the frontend. Bearer goes through
/// [`account_api_with_bearer_or_bootstrap_for`] (account session, falling back to the static
/// server token); the raw-wire [`account_srp_register`] keeps its account-session
/// fail-closed behaviour unchanged. The two paths have different Bearer semantics.
#[command(rename_all = "snake_case")]
pub async fn account_srp_register_with_password(
    account_id: String,
    request: AccountSrpRegisterWithPasswordRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSrpRegisterResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_or_bootstrap_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api
        .register_srp_credential(&account_id, &request.device_name, &request.password)
        .await
    {
        Ok(resp) => Ok(ApiResponse::success(AccountSrpRegisterResponse {
            device_name: resp.device_name,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account SRP register failed: {e}"
        ))),
    }
}

/// Wizard-style SRP login: the challenge/verify two-leg dance and the M2 check are all
/// orchestrated in core (the token is never handed over if the server proof fails), and the
/// 15-minute token is written straight to `account_token_store` — the response carries no token
/// body, only the validity period and the session fingerprint, which is all the render layer
/// sees. Exchanging it for a 24h session goes through [`account_create_session`] (with the
/// srp_token evidence).
#[command(rename_all = "snake_case")]
pub async fn account_srp_login(
    account_id: String,
    request: AccountSrpLoginRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSrpLoginResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let outcome = match api
        .srp_login(&account_id, &request.device_name, &request.password)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return Ok(ApiResponse::error(format!("Account SRP login failed: {e}"))),
    };
    if let Err(e) = state.account_token_store.set(&db_path, &outcome.token) {
        return Ok(ApiResponse::error(format!(
            "Account login succeeded but storing the session token failed: {e}"
        )));
    }
    Ok(ApiResponse::success(AccountSrpLoginResponse {
        expires_in_secs: outcome.expires_in_secs,
        session_key_fingerprint: outcome.session_key_fingerprint,
    }))
}

/// Exchange for a 24h account session (orchestration command): the 15-minute SRP token in the
/// keyring serves as both the Bearer and the body evidence (the server sessions endpoint is a
/// double gate of Bearer plus exactly one kind of evidence; on the SRP path both are the same
/// token), and the resulting 24h session token is written straight to the keyring, overwriting
/// the short-lived token. The token body never crosses IPC; the passkey-assertion evidence path
/// still uses the bare [`account_create_session`] (the assertion is produced by the frontend's
/// WebAuthn ceremony).
#[command(rename_all = "snake_case")]
pub async fn account_exchange_session(
    account_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSessionExchangeResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let server_url = account_server_for(&state).await?;
    let bearer = state
        .account_token_store
        .get(&db_path)
        .map_err(|e| format!("OS keyring read failed: {e}"))?
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            "Account session is not configured — finish the account login first".to_string()
        })?;
    let api = persona_core::accounts::remote::AccountsApi::with_bearer(&server_url, &bearer)
        .map_err(|e| format!("Invalid account server configuration: {e}"))?;
    let evidence = persona_core::accounts::remote::CreateAccountSessionRequest {
        srp_token: Some(bearer),
        passkey_assertion: None,
    };
    let resp = match api.create_account_session(&account_id, &evidence).await {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Account session exchange failed: {e}"
            )))
        }
    };
    if let Err(e) = state.account_token_store.set(&db_path, &resp.session_token) {
        return Ok(ApiResponse::error(format!(
            "Account session created but storing the session token failed: {e}"
        )));
    }
    Ok(ApiResponse::success(AccountSessionExchangeResponse {
        expires_in_secs: resp.expires_in_secs,
    }))
}

/// Sign out of the account (orchestration command): revokes the current token held in the
/// keyring (both the 15-minute short-lived token and the 24h session live in the server's
/// `account_sessions` table, and the same DELETE revokes itself) and clears the local keyring.
/// Server-side revocation is best-effort (expired/nonexistent tokens don't block sign-out);
/// local cleanup is a hard semantic — only a failed keyring clear is an error. The binding
/// (settings.account) is cleared by the frontend along with the success response.
#[command(rename_all = "snake_case")]
pub async fn account_sign_out(
    account_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSignOutResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let bearer = state
        .account_token_store
        .get(&db_path)
        .map_err(|e| format!("OS keyring read failed: {e}"))?
        .filter(|t| !t.trim().is_empty());
    let Some(bearer) = bearer else {
        // No local token left = already signed out; idempotent success (revoked_on_server=false)
        return Ok(ApiResponse::success(AccountSignOutResponse {
            revoked_on_server: false,
        }));
    };
    let mut revoked_on_server = false;
    if let Ok(server_url) = account_server_for(&state).await {
        if let Ok(api) =
            persona_core::accounts::remote::AccountsApi::with_bearer(&server_url, &bearer)
        {
            revoked_on_server = api
                .revoke_account_session(&account_id, &bearer)
                .await
                .is_ok();
        }
    }
    if let Err(e) = state.account_token_store.delete(&db_path) {
        return Ok(ApiResponse::error(format!(
            "Failed to clear the local account token: {e}"
        )));
    }
    Ok(ApiResponse::success(AccountSignOutResponse {
        revoked_on_server,
    }))
}

/// Generate recovery codes (Bearer endpoint). Each call produces a fresh batch (8 codes);
/// previously unused ones are invalidated.
#[command(rename_all = "snake_case")]
pub async fn account_generate_recovery_codes(
    account_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountRecoveryCodes>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.generate_recovery_codes(&account_id).await {
        Ok(resp) => Ok(ApiResponse::success(AccountRecoveryCodes {
            codes: resp.codes,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account recovery-codes failed: {e}"
        ))),
    }
}

/// Verify a recovery code (public endpoint). One-time use; marked as consumed once verified.
#[command(rename_all = "snake_case")]
pub async fn account_verify_recovery_code(
    account_id: String,
    request: AccountVerifyRecoveryCodeRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountVerifyRecoveryCodeResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.verify_recovery_code(&account_id, &request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountVerifyRecoveryCodeResponse {
            success: resp.success,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account recovery-code verify failed: {e}"
        ))),
    }
}

/// Authorize a device for the account (Bearer endpoint). Associates an already-registered sync
/// device (matched by device_id + public key) with the account.
#[command(rename_all = "snake_case")]
pub async fn account_authorize_device(
    account_id: String,
    request: AccountAuthorizeDeviceRequest,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountAuthorizeDeviceResponse>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.authorize_device(&account_id, &request.into()).await {
        Ok(resp) => Ok(ApiResponse::success(AccountAuthorizeDeviceResponse {
            id: resp.id,
            status: resp.status,
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account authorize-device failed: {e}"
        ))),
    }
}

/// List the devices authorized under the account (Bearer endpoint).
#[command(rename_all = "snake_case")]
pub async fn account_list_devices(
    account_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountDevicesList>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.list_account_devices(&account_id).await {
        Ok(resp) => Ok(ApiResponse::success(AccountDevicesList {
            devices: resp.devices.into_iter().map(Into::into).collect(),
        })),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account list-devices failed: {e}"
        ))),
    }
}

/// Revoke a device under the account (Bearer endpoint). A 204 with no body signals success.
#[command(rename_all = "snake_case")]
pub async fn account_revoke_device(
    account_id: String,
    device_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api.revoke_account_device(&account_id, &device_id).await {
        Ok(ok) => Ok(ApiResponse::success(ok)),
        Err(e) => Ok(ApiResponse::error(format!(
            "Account revoke-device failed: {e}"
        ))),
    }
}

/// Create an account session (Bearer endpoint). Exchanges exactly one piece of login evidence (the
/// SRP 15-minute token or a passkey assertion) for a 24h account session token; on success the
/// token overwrites the account bearer in the keyring (sign-out/renewal semantics: the most
/// recent login's session is the one valid locally).
#[command(rename_all = "snake_case")]
pub async fn account_create_session(
    account_id: String,
    request: AccountSessionEvidence,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<AccountSessionInfo>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    let resp = match api
        .create_account_session(&account_id, &request.into())
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(ApiResponse::error(format!(
                "Account create-session failed: {e}"
            )))
        }
    };
    if let Err(e) = state.account_token_store.set(&db_path, &resp.session_token) {
        return Ok(ApiResponse::error(format!(
            "Account session created but storing the session token failed: {e}"
        )));
    }
    Ok(ApiResponse::success(AccountSessionInfo::from(resp)))
}

/// Revoke an account session (Bearer endpoint). Signs out that session token; if the revoked
/// token is exactly the active session held in the local keyring, it is cleared too (self
/// revocation = signing the local account out).
#[command(rename_all = "snake_case")]
pub async fn account_revoke_session(
    account_id: String,
    session_token: String,
    state: State<'_, AppState>,
) -> std::result::Result<ApiResponse<bool>, String> {
    if let Some(message) = require_unlocked(&state).await {
        return Ok(ApiResponse::error(message));
    }
    let db_path = match require_db_path(&state).await {
        Some(db_path) => db_path,
        None => {
            return Ok(ApiResponse::error(
                "Database path unavailable. Initialize the service first.".to_string(),
            ))
        }
    };
    let api = match account_api_with_bearer_for(&state).await {
        Ok(api) => api,
        Err(message) => return Ok(ApiResponse::error(message)),
    };
    match api
        .revoke_account_session(&account_id, &session_token)
        .await
    {
        Ok(ok) => {
            let stored = state
                .account_token_store
                .get(&db_path)
                .unwrap_or(None)
                .unwrap_or_default();
            if stored == session_token {
                let _ = state.account_token_store.delete(&db_path);
            }
            Ok(ApiResponse::success(ok))
        }
        Err(e) => Ok(ApiResponse::error(format!(
            "Account revoke-session failed: {e}"
        ))),
    }
}
