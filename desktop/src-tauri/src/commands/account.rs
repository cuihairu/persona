use super::*;

/// settings.sync.server_url（账号与 sync 共用同一服务器地址）。只用
/// url，不读 token——账号 bearer 独立存 account token store。
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

/// 账号公开端点客户端（免 Bearer）。
pub(crate) async fn account_api_for(
    state: &State<'_, AppState>,
) -> std::result::Result<persona_core::accounts::remote::AccountsApi, String> {
    let server_url = account_server_for(state).await?;
    persona_core::accounts::remote::AccountsApi::new(&server_url)
        .map_err(|e| format!("Invalid account server configuration: {e}"))
}

/// 账号 Bearer 端点客户端：从 keyring 解析账号 bearer（fail-closed）。
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

/// Bearer 解析（引导链闭合版）：优先账号会话令牌；没有账号会话时回退
/// 静态服务器令牌（sync 配置写入 `token_store` 的那枚）。服务器
/// `require_account_bearer` 对静态令牌与账号令牌一视同仁——全新账号
/// 注册第一把 SRP 凭证时还没有任何账号会话，静态令牌是契约内的合法
/// 引导 Bearer；不回退则 SRP 凭证永远无法创建（死锁）。仅用于引导型
/// 命令（`account_srp_register_with_password`）；常规 Bearer 命令仍走
/// [`account_api_with_bearer_for`] 保持"账号会话 fail-closed"语义。
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

/// 账号域绑定写入（显式动作）：`Some` = 绑定（向导注册/登录成功后由
/// 前端调用），`None` = 解绑（退出账号时随 revoke_session 一起）。
/// 非敏感标识存 vault JSON（`WorkspaceSettings.account`）；令牌真值在
/// OS keyring（ACCOUNT_SERVICE），不经此命令。读取走
/// `get_workspace_settings`（同一条 settings 直出）。
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

/// 公开注册新账号（无需认证）。
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

/// passkey 注册选项（公开端点）。响应是服务器签发的裸 WebAuthn
/// creation options（120s 一次性挑战），原样透传。
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

/// passkey 注册完成（公开端点）。提交认证器 attestation，服务器做 RP 侧
/// 完整验证后存公钥材料。
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

/// passkey 登录选项（公开端点，登录仪式第一步）。按凭据 id 换取服务器
/// 挑战（120s 一次性），断言时消费。
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

/// SRP 凭据登记（Bearer 端点）。账号内设备的 SRP salt+verifier 登记
/// （密码登录的兜底凭据）。
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

/// SRP 挑战请求（公开端点，登录步骤）。发起账号 SRP 登录握手。
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

/// SRP 验证完成（公开端点，登录步骤）。完成握手，返回 15 分钟 SRP 登录
/// 令牌；本命令除透传外，把令牌写入 keyring 作为账号 bearer 的解析源
/// （后续 Bearer 门禁命令免前端回传）。
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

/// 向导式 SRP 凭证注册（引导命令）：口令在 core 推导成 salt/verifier
/// 并注册到账号，wire 值与口令都不经前端周转。Bearer 走
/// [`account_api_with_bearer_or_bootstrap_for`]（账号会话 → 静态服务器
/// 令牌回退）；裸 wire 的 [`account_srp_register`] 保持账号会话
/// fail-closed 不变，两条路的 Bearer 语义不同。
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

/// 向导式 SRP 登录：challenge/verify 两跳与 M2 核验全部在 core 编排
/// （服务器证明不过不交付令牌），15 分钟令牌直写 `account_token_store`
/// ——响应不含令牌本体，渲染层只见有效期与会话指纹。后续兑换 24h
/// 会话走 [`account_create_session`]（带 srp_token 证据）。
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

/// 兑换 24h 账号会话（编排命令）：keyring 里的 15 分钟 SRP 令牌同时作
/// Bearer 与 body 证据（服务器 sessions 端点是 Bearer + 恰好一种证据的
/// 双闸，SRP 路径下两者是同一枚令牌），换得的 24h 会话令牌直写 keyring
/// 覆盖短期令牌。令牌本体全程不过 IPC；passkey 断言证据路径仍走裸
/// [`account_create_session`]（断言由渲染层的 WebAuthn 仪式产出）。
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

/// 退出账号（编排命令）：吊销 keyring 里的当前令牌（15 分钟短期令牌与
/// 24h 会话都在服务器 `account_sessions` 表里，同一 DELETE 自吊销）并
/// 清除本机 keyring。服务器吊销尽力而为（过期/不存在不拦退出），本机
/// 清理是硬性语义——keyring 清除失败才报错。绑定（settings.account）
/// 由前端随成功响应一并清除。
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
        // 本机已无令牌 = 已退出；幂等成功（revoked_on_server=false）
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

/// 生成恢复码（Bearer 端点）。每次调用生成新一组（8 个），旧未用的作废。
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

/// 验证恢复码（公开端点）。一次性消费，验证成功后标记为已用。
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

/// 为账号授权设备（Bearer 端点）。把已登记的 sync 设备（按 device_id +
/// 公钥比对）关联到账号。
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

/// 获取账号下的已授权设备列表（Bearer 端点）。
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

/// 吊销账号下的设备（Bearer 端点）。204 无体成功。
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

/// 创建账号会话（Bearer 端点）。凭恰好一种登录证据（SRP 15 分钟令牌或
/// passkey 断言）兑换 24h 账号会话令牌；成功后令牌覆盖 keyring 的账号
/// bearer（登出/续期语义：最后一次登录的会话为本机有效会话）。
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

/// 吊销账号会话（Bearer 端点）。登出该会话令牌；若吊销的正是本机
/// keyring 里存的有效会话，一并清除（自吊销 = 本机退出账号登录）。
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
