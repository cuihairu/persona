//! 账号域 wire 类型：注册、passkey、SRP、设备列表与生物识别。

use serde::{Deserialize, Serialize};

/// account_register 请求（公开注册，无需认证）。
#[derive(Debug, Deserialize)]
pub struct AccountRegisterRequest {
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRegistrationResponse {
    pub account_id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// account_passkey_create_options 请求。响应是裸 WebAuthn creation
/// options JSON（服务器未类型化的 json! 对象），命令层原样透传
/// `serde_json::Value`（= 前端 AccountPasskeyCreationOptions）。
#[derive(Debug, Deserialize)]
pub struct AccountPasskeyCreateOptionsRequest {
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: Option<String>,
    pub user_handle: String,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountPasskeyRegisterRequest {
    /// 认证器 attestation 响应（{credentialId, attestationObject}，均
    /// base64url 串），服务器按不透明 Value 接收。
    pub attestation_response: serde_json::Value,
    pub client_data_json: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPasskeyRegisterResponse {
    pub passkey_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountPasskeyLoginOptionsRequest {
    pub credential_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPasskeyLoginOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpRegisterRequest {
    pub device_name: String,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpRegisterResponse {
    pub device_name: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpChallengeRequest {
    pub device_name: String,
    pub client_public: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpChallengeResponse {
    pub session_id: String,
    pub salt: String,
    pub server_public: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountSrpVerifyRequest {
    pub session_id: String,
    pub client_proof: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpVerifyResponse {
    pub server_proof: String,
    /// 15 分钟账号登录令牌：命令层除透传外，还会写入
    /// `account_token_store`（Bearer 门禁命令的解析源）。
    pub token: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRecoveryCodes {
    pub codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountVerifyRecoveryCodeRequest {
    pub code: String,
}

/// verify_recovery_code 响应（= 前端内联 `{ success: boolean }`；core 侧
/// 同形 wire 类型只 Deserialize，不进命令返回位）。
#[derive(Debug, Clone, Serialize)]
pub struct AccountVerifyRecoveryCodeResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct AccountAuthorizeDeviceRequest {
    /// sync_devices.id
    pub device_id: String,
    /// base64，32 字节 X25519
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountAuthorizeDeviceResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountDeviceInfo {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountDevicesList {
    pub devices: Vec<AccountDeviceInfo>,
}

/// sessions 端点的 passkey 断言证据（字段全为 base64url 编码）。
#[derive(Debug, Deserialize)]
pub struct AccountPasskeyAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub origin: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// sessions 端点证据：SRP 15 分钟令牌或 passkey 断言，恰好一种（服务器
/// 两者同给/都缺 = 422）。serde 默认忽略未知字段，两种形状都收。
#[derive(Debug, Default, Deserialize)]
pub struct AccountSessionEvidence {
    #[serde(default)]
    pub srp_token: Option<String>,
    #[serde(default)]
    pub passkey_assertion: Option<AccountPasskeyAssertion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountSessionInfo {
    pub session_token: String,
    pub expires_in_secs: u64,
}

/// 向导式 SRP 凭证注册（口令进、wire 值不出）：salt/verifier 由 core
/// 推导，前端只交设备名与口令。
#[derive(Debug, Deserialize)]
pub struct AccountSrpRegisterWithPasswordRequest {
    pub device_name: String,
    pub password: String,
}

/// 向导式 SRP 登录请求：challenge/verify 两跳由 core 编排，M2 核验
/// 在 core 完成。
#[derive(Debug, Deserialize)]
pub struct AccountSrpLoginRequest {
    pub device_name: String,
    pub password: String,
}

/// `account_srp_login` 响应。**不含令牌**：15 分钟令牌由命令层直写
/// `account_token_store`（Bearer 解析源），不随响应下发渲染层；指纹
/// 供诊断/会话绑定展示。
#[derive(Debug, Clone, Serialize)]
pub struct AccountSrpLoginResponse {
    pub expires_in_secs: u64,
    pub session_key_fingerprint: String,
}

/// `account_exchange_session` 响应。**不含会话令牌**：24h 会话由命令层
/// 直写 keyring 覆盖 15 分钟短期令牌，渲染层只见有效期。
#[derive(Debug, Clone, Serialize)]
pub struct AccountSessionExchangeResponse {
    pub expires_in_secs: u64,
}

/// `account_sign_out` 响应：本机令牌必清（否则返回错误）；服务器侧吊销
/// 是尽力而为——令牌已过期/已不存在时照样算退出成功（false 仅说明
/// 服务器那边无可吊销项），本地状态永不因远端 4xx 卡死。
#[derive(Debug, Clone, Serialize)]
pub struct AccountSignOutResponse {
    pub revoked_on_server: bool,
}

/// biometric unlock 状态查询响应。`available` = OS 认证栈 + keyring 均
/// 可达（fail-closed：任一不可用即 false，前端隐藏指纹入口）；
/// `enabled` = 本 vault 的 keyring 托管条目存在——单一真相源，
/// workspace settings 不存开关（vault 文件拷机后 keyring 无条目，
/// 功能自然回到未启用）。
#[derive(Debug, Clone, Serialize)]
pub struct BiometricStatusResponse {
    pub available: bool,
    pub enabled: bool,
    /// 平台名（"touch-id" / "windows-hello" / "linux-polkit" / "unsupported"）
    pub platform: String,
    /// 包裹档位（biometric_wrap 模块三档，设计文档 §1）：
    /// "hardware-bound"（本 vault 的包裹 blob 存在且解链走硬件）/
    /// "os-gate"（门禁层密码托管）/ "unsupported"（平台无硬件绑定层）
    pub wrap_tier: String,
}

/// 启用 biometric unlock：主密码经 OS 认证弹框确认后托管（硬件绑定档
/// 走密钥包裹 blob，门禁档走 keyring 密码托管——分流见 biometric_enable）
#[derive(Debug, Deserialize)]
pub struct BiometricEnableRequest {
    pub master_password: String,
}

/// biometric 解锁：参数 db_path 在前端勾选自定义库路径时传入
/// （默认 None = 本会话路径或默认路径）
#[derive(Debug, Deserialize)]
pub struct BiometricUnlockRequest {
    pub db_path: Option<String>,
}

/// Secure Enclave spike 探针单步输出（`biometric_wrap_spike` 命令返回；
/// 设计文档 §5.2）。真机跑完把 `detail` 里的 OSStatus 贴回设计文档。
#[derive(Debug, Clone, Serialize)]
pub struct BiometricSpikeStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}
