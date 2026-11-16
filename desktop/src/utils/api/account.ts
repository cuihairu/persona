import { invoke } from './invoke';

import type {
  ApiResponse,
  WorkspaceSettings,
  AccountRegistrationResponse,
  AccountSrpRegisterResponse,
  AccountSrpChallengeResponse,
  AccountSrpVerifyResponse,
  AccountPasskeyCreationOptions,
  AccountPasskeyLoginOptions,
  AccountSessionEvidence,
  AccountDevicesList,
  AccountRecoveryCodes,
  AccountSessionInfo,
} from '@/types';

export const accountApi = {

  // -------------------------------------------------------------------------
  // 账号体系（M2 脚手架：对齐 server /api/v1/accounts/* 契约的代理 seam，
  // tauri 代理命令层随 M2 账号 UI 批次落地；账号/同步功能默认关闭）
  // -------------------------------------------------------------------------

  /** 公开注册新账号（无需认证）。成功返回 account_id 与 basic info。 */
  async accountRegister(
    request: { username: string; display_name?: string }
  ): Promise<ApiResponse<AccountRegistrationResponse>> {
    return invoke('account_register', { request });
  },


  /** passkey 注册选项（公开端点）。服务器签发带挑战的 WebAuthn creation
   * options（120s 一次性挑战，register 时严格比对）。 */
  async accountPasskeyCreateOptions(
    account_id: string,
    request: {
      rp_id: string;
      rp_name?: string;
      user_handle: string;
      user_name?: string;
      user_display_name?: string;
    }
  ): Promise<ApiResponse<AccountPasskeyCreationOptions>> {
    return invoke('account_passkey_create_options', { account_id, request });
  },


  /** passkey 注册完成（公开端点）。提交认证器 attestation，服务器做 RP 侧
   * 完整验证后存入公钥材料。 */
  async accountPasskeyRegister(
    account_id: string,
    request: {
      attestation_response: { credentialId: string; attestationObject: string };
      client_data_json: string;
      origin: string;
    }
  ): Promise<ApiResponse<{ passkey_id: string }>> {
    return invoke('account_passkey_register', { account_id, request });
  },


  /** passkey 登录选项（公开端点，登录仪式第一步）。按凭据 id 换取服务器
   * 挑战（120s 一次性），断言时消费。 */
  async accountPasskeyLoginOptions(
    account_id: string,
    request: { credential_id: string }
  ): Promise<ApiResponse<AccountPasskeyLoginOptions>> {
    return invoke('account_passkey_login_options', { account_id, request });
  },


  /** SRP 凭据注册（需要 Bearer）。账号内设备的 SRP salt+verifier 登记。 */
  async accountSrpRegister(
    account_id: string,
    request: { device_name: string; salt: string; verifier: string }
  ): Promise<ApiResponse<AccountSrpRegisterResponse>> {
    return invoke('account_srp_register', { account_id, request });
  },


  /** SRP 挑战请求（公开端点，登录步骤）。发起账号 SRP 登录握手。 */
  async accountSrpChallenge(
    account_id: string,
    request: { device_name: string; client_public: string }
  ): Promise<ApiResponse<AccountSrpChallengeResponse>> {
    return invoke('account_srp_challenge', { account_id, request });
  },


  /** SRP 验证完成（公开端点，登录步骤）。完成握手，返回 15 分钟 SRP
   * 登录令牌（可作账号路由 Bearer，或兑换 24h 会话）。 */
  async accountSrpVerify(
    account_id: string,
    request: { session_id: string; client_proof: string }
  ): Promise<ApiResponse<AccountSrpVerifyResponse>> {
    return invoke('account_srp_verify', { account_id, request });
  },


  /** 向导式 SRP 凭据注册：口令在 core 推导 salt+verifier 并注册（引导
   * Bearer：账号会话缺失时回退静态服务器令牌）。前端不接触 wire 值。 */
  async accountSrpRegisterWithPassword(
    account_id: string,
    request: { device_name: string; password: string }
  ): Promise<ApiResponse<{ device_name: string }>> {
    return invoke('account_srp_register_with_password', { account_id, request });
  },


  /** 向导式 SRP 登录：challenge/verify 与 M2 核验在 core 编排，15 分钟
   * 令牌直写 keyring（响应不含令牌本体）。 */
  async accountSrpLogin(
    account_id: string,
    request: { device_name: string; password: string }
  ): Promise<ApiResponse<{ expires_in_secs: number; session_key_fingerprint: string }>> {
    return invoke('account_srp_login', { account_id, request });
  },


  /** 账号域绑定写入：绑定（向导成功后）/ 解绑（退出账号，传 null）。
   * 读取走 getWorkspaceSettings（settings.account 直出）。 */
  async accountSetBinding(
    binding: { account_id: string; username: string; device_name?: string | null } | null
  ): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_account_binding', { binding });
  },


  /** 兑换 24h 会话（编排命令）：keyring 的 15 分钟令牌同时作 Bearer 与
   * 证据，24h 会话直写 keyring。响应不含令牌本体。 */
  async accountExchangeSession(
    account_id: string
  ): Promise<ApiResponse<{ expires_in_secs: number }>> {
    return invoke('account_exchange_session', { account_id });
  },


  /** 退出账号（编排命令）：自吊销 keyring 令牌（服务器尽力而为）并清
   * keyring。revoked_on_server=false = 服务器侧无可吊销项。 */
  async accountSignOut(account_id: string): Promise<ApiResponse<{ revoked_on_server: boolean }>> {
    return invoke('account_sign_out', { account_id });
  },


  /** 生成恢复码（需要 Bearer）。每次调用生成新一组（8 个），旧未用的作废。 */
  async accountGenerateRecoveryCodes(
    account_id: string
  ): Promise<ApiResponse<AccountRecoveryCodes>> {
    return invoke('account_generate_recovery_codes', { account_id });
  },


  /** 验证恢复码（公开端点）。一次性消费，验证成功后标记为已用。 */
  async accountVerifyRecoveryCode(
    account_id: string,
    request: { code: string }
  ): Promise<ApiResponse<{ success: boolean }>> {
    return invoke('account_verify_recovery_code', { account_id, request });
  },


  /** 为账号授权设备（需要 Bearer）。把已登记的 sync 设备（按 device_id +
   * 公钥比对）关联到账号。 */
  async accountAuthorizeDevice(
    account_id: string,
    request: { device_id: string; public_key: string }
  ): Promise<ApiResponse<{ id: string; status: string }>> {
    return invoke('account_authorize_device', { account_id, request });
  },


  /** 获取账号下的已授权设备列表（需要 Bearer）。 */
  async accountListDevices(
    account_id: string
  ): Promise<ApiResponse<AccountDevicesList>> {
    return invoke('account_list_devices', { account_id });
  },


  /** 吊销账号下的设备（需要 Bearer）。 */
  async accountRevokeDevice(
    account_id: string,
    device_id: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('account_revoke_device', { account_id, device_id });
  },


  /** 创建账号会话（需要 Bearer）。凭恰好一种登录证据（SRP 15 分钟令牌或
   * passkey 断言）兑换 24h 账号会话令牌。 */
  async accountCreateSession(
    account_id: string,
    request: AccountSessionEvidence
  ): Promise<ApiResponse<AccountSessionInfo>> {
    return invoke('account_create_session', { account_id, request });
  },


  /** 吊销账号会话（需要 Bearer）。登出该会话令牌。 */
  async accountRevokeSession(
    account_id: string,
    session_token: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('account_revoke_session', { account_id, session_token });
  },
};
