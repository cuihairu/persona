/** 账号域：绑定、SRP 注册/质询、passkey 选项、会话与设备清单、旅行模式、Connect 令牌。 */

/** 账号域绑定（core `AccountBinding` 镜像）。非敏感标识；令牌真值在
 * OS keyring，不经前端。 */
export interface AccountBinding {
  account_id: string;
  username: string;
  /** 本机 SRP 凭证的设备名 */
  device_name?: string | null;
}

/** 旅行模式状态（读取免解锁免 travel 口令） */
export interface TravelStatus {
  /** settings 里的 travel_mode 旗标 */
  active: boolean;
  /** 进入时刻（RFC3339；enter 写入、exit 清空） */
  entered_at: string | null;
  /** `<db dir>/travel.persenc` 是否存在 */
  sidecar_exists: boolean;
  /** active && !sidecar_exists：数据容器没了——数据已丢失 */
  inconsistent: boolean;
}

/** enter/exit 完成后的数量报告 */
export interface TravelCounts {
  identities: number;
  credentials: number;
  attachments: number;
  passkeys: number;
  wallets: number;
  history_rows: number;
  files: number;
}

/** Connect listener 运行状态（设置页渲染 + 自动化开关判定） */
export interface ConnectServerStatus {
  running: boolean;
  /** listener 实际端口（未运行 = null；端口 0 = OS 分配后的真实值） */
  port: number | null;
}

/** token 授权范围（三维：身份列表空 = 全部、类型枚举、动词；read 起步唯一合法值） */
export interface ConnectTokenScope {
  identities: string[];
  /** snake_case 类型词汇表（password/api_key/totp/…；passkey/wallet/ssh 恒不可授权） */
  item_types: string[];
  verbs: string[];
}

/** token 管理列表条目（哈希不出库；只展示指纹） */
export interface ConnectTokenView {
  id: string;
  label: string;
  /** SHA-256 前 8 字节十六进制，供人工核对 */
  fingerprint: string;
  scope: ConnectTokenScope;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** 创建成功响应：明文 token 只此一次，关闭弹窗后无法再次查看 */
export interface ConnectTokenCreatedView {
  token: string;
  info: ConnectTokenView;
}

/* account system (M2) */
export interface AccountRegistrationResponse {
  account_id: string;
  username: string;
  display_name?: string;
}

export interface AccountSrpRegisterResponse {
  device_name: string;
}

export interface AccountSrpChallengeResponse {
  session_id: string;
  salt: string;
  server_public: string;
}

export interface AccountSrpVerifyResponse {
  server_proof: string;
  token: string;
  expires_in_secs: number;
}

/** passkeys/create-options 响应（服务器签发挑战的 WebAuthn creation
 * options；与本地密码库 passkey 的类型分开——RP 侧账号域）。 */
export interface AccountPasskeyCreationOptions {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: string; alg: number }[];
  authenticatorSelection: {
    authenticatorAttachment?: string;
    userVerification?: string;
    residentKey?: string;
  };
  timeout: number;
  attestation: string;
}

/** passkeys/login-options 响应：登录仪式第一步拿到的服务器挑战。 */
export interface AccountPasskeyLoginOptions {
  challenge: string;
  rp_id: string;
}

/** sessions 端点的 passkey 断言证据（字段全为 base64url 编码）。 */
export interface AccountPasskeyAssertion {
  credential_id: string;
  client_data_json: string;
  origin: string;
  authenticator_data: string;
  signature: string;
}

/** sessions 端点证据：SRP 15 分钟令牌或 passkey 断言，恰好一种。 */
export type AccountSessionEvidence =
  | { srp_token: string }
  | { passkey_assertion: AccountPasskeyAssertion };

export interface AccountDeviceInfo {
  id: string;
  device_id: string;
  device_name: string;
  public_key: string;
  status: string;
}

export interface AccountDevicesList {
  devices: AccountDeviceInfo[];
}

export interface AccountRecoveryCodes {
  codes: string[];
}

export interface AccountSessionInfo {
  session_token: string;
  expires_in_secs: number;
}

/* end account system */
