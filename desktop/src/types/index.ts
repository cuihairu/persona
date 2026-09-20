/**
 * 后端错误码（与 desktop/src-tauri/src/error.rs 的 map_persona_error 对应）。
 * REAUTH_REQUIRED：敏感操作需要重新认证 → 前端弹 ReauthModal。
 * SERVICE_LOCKED：服务已锁定 → 前端回到解锁屏。
 * PASSWORD_CHANGE_REQUIRED：主密码按策略需轮换 → 前端弹强制改密弹窗。
 */
export type ApiErrorCode =
  | 'REAUTH_REQUIRED'
  | 'SERVICE_LOCKED'
  | 'PASSWORD_CHANGE_REQUIRED';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  error_code?: ApiErrorCode;
}

/** persona://auto-lock 事件的载荷（与 Rust 侧 SerializableAutoLockEvent 对应） */
export type AutoLockEventPayload =
  | { type: 'lock_pending'; session_id: string; seconds_remaining: number }
  | { type: 'locked'; session_id: string; reason: string }
  | { type: 'unlocked'; session_id: string }
  | { type: 'activity'; session_id: string };

/** persona://ssh-approval 事件的载荷（与 Rust 侧 SshApprovalRequest 对应） */
export interface SshApprovalRequest {
  request_id: string;
  key_id: string;
  fingerprint: string;
  operation: string;
  peer: string | null;
  timestamp: string;
}

/** persona://passkey-approval 事件的负载（与 Rust 侧 PasskeyApprovalRequest 对应） */
export interface PasskeyApprovalRequest {
  request_id: string;
  /** bridge wire 的操作名："passkey_create" | "passkey_assert" */
  operation: string;
  /** 人工核对的 relying party（assert 时为 null：rp 存在 vault item 上） */
  rp_id: string | null;
  /** 发起请求的完整页面 origin */
  origin: string;
  /** create 时的账号名 */
  user_name: string | null;
  /** assert 时对应 vault item 的 UUID */
  item_id: string | null;
}

/** Auto-lock 配置（对应 Rust AutoLockConfigRequest；0 = 禁用） */
export interface AutoLockConfigRequest {
  inactivity_timeout_secs: number;
  absolute_timeout_secs?: number;
  require_reauth_sensitive?: boolean;
}

export interface AutoLockStatus {
  is_unlocked: boolean;
  session_locked: boolean;
  needs_reauth: boolean;
  inactivity_timeout_secs: number;
}

/** 高级功能开关（对应 Rust FeatureFlags；1Password 式默认全关、设置页 opt-in） */
export interface FeatureFlags {
  /** SSH agent（浏览器/终端经 socket 取钥签名） */
  ssh_agent: boolean;
  /** 钱包面板 */
  wallet: boolean;
  /** Passkey 管理与审批服务端 */
  passkeys: boolean;
  /** 站点 favicon 按需抓取与展示（唯一外联入口 = 详情面板 Fetch icon 按钮） */
  fetch_favicons: boolean;
}

/** 同步服务器（persona-server Events API）客户端配置（对应 Rust SyncConfig） */
export interface SyncConfig {
  enabled: boolean;
  server_url: string;
  /**
   * 后端恒返回空串——token 真值存 OS keyring，不经 IPC 回读。
   * 提交空串 = 保留 keyring 既有令牌（前端不回填，避免常驻内存）。
   */
  server_token: string;
}

/** workspace 设置全量（对应 Rust WorkspaceSettings；由 settings 命令返回） */
export interface WorkspaceSettings {
  encryption_enabled: boolean;
  auto_backup_hours: number;
  backup_retention_count: number;
  session_timeout_seconds: number;
  require_confirmation: boolean;
  default_identity_type: string;
  features: FeatureFlags;
  /** 主密码有效期（天）；null = 不过期（默认，旧 JSON 缺键时为 null） */
  password_expiry_days: number | null;
  /** 可选同步服务器配置（旧 JSON 缺键时为 null） */
  sync: SyncConfig | null;
}

/** 已缓存的站点图标（对应 Rust SerializableFavicon；data 为 base64 图像字节） */
export interface FaviconData {
  host: string;
  mime_type: string;
  data: string;
}

/** 审计日志条目（只读视图，不含敏感负载） */
export interface AuditLogEntry {
  id: string;
  user_id?: string;
  identity_id?: string;
  credential_id?: string;
  session_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  success: boolean;
  error_message?: string;
  metadata: Record<string, string>;
  timestamp: string;
}

/** 审计查询过滤（None 字段 = 不过滤） */
export interface AuditQueryRequest {
  user_id?: string;
  identity_id?: string;
  action?: string;
  failures_only?: boolean;
  security_sensitive_only?: boolean;
  time_range?: [string, string];
  limit?: number;
}

export interface AuditStatistics {
  total_logs: number;
  failed_operations: number;
  recent_login_attempts: number;
  active_users_last_week: number;
}

// -------------------------------------------------------------------------
// Watchtower 健康扫描（报告只含元数据，永不含密文）
// -------------------------------------------------------------------------

export type HealthSeverity = 'low' | 'medium' | 'high';

/** 问题类型（serde tag = "type"，snake_case 变体名） */
export interface HealthIssueKindPayload {
  type:
    | 'weak_password'
    | 'reused_password'
    | 'breached_password'
    | 'expired'
    | 'expiring_soon'
    | 'stale_unchanged';
  /** weak_password：zxcvbn 分数 */
  score?: number;
  /** reused_password：共用同一明文密码的凭据数 */
  group_size?: number;
  /** breached_password：在泄露库中出现的次数 */
  count?: number;
  /** expiring_soon / stale_unchanged：距过期/未更新天数 */
  days?: number;
}

export interface HealthIssue {
  credential_id: string;
  credential_name: string;
  credential_type: string;
  severity: HealthSeverity;
  detail: string;
  /** serde(flatten) 的问题类型负载 */
  type: HealthIssueKindPayload['type'];
  score?: number;
  group_size?: number;
  count?: number;
  days?: number;
}

export interface HealthReport {
  scanned_at: string;
  total_credentials: number;
  issues: HealthIssue[];
  /** 严重度 → 数量（"high"/"medium"/"low"） */
  counts: Record<string, number>;
}

export interface HealthScanRequest {
  /** zxcvbn 分数阈值（0-4），低于该值判弱；缺省用 core 默认值 */
  min_password_score?: number;
  /** 过期警告窗口（天） */
  expiry_warning_days?: number;
  /** 超过该天数未更新判陈旧 */
  stale_after_days?: number;
  /** 查询 HIBP 泄露库（k-anonymity，仅发送哈希前 5 字符） */
  check_breaches?: boolean;
}

/** Passkey 列表项（永不含私钥字段） */
export interface Passkey {
  id: string;
  identity_id: string;
  rp_id: string;
  rp_name?: string;
  user_handle_b64: string;
  user_name?: string;
  user_display_name?: string;
  credential_id_b64: string;
  uv_initialized: boolean;
  export_allowed: boolean;
  created_at: string;
  last_used_at?: string;
}

export interface CreatePasskeyRequest {
  identity_id: string;
  rp_id: string;
  origin: string;
  /** base64(UTF-8 JSON) 的 clientDataJSON */
  client_data_json_b64: string;
  user_handle_b64?: string;
  user_name?: string;
  user_display_name?: string;
  user_verification: boolean;
}

export interface PasskeyCreationResponse {
  passkey: Passkey;
  /** base64 的 `none` 格式 attestation object */
  attestation_object_b64: string;
}

/** 敏感字段名（对应 Rust reveal_credential_secret 的 field 集合） */
export type SecretField =
  | 'password'
  | 'security_questions'
  | 'ssh_private_key'
  | 'ssh_passphrase'
  | 'api_key'
  | 'api_secret'
  | 'token'
  | 'wallet_private_key'
  | 'wallet_mnemonic'
  | 'raw_data';

export interface SecretReveal {
  field: SecretField;
  value: string;
}

export interface IdentityExport {
  exported_at: string;
  data: { identity: Identity; credentials: Credential[] };
}

// ---------------------------------------------------------------------------
// 钱包交易（与 Rust TransactionRequest/SignedTransaction 的 serde 输出对应）
// ---------------------------------------------------------------------------

/** 待签交易请求（由 wallet_create_transaction 返回） */
export interface WalletTransaction {
  id: string;
  wallet_id: string;
  network: string;
  from_address: string;
  to_address: string;
  /** 最小单位字符串（wei / satoshi / lamport） */
  amount: string;
  fee: string;
  gas_price?: string;
  gas_limit?: number;
  nonce?: number;
  memo?: string;
  required_signatures: number;
  created_at: string;
  expires_at?: string;
  metadata: Record<string, string>;
}

export interface WalletSignature {
  [key: string]: unknown;
}

/** 已签名交易（由 wallet_sign_transaction 返回） */
export interface WalletSignedTransaction {
  id: string;
  request: WalletTransaction;
  signatures: WalletSignature[];
  raw_signed_transaction: number[];
  transaction_hash: string;
  signed_at: string;
  broadcast_status: string;
}

export interface CreateTransactionRequest {
  wallet_id: string;
  to_address: string;
  amount: string;
  fee: string;
  gas_price?: string;
  gas_limit?: number;
  nonce?: number;
  memo?: string;
  expires_in_minutes?: number;
}

export interface SignTransactionRequest {
  transaction_id: string;
  password: string;
}

/** persona://ssh-approval 事件负载：待审批的 SSH 签名请求 */
export interface SshApprovalRequest {
  request_id: string;
  /** 凭据 UUID（非敏感） */
  key_id: string;
  /** 公钥指纹（SHA256 前 8 字节，用于人工核对） */
  fingerprint: string;
  /** 操作名（当前恒为 "sign"） */
  operation: string;
  /** 目标主机（未知时为 null） */
  peer: string | null;
  /** 触发原因（策略说明） */
  reason: string;
}

export interface Identity {
  id: string;
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
  ssh_key?: string;
  gpg_key?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  is_active: boolean;
}

export interface Credential {
  id: string;
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url?: string;
  username?: string;
  notes?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  last_accessed?: string;
  is_active: boolean;
  is_favorite: boolean;
}

export interface CredentialData {
  credential_type: string;
  data: any;
}

/** 字段级 diff（对应 Rust SerializableFieldChange；快照 JSON 不回传） */
export interface FieldChangeEntry {
  field: string;
  old_value: string;
  new_value: string;
}

/** 凭据历史行（对应 Rust SerializableChangeHistory；新版本在前） */
export interface CredentialHistoryEntry {
  id: string;
  entity_id: string;
  change_type: 'created' | 'updated' | 'deleted' | 'restored' | 'archived' | 'activated' | 'deactivated';
  version: number;
  timestamp: string;
  changes: FieldChangeEntry[];
}

/** 附件元数据（对应 Rust SerializableAttachment；blob 内容永不整段回传） */
export interface AttachmentEntry {
  id: string;
  credential_id: string;
  filename: string;
  mime_type: string;
  size: number;
  is_encrypted: boolean;
  content_hash: string;
  created_at: string;
}

export interface CreateIdentityRequest {
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
}

export interface UpdateIdentityRequest {
  id: string;
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
  tags?: string[];
}

export interface CreateCredentialRequest {
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url?: string;
  username?: string;
  notes?: string;
  tags?: string[];
  credential_data: CredentialDataRequest;
}

export type CredentialDataRequest =
  | { type: 'Password'; password: string; email?: string; security_questions: SecurityQuestion[] }
  | { type: 'CryptoWallet'; wallet_type: string; mnemonic_phrase?: string; private_key?: string; public_key: string; address: string; network: string }
  | { type: 'SshKey'; private_key: string; public_key: string; key_type: string; passphrase?: string }
  | { type: 'ApiKey'; api_key: string; api_secret?: string; token?: string; permissions: string[]; expires_at?: string }
  | { type: 'TwoFactor'; secret_key: string; issuer: string; account_name: string; algorithm: string; digits: number; period: number }
  | { type: 'GameToken'; provider: string; secret_key: string; issuer: string; account_name: string; url?: string }
  | { type: 'SecureNote'; note: string }
  | { type: 'Raw'; data: number[] };

export interface SecurityQuestion {
  question: string;
  answer: string;
}

export interface SshAgentStatus {
  running: boolean;
  socket_path?: string;
  pid?: number;
  key_count?: number;
  state_dir: string;
}

export interface SshAgentKey {
  id: string;
  identity_id: string;
  identity_name: string;
  name: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Statistics {
  total_identities: number;
  total_credentials: number;
  active_credentials: number;
  favorite_credentials: number;
  credential_types: Record<string, number>;
  security_levels: Record<string, number>;
}

export interface TotpCodeResponse {
  code: string;
  remaining_seconds: number;
  period: number;
  digits: number;
  algorithm: string;
  issuer: string;
  account_name: string;
}

export interface WalletSummary {
  id: string;
  name: string;
  network: string;
  wallet_type: string;
  balance: string;
  address_count: number;
  watch_only: boolean;
  security_level: string;
  created_at: string;
  updated_at: string;
}

export interface WalletAddress {
  address: string;
  address_type: string;
  index: number;
  used: boolean;
  balance: string;
  derivation_path?: string | null;
}

export interface WalletListResponse {
  wallets: WalletSummary[];
}

export interface WalletAddressesResponse {
  addresses: WalletAddress[];
}

export interface WalletGenerateRequest {
  name: string;
  network: string;
  wallet_type: 'hd';
  password: string;
  address_count?: number;
}

export interface WalletGenerateResponse {
  wallet_id: string;
  name: string;
  network: string;
  mnemonic: string;
  first_address: string;
}

export interface WalletImportRequest {
  name: string;
  network: string;
  import_type: 'mnemonic' | 'private_key' | 'wif';
  data: string;
  password: string;
  address_count?: number;
}

export interface WalletExportRequest {
  wallet_id: string;
  format: 'json' | 'mnemonic' | 'xpub' | 'private_key' | 'wif';
  include_private: boolean;
  password?: string;
}

export type IdentityType = 'Personal' | 'Work' | 'Social' | 'Financial' | 'Gaming';
export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor' | 'GameToken' | 'SecureNote';
export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** 主题偏好三档；'system' 跟随 prefers-color-scheme */
export type ThemePreference = 'system' | 'light' | 'dark';

/** 侧栏分类树的单选筛选态（默认 { kind: 'all' }；不做 localStorage 持久化） */
export type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'type'; value: string }
  | { kind: 'tag'; value: string };

/**
 * 待注入的凭据选中项（全局搜索跨身份跳转用）：QuickSearch 写入，
 * CredentialList 在目标身份的凭据加载完成后消费并清除。
 */
export type PendingCredentialSelection = { identityId: string; credentialId: string };

export interface InitRequest {
  master_password: string;
  db_path?: string;
}
