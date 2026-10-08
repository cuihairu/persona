/**
 * 后端错误码（与 desktop/src-tauri/src/error.rs 的 map_persona_error 对应）。
 * REAUTH_REQUIRED：敏感操作需要重新认证 → 前端弹 ReauthModal。
 * SERVICE_LOCKED：服务已锁定 → 前端回到解锁屏。
 * PASSWORD_CHANGE_REQUIRED：主密码按策略需轮换 → 前端弹强制改密弹窗。
 * BIOMETRIC_RESET：biometric 托管条目不存在或已失效自删 → 解锁屏隐藏
 * 指纹按钮、提示改用主密码登录。
 * BIOMETRIC_CANCELLED：用户在生物识别弹框点了取消 → 静默回解锁屏，指纹
 * 按钮保留，不弹错误提示（设计文档 §3.4）。
 * TRAVEL_MODE_ACTIVE：旅行模式进行中，改密等不兼容操作被拒 → 提示先退出。
 * CONCURRENT_CONFLICT：并发互斥操作冲突（组密钥轮换的 epoch 乐观锁未命中，
 * 另一台设备已抢先轮换）→ 提示同步状态已更新，请重试轮换。
 * ITEM_PASSWORD_REQUIRED / ITEM_PASSWORD_WRONG：钱包条目独立密码守卫
 * （reveal 种子材料缺参/不匹配）→ RevealSecretButton 内联追加密码输入。
 */
export type ApiErrorCode =
  | 'REAUTH_REQUIRED'
  | 'SERVICE_LOCKED'
  | 'PASSWORD_CHANGE_REQUIRED'
  | 'BIOMETRIC_RESET'
  | 'BIOMETRIC_CANCELLED'
  | 'TRAVEL_MODE_ACTIVE'
  | 'CONCURRENT_CONFLICT'
  | 'ITEM_PASSWORD_REQUIRED'
  | 'ITEM_PASSWORD_WRONG';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  error_code?: ApiErrorCode;
}

/** biometric unlock 状态（对应 Rust BiometricStatusResponse；enabled 只表示
 * "本 vault 配置过生物解锁"这一位元数据，托管的主密码真值永不出 keyring；
 * wrap_tier 为后端三档包裹档位："hardware-bound" / "os-gate" / "unsupported"） */
export interface BiometricStatus {
  available: boolean;
  enabled: boolean;
  platform: string;
  wrap_tier: string;
}

/** persona://auto-lock 事件的载荷（与 Rust 侧 SerializableAutoLockEvent 对应） */
export type AutoLockEventPayload =
  | { type: 'lock_pending'; session_id: string; seconds_remaining: number }
  | { type: 'locked'; session_id: string; reason: string }
  | { type: 'unlocked'; session_id: string }
  | { type: 'activity'; session_id: string };

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

/** E2EE sync 设备管理（对应 Rust SyncDeviceStatus / SyncJoinOutcome / SyncDeviceView） */
export interface SyncDeviceStatus {
  joined: boolean;
  /** keyring 有记录但解析失败——UI 引导重新 join */
  corrupted: boolean;
  device_id: string | null;
  device_name: string | null;
}

export interface SyncJoinOutcome {
  device_id: string;
  device_name: string;
  /** 已登记但尚未被授权（需在另一台已授权设备上授权） */
  pending: boolean;
}

export interface SyncDeviceView {
  id: string;
  device_name: string;
  created_at: string;
  /** 设备主人的自由备注（仅设备本人可写，全员可读） */
  remark: string;
  authorized: boolean;
  this_device: boolean;
}

/** `sync_now` 返回：一轮同步的计数汇总（对应 Rust SyncNowReport） */
export interface SyncNowReport {
  /** 新拉取落库的远端 op 条数 */
  pulled: number;
  /** 物化进主库的条目数（新行或更新） */
  materialized: number;
  /** 当前待裁决的冲突条目数（>0 时打开冲突弹窗） */
  conflicts: number;
  /** 因身份未同步而挂起的条目数（下轮补齐） */
  pending_identity: number;
  /** push 出去的本地 op 条数 */
  pushed: number;
  /** 本次灌入 oplog 的存量凭据条数（通常只在首次同步非零） */
  backfilled: number;
}

/** `sync_rotate` 返回：一次 group key 轮换的计数汇总（对应 Rust SyncRotateReport） */
export interface SyncRotateReport {
  /** 以新组密钥重新入账的凭据条数 */
  rewrapped: number;
  /** 因 legacy/解密失败跳过的条数（轮换后仍只有旧组密文） */
  skipped: number;
  /** 轮换全程 push 出去的 op 总条数 */
  pushed: number;
}

/** 同步快照明文（对应 Rust SyncItemSnapshot；冲突对比展示用，data 不展开） */
export interface SyncItemSnapshotView {
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url: string | null;
  username: string | null;
  notes: string | null;
  tags: string[];
  is_favorite: boolean;
  is_active: boolean;
  /** 凭据数据（Rust CredentialData 的 serde 形态；前端只做整体对比） */
  data: unknown;
}

/** 冲突条目的单个版本（对应 Rust desktop SyncConflictVersion） */
export interface SyncConflictVersion {
  /** 采纳时传给 sync_conflict_resolve 的 op id */
  op_id: string;
  /** 产生该版本的设备 id（对比本机 device_id 标「本机」） */
  device_id: string;
  lamport: number;
  /** 仅展示，不参与裁决排序（LWW 只看 lamport + device） */
  timestamp: string | null;
  /** tombstone 版本：采纳 = 删除该条目；此时无 snapshot */
  deleted: boolean;
  snapshot: SyncItemSnapshotView | null;
}

/** 一个条目的冲突视图（对应 Rust desktop SyncConflictEntry） */
export interface SyncConflictEntry {
  item_id: string;
  /** 当前版本（LWW 主位——什么都不做就保留它） */
  primary: SyncConflictVersion;
  /** 待裁决副本（每份可采纳，采纳后其余版本淘汰） */
  copies: SyncConflictVersion[];
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
  /** 界面语言（"zh-CN" / "en"）；null = 默认基准语言 zh-CN */
  locale: string | null;
  /** 可选同步服务器配置（旧 JSON 缺键时为 null） */
  sync: SyncConfig | null;
  /** Quick Access 全局热键是否启用（默认 true，旧 JSON 缺键时为 true） */
  quick_access_enabled: boolean;
  /** Quick Access 全局热键绑定串；null = 用桌面端平台默认绑定 */
  quick_access_hotkey: string | null;
  /** 账号域绑定（null = 未绑定；账号功能默认关闭，绑定是显式动作） */
  account: AccountBinding | null;
  /** 自救口备份凭证（null = 从未在本机导出过；旧 JSON 缺键时为 null） */
  backup: BackupEvidence | null;
}

/** 一次整库加密备份的导出记录（core `BackupEvidence` 镜像）。
 * 非敏感元数据；备份口令永不落盘。 */
export interface BackupEvidence {
  /** 导出时刻（RFC3339） */
  exported_at: string;
  /** 目标类型："file"（本地文件）/ "server"（服务器密文仓，后续批） */
  destination: string;
  /** 密文字节数 */
  size_bytes: number;
}

/** `backup_export_to_file` 的返回（含与 BackupEvidence 对账的元数据）。 */
export interface BackupExportOutcome {
  path: string;
  size_bytes: number;
  sha256: string;
  exported_at: string;
}

/** `backup_restore_from_file` 的返回：换库段留下的原库副本 `.bak` 路径
 * （原库不存在时为 null——全新安装上的首次恢复没有可留存的旧库）。 */
export interface BackupRestoreOutcome {
  backup_copy: string | null;
}

/** `backup_push_to_server` 的返回（服务器返回元数据 + 本地导出凭证时刻）。 */
export interface BackupPushOutcome {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
  /** 同设备最新版本 sha256 相同时服务器去重（未产生新版本） */
  deduplicated: boolean;
  exported_at: string;
}

/** 服务器密文仓里的一个备份版本（列表视图）。 */
export interface BackupVersionView {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

/** `backup_delete_server_version` 的返回（服务器 404 幂等，恒 true）。 */
export interface BackupServerDeleteOutcome {
  deleted: boolean;
}

/** 账号域绑定（core `AccountBinding` 镜像）。非敏感标识；令牌真值在
 * OS keyring，不经前端。 */
export interface AccountBinding {
  account_id: string;
  username: string;
  /** 本机 SRP 凭证的设备名 */
  device_name?: string | null;
}

/**
 * Quick Access 状态面（对应 Rust quick_access::QuickAccessStatus）。
 * configured（DB 真值）与 registered（真实抢注结果）分开：抢注失败时
 * 前者有值、后者为 null，UI 据此显示"未生效 + 原因"
 */
export interface QuickAccessStatus {
  enabled: boolean;
  configured_accelerator: string;
  registered_accelerator: string | null;
  error: string | null;
}

/** persona://quick-access-open-credential 事件载荷（浮窗 → 主窗口跨窗跳转） */
export interface QuickAccessOpenCredential {
  identity_id: string;
  credential_id: string;
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
    | 'stale_unchanged'
    | 'two_factor_available';
  /** weak_password：zxcvbn 分数 */
  score?: number;
  /** reused_password：共用同一明文密码的凭据数 */
  group_size?: number;
  /** breached_password：在泄露库中出现的次数 */
  count?: number;
  /** expiring_soon / stale_unchanged：距过期/未更新天数 */
  days?: number;
  /** two_factor_available：命中 2FA 目录的站点（归一化域名） */
  site?: string;
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
  /** two_factor_available：命中 2FA 目录的站点（归一化域名） */
  site?: string;
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
  | 'wallet_bip39_passphrase'
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
  /** 旅行模式标记：enter 时随之移出本设备 */
  travel_marked: boolean;
}

// ---------------------------------------------------------------------------
// 旅行模式（与 Rust TravelStatus/TravelCounts 的 serde 输出对应）
// ---------------------------------------------------------------------------

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
  /** 该版本可否恢复（删除行无 new_state，不可恢复） */
  restorable: boolean;
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

/** 元数据编辑请求（条目类型不可变；payload 编辑走 UpdateCredentialDataRequest） */
export interface UpdateCredentialRequest {
  id: string;
  name: string;
  security_level?: string;
  url?: string;
  username?: string;
  notes?: string;
  tags?: string[];
}

/** 密文 payload 编辑请求（敏感：复用原 item key 重封 + 敏感门禁） */
export interface UpdateCredentialDataRequest {
  credential_id: string;
  credential_data: CredentialDataRequest;
}

export type CredentialDataRequest =
  | { type: 'Password'; password: string; email?: string; security_questions: SecurityQuestion[] }
  | { type: 'CryptoWallet'; wallet_type: string; mnemonic_phrase?: string; private_key?: string; public_key: string; address: string; network: string; bip39_passphrase?: string }
  | { type: 'SshKey'; private_key: string; public_key: string; key_type: string; passphrase?: string }
  | { type: 'ApiKey'; api_key: string; api_secret?: string; token?: string; permissions: string[]; expires_at?: string }
  | { type: 'TwoFactor'; secret_key: string; issuer: string; account_name: string; algorithm: string; digits: number; period: number }
  | { type: 'GameToken'; provider: string; secret_key: string; issuer: string; account_name: string; url?: string }
  | { type: 'SecureNote'; note: string }
  | {
      type: 'Identity';
      first_name: string;
      last_name: string;
      username?: string;
      email?: string;
      phone?: string;
      birthday?: string;
      address?: string;
      id_number?: string;
      passport_number?: string;
      driver_license?: string;
      tax_id?: string;
      organization?: string;
      job_title?: string;
    }
  | {
      type: 'SoftwareLicense';
      license_key: string;
      version?: string;
      publisher?: string;
      purchase_date?: string;
      order_number?: string;
      support_email?: string;
      download_url?: string;
      seats?: number;
      valid_until?: string;
    }
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
  /** 线格式算法（ssh-ed25519 等）；数据取不到时为 null */
  ssh_algorithm?: string | null;
  /** SHA256 指纹（SHA256:…），与导入/生成确认处同口径 */
  fingerprint?: string | null;
  /** 位数/曲线标签（Ed25519→256、RSA→4096、ECDSA→P-256）；不适用为 null */
  key_size?: string | null;
  /** 完整公钥行，供一键复制 */
  public_key?: string | null;
}

/** inspect_ssh_key_file 响应：导入确认弹框展示（指纹人工核对） */
export interface SshKeyInspection {
  file_name: string;
  key_type: string;
  ssh_algorithm: string;
  public_key: string;
  fingerprint: string;
  comment: string;
  encrypted: boolean;
}

/** import_ssh_key 响应 */
export interface SshKeyImported {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

/** generate_ssh_key 响应：与导入同形（成功态展示复用） */
export interface SshKeyGenerated {
  credential_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
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
export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor' | 'GameToken' | 'SecureNote' | 'Identity' | 'SoftwareLicense';
export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** 主题偏好三档；'system' 跟随 prefers-color-scheme */
export type ThemePreference = 'system' | 'light' | 'dark';

/**
 * 1Password 式凭据分类（侧栏"类别"分组 + 列表筛选）。
 * 每个分类映射到一组 credential_type（见 sidebarNav.ts CATEGORY_TYPES）；
 * 通行密钥不在此列——它存在独立的 passkeys 表里，由 { kind: 'passkeys' } 视图管理。
 */
export type CredentialCategory =
  | 'passwords'
  | 'secure_notes'
  | 'api_keys'
  | 'ssh_keys'
  | 'software_licenses'
  | 'identity_documents'
  | 'crypto_wallets'
  | 'game_tokens';

/** 侧栏分类树的单选筛选态（默认 { kind: 'all' }；不做 localStorage 持久化） */
export type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'category'; value: CredentialCategory }
  | { kind: 'identity'; value: string } // identity id
  | { kind: 'tag'; value: string }
  // 特殊视图（不参与凭据筛选，直接渲染对应面板）
  | { kind: 'statistics' }
  | { kind: 'sshAgent' }
  | { kind: 'wallets' }
  | { kind: 'watchtower' }
  | { kind: 'passkeys' }
  | { kind: 'generator' };

/**
 * 待注入的凭据选中项（全局搜索跨身份跳转用）：QuickSearch 写入，
 * CredentialList 在目标身份的凭据加载完成后消费并清除。
 */
export type PendingCredentialSelection = { identityId: string; credentialId: string };

export interface InitRequest {
  master_password: string;
  db_path?: string;
}

// ---------------------------------------------------------------------------
// Connect 本机自动化（与 Rust connect_server/commands 的 serde 输出对应）
// ---------------------------------------------------------------------------

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

/** `generate_password_advanced` 响应：候选口令 + 供展示的熵值估计与字符池
 * 大小（显示参考而非安全承诺；与 core 生成器字符集同源）。 */
export interface GeneratedPasswords {
  passwords: string[];
  entropy_bits: number;
  pool_size: number;
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


/** 同步组配对（对应 Rust SyncPairingCreateOutcome）：host 出码面 */
export interface SyncPairingCreateOutcome {
  /** 动态密码（9 位 Crockford base32，与对方人工核对） */
  code: string;
  /** 邀请串 persona-pair-1.{b64url 载荷}（QR / 剪贴板递给对方） */
  invite_link: string;
  /** 中转会话 id（poll / cancel 定位用） */
  session_id: string;
  /** 中转会话剩余有效期（秒） */
  expires_in_secs: number;
}

/** `sync_group_pairing_poll` 返回（对应 Rust SyncPairingPollOutcome） */
export interface SyncPairingPollOutcome {
  completed: boolean;
  /** host 侧 6 位数字短指纹（与 guest 端展示比对） */
  fingerprint: string | null;
}

/** `sync_group_join_begin` 返回（对应 Rust SyncJoinBeginOutcome） */
export interface SyncJoinBeginOutcome {
  /** guest 侧 6 位数字短指纹（与 host 端比对，一致才 confirm） */
  fingerprint: string;
  /** 邀请串里的动态密码（与手输码核对） */
  code: string;
  /** 中转会话 id（confirm / cancel 定位用） */
  session_id: string;
}

/** `sync_status` 返回（对应 Rust SyncStatusInfo）：组同步水位快照 */
export interface SyncStatusReport {
  /** 组最新版本号（服务器指令流最大 seq；空组 0） */
  headSeq: number;
  /** 本机已同步水位（已拉到的 seq；从未拉过 0） */
  localWatermark: number;
  /** 落后组多少条指令 */
  behind: number;
  /** 本机已产生、尚未推上组的指令数 */
  pendingPush: number;
  /** 最近一次成功同步（RFC3339；null = 从未同步） */
  lastSyncAt: string | null;
}

/** `ssh_agent_integration_status` 返回（对应 Rust SshIntegrationStatus）：
 *  ~/.ssh/config 的 IdentityAgent 锚点块三态快照 */
export interface SshIntegrationStatus {
  /** 锚点块存在且指向当前 agent socket */
  enabled: boolean;
  /** 锚点块存在但指向别处（旧路径/手改）——重新启用即修复 */
  anomaly: string | null;
  /** 锚点块之外用户手写的 persona IdentityAgent（提示，不自动动它） */
  manualEntry: boolean;
  /** ~/.ssh/config 实际路径 */
  configPath: string;
  /** agent 稳定 socket（写入值/比对基准） */
  socketPath: string;
  /** 锚点块当前 IdentityAgent 值（未启用 null） */
  identityAgent: string | null;
  /** OpenSSH 版本（探测失败 null；IdentityAgent 需 8.3+） */
  sshVersion: string | null;
  /** config 文件在盘上（不存在不算错误：首次启用会创建） */
  configExists: boolean;
  /** 读失败原因（权限/IO）——如实显示，绝不静默吞；enable 时会拒绝写 */
  readError: string | null;
}

/** ~/.ssh/config 里的单条 agent 相关配置（对应 Rust SshConfigEntry） */
export interface SshConfigEntry {
  /** 所在文件绝对路径（Include 展开后可能是别的文件） */
  file: string;
  /** 行号（1 起） */
  line: number;
  /** 作用域行原文（空串 = 顶层全局；否则 Host/Match 行） */
  scope: string;
  /** 关键字原文（保留大小写） */
  keyword: string;
  /** 值（去引号） */
  value: string;
}

/** `ssh_agent_config_analysis` 返回（对应 Rust SshConfigAgentAnalysis）：
 *  ~/.ssh/config 的 agent 面只读分析——Include 展开 + 环境变量 + socket 探测 */
export interface SshConfigAgentAnalysis {
  configPath: string;
  /** config 文件在盘上 */
  configExists: boolean;
  /** 主文件可读（Include 子文件读失败只进 warnings） */
  readable: boolean;
  /** 主文件读失败原因（权限/IO/非 UTF-8） */
  readError: string | null;
  /** 解析过程中的非致命问题（Include 缺文件/循环/超深度等） */
  warnings: string[];
  /** agent 相关条目（IdentityAgent/ForwardAgent/AddKeysToAgent/ProxyAgent；
   *  persona 锚点块内不计） */
  entries: SshConfigEntry[];
  /** ForwardAgent 条目（转发经常单列展示） */
  forwardAgentEntries: SshConfigEntry[];
  /** 生效 IdentityAgent：首个顶层条目；只有 host 级时 null 不妄断 */
  identityAgentEffective: string | null;
  /** 环境 SSH_AUTH_SOCK */
  sshAuthSock: string | null;
  /** 生效 socket：identityAgentEffective 优先，否则退 SSH_AUTH_SOCK */
  effectiveSocket: string | null;
  /** effectiveSocket 连通探测：true 有进程在听 / false 无人听 / null 未知 */
  socketAlive: boolean | null;
  /** persona agent 稳定 socket 连通探测（agent 进程是否活着） */
  personaSocketAlive: boolean;
}
