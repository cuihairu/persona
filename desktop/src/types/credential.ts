/** 凭据域：身份/凭据/附件/历史/自定义字段、passkey 与揭示、快速访问与填充确认。 */

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

/**
 * 生成器热键状态面（对应 Rust quick_access::GeneratorStatus，语义与
 * QuickAccessStatus 同构：configured = DB 真值，registered = 真实抢注结果）
 */
export interface GeneratorStatus {
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

/** 桌面填充注入目标状态（fill_target_status 命令响应；snake_case 逐字对齐） */
export interface FillTargetStatus {
  supported: boolean;
  /** 已捕获且当前指纹（窗口/进程/类名/可执行文件）仍然一致的目标 */
  ready: boolean;
  target_title: string | null;
  /** 目标应用可执行文件名（如 "notepad.exe"；确认面展示用） */
  target_app: string | null;
  /** 当前有效快照标识（P1 确认绑定）：注入请求必须原样带回 */
  snapshot_id: string | null;
}

/** 桌面填充注入结果（desktop_fill_credential 命令响应；snake_case 逐字对齐） */
export interface DesktopFillResult {
  username_filled: boolean;
  password_filled: boolean;
  target_title: string;
  warning: string | null;
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

/**
 * 结构化自定义字段（1Password 对齐，对应 Rust SerializableCustomField）。
 * 整表以 per-item key 密封存于 credential.metadata，读需解锁；
 * `concealed` 行 value 是密文解出后的明文，仅在 UI 层打码。
 */
export interface CustomField {
  id: string;
  label: string;
  value: string;
  type: 'text' | 'concealed' | 'date';
  section: string | null;
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
  | { type: 'TwoFactor'; secret_key: string; issuer: string; account_name: string; algorithm: string; digits: number; period: number; hotp?: boolean; initial_counter?: number }
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

export type IdentityType = 'Personal' | 'Work' | 'Social' | 'Financial' | 'Gaming';

export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor' | 'GameToken' | 'SecureNote' | 'Identity' | 'SoftwareLicense';

export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

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
