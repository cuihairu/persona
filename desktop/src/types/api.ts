/** 平台 API 面：错误码与统一响应壳、自动锁/生物识别/功能开关、托盘与工具载荷。 */

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
 * FILL_TARGET_SNAPSHOT_REQUIRED / FILL_TARGET_DISCARDED / FILL_TARGET_CHANGED：
 * 桌面填充确认绑定（P1）——请求缺 snapshot_id / 确认后目标已丢弃（浮窗
 * 收起清槽）/ 确认后目标被重新捕获替换 → 如实提示重新走确认流。
 * SYNC_SERVER_UNREACHABLE / SYNC_CLOUD_FOLDER_UNAVAILABLE：同步周期的
 * 传输层 I/O 失败（CLOUD_DRIVE_SYNC §9.4）——服务器侧不可达 / 云盘目录
 * 不可用（不存在、被删、OS 云代理未分发）。两者修法不同，前端按码分流
 * 提示，不混成一个「同步失败」。
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
  | 'ITEM_PASSWORD_WRONG'
  | 'FILL_TARGET_SNAPSHOT_REQUIRED'
  | 'FILL_TARGET_DISCARDED'
  | 'FILL_TARGET_CHANGED'
  | 'SYNC_SERVER_UNREACHABLE'
  | 'SYNC_CLOUD_FOLDER_UNAVAILABLE';

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

/** 已缓存的站点图标（对应 Rust SerializableFavicon；data 为 base64 图像字节） */
export interface FaviconData {
  host: string;
  mime_type: string;
  data: string;
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

/** 主题偏好三档；'system' 跟随 prefers-color-scheme */
export type ThemePreference = 'system' | 'light' | 'dark';

export interface InitRequest {
  master_password: string;
  db_path?: string;
}

// ---------------------------------------------------------------------------
// Connect 本机自动化（与 Rust connect_server/commands 的 serde 输出对应）
// ---------------------------------------------------------------------------

/** `generate_password_advanced` 响应：候选口令 + 供展示的熵值估计与字符池
 * 大小（显示参考而非安全承诺；与 core 生成器字符集同源）。 */
export interface GeneratedPasswords {
  passwords: string[];
  entropy_bits: number;
  pool_size: number;
}

/** `ssh_agent_integration_status` 返回（对应 Rust SshIntegrationStatus）：
 *  ~/.ssh/config 的 IdentityAgent 锚点块三态快照 */
/** 托盘右键菜单文案（i18n locale 表是真值源，Rust 只渲染不存词） */
export interface TrayLocaleLabels {
  open: string;
  quickAccess: string;
  generator: string;
  lock: string;
  quit: string;
}
