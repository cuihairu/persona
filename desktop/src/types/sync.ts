/** 同步域：配置、设备、配对/加入流程产出、冲突与轮换报表。 */

import type { AccountBinding } from './account';
import type { BackupEvidence } from './backup';
import type { FeatureFlags } from './api';

/** 同步服务器（persona-server Events API）客户端配置（对应 Rust SyncConfig） */
export interface SyncConfig {
  enabled: boolean;
  server_url: string;
  /**
   * 后端恒返回空串——token 真值存 OS keyring，不经 IPC 回读。
   * 提交空串 = 保留 keyring 既有令牌（前端不回填，避免常驻内存）。
   */
  server_token: string;
  /**
   * 云盘传输（Phase 2）的同步文件夹本机路径（iCloud Drive / Dropbox /
   * Google Drive 的本地同步目录）。非 secret，存 settings JSON；null =
   * 未配置。仅 `sync_transport === 'cloud'` 时有意义。
   */
  cloud_drive_dir?: string | null;
  /** 指令流走哪条传输：`server`（persona-server HTTP，默认）/ `cloud`
   * （云盘目录文件交换）。旧 JSON 缺键由后端 serde 回退 `server`。 */
  sync_transport?: 'server' | 'cloud';
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
  /** 同步方式开关（跨设备同步默认开、账号同步默认关；旧 JSON 缺键回退默认）。
   * 只控设置页入口可用性——关闭 ≠ 离开同步组、不删 keyring、不触发网络。 */
  sync_methods: { cross_device_sync: boolean; account_sync: boolean };
  /** Quick Access 全局热键是否启用（默认 true，旧 JSON 缺键时为 true） */
  quick_access_enabled: boolean;
  /** Quick Access 全局热键绑定串；null = 用桌面端平台默认绑定 */
  quick_access_hotkey: string | null;
  /** 账号域绑定（null = 未绑定；账号功能默认关闭，绑定是显式动作） */
  account: AccountBinding | null;
  /** 自救口备份凭证（null = 从未在本机导出过；旧 JSON 缺键时为 null） */
  backup: BackupEvidence | null;
}

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
