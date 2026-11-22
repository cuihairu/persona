import { invoke } from './invoke';

import type {
  ApiResponse,
  SyncConfig,
  SyncConflictEntry,
  SyncDeviceStatus,
  SyncDeviceView,
  SyncJoinBeginOutcome,
  SyncJoinOutcome,
  SyncNowReport,
  SyncPairingCreateOutcome,
  SyncPairingPollOutcome,
  SyncRotateReport,
  SyncStatusReport,
  ConnectServerStatus,
  ConnectTokenScope,
  ConnectTokenView,
  ConnectTokenCreatedView,
  WorkspaceSettings,
} from '@/types';

export const syncApi = {

  // ---------------------------------------------------------------------
  // Connect 本机自动化（secrets automation）
  // ---------------------------------------------------------------------

  /** 启动 Connect listener（bind 127.0.0.1；端口 null = OS 分配） */
  async connectServerStart(port?: number | null): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_start', { port: port ?? null });
  },


  /** 停止 Connect listener（幂等） */
  async connectServerStop(): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_stop');
  },


  /** Connect listener 运行状态 */
  async connectServerStatus(): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_status');
  },


  /** 创建 Connect token（敏感操作：reauth 门禁；明文仅响应一次） */
  async connectTokenCreate(
    label: string,
    scope: ConnectTokenScope,
  ): Promise<ApiResponse<ConnectTokenCreatedView>> {
    return invoke('connect_token_create', { label, scope });
  },


  /** token 管理列表（含已吊销；哈希不出库） */
  async connectTokenList(): Promise<ApiResponse<ConnectTokenView[]>> {
    return invoke('connect_token_list');
  },


  /** 吊销 Connect token（幂等，即时生效） */
  async connectTokenRevoke(id: string): Promise<ApiResponse<boolean>> {
    return invoke('connect_token_revoke', { id });
  },


  /** 窄写同步服务器配置；server_token 空串 = 后端保留旧 token（真值存 OS keyring） */
  async setSyncConfig(config: SyncConfig): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_config', {
      enabled: config.enabled,
      server_url: config.server_url,
      server_token: config.server_token,
    });
  },


  /**
   * 窄写同步方式开关（跨设备同步 / 账号同步，各自独立）。
   *
   * 语义红线：只写偏好（settings.sync_methods），**不删 keyring、不触发网络**
   * ——关闭某个方式 ≠ 离开同步组。成功返回全量 settings，由调用方回填真相。
   */
  async setSyncMethods(
    cross_device_sync: boolean,
    account_sync: boolean,
  ): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_methods', { cross_device_sync, account_sync });
  },


  /** OS keyring 里是否存有 sync token（免解锁只读；真值不经 IPC） */
  async syncTokenPresent(): Promise<ApiResponse<boolean>> {
    return invoke('sync_token_present');
  },


  /** E2EE sync 设备身份状态（纯本地 keyring，免解锁） */
  async syncDeviceStatus(): Promise<ApiResponse<SyncDeviceStatus>> {
    return invoke('sync_device_status');
  },


  /** 加入 E2EE 同步（生成设备密钥对并向服务器登记；失败不留半态） */
  async syncJoin(deviceName: string): Promise<ApiResponse<SyncJoinOutcome>> {
    return invoke('sync_join', { deviceName });
  },


  /** 离开同步（本地清理优先；服务器吊销尽力而为） */
  async syncLeave(): Promise<ApiResponse<boolean>> {
    return invoke('sync_leave');
  },


  /** 同步组设备列表（含授权状态与本机标记） */
  async syncListDevices(): Promise<ApiResponse<SyncDeviceView[]>> {
    return invoke('sync_list_devices');
  },


  /** 设置本设备备注（服务端按令牌归属锁定；空串/纯空白 = 清除；返回规整后的备注） */
  async syncSetDeviceRemark(remark: string): Promise<ApiResponse<string>> {
    return invoke('sync_set_device_remark', { remark });
  },


  /** 为目标设备授权（拆本机信封重封目标公钥；本机未授权 fail-closed） */
  async syncAuthorize(targetDeviceId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_authorize', { targetDeviceId });
  },


  /** 吊销设备（幂等；吊销自己走 syncLeave） */
  async syncRevoke(targetDeviceId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_revoke', { targetDeviceId });
  },


  /** 立即同步：存量灌入 → pull/materialize/push 周期，返回计数汇总 */
  async syncNow(): Promise<ApiResponse<SyncNowReport>> {
    return invoke('sync_now');
  },


  /** 同步状态快照：组最新版本号/本机水位/落后 N/待推 N/最近同步时间（只读） */
  async syncStatus(): Promise<ApiResponse<SyncStatusReport>> {
    return invoke('sync_status');
  },


  /** group key 轮换：换信封 + 全量重包（吊销设备真正闭环的安全操作） */
  async syncRotate(): Promise<ApiResponse<SyncRotateReport>> {
    return invoke('sync_rotate');
  },


  /** 全部待裁决冲突条目（主位 + 副本解密快照；只读） */
  async syncConflictsList(): Promise<ApiResponse<SyncConflictEntry[]>> {
    return invoke('sync_conflicts_list');
  },


  /** 冲突裁决：采纳一个副本（其余版本淘汰出裁决视图，数据不丢） */
  async syncConflictResolve(itemId: string, adoptOpId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_conflict_resolve', { itemId, adoptOpId });
  },


  /** 同步组：本 vault 是否已加入（keyring 组密钥条目，免解锁只读） */
  async syncGroupStatus(): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_status');
  },


  /** 同步组配对：host 出码（动态密码 + 邀请串；会话挂起等待对方加入） */
  async syncGroupPairingCreate(): Promise<ApiResponse<SyncPairingCreateOutcome>> {
    return invoke('sync_group_pairing_create');
  },


  /**
   * 同步组配对：host 等待 guest 加入（阻塞至完成或 90s 超时；取消走
   * syncGroupPairingCancel，中转信箱删除后本调用即报错返回）
   */
  async syncGroupPairingPoll(sessionId: string): Promise<ApiResponse<SyncPairingPollOutcome>> {
    return invoke('sync_group_pairing_poll', { sessionId });
  },


  /** 同步组配对：取消会话（host/guest 通用；幂等，尽力清理中转信箱） */
  async syncGroupPairingCancel(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_pairing_cancel', { sessionId });
  },


  /** 同步组加入：guest 解析邀请串起配，返回短指纹（与 host 端比对） */
  async syncGroupJoinBegin(inviteLink: string): Promise<ApiResponse<SyncJoinBeginOutcome>> {
    return invoke('sync_group_join_begin', { inviteLink });
  },


  /** 同步组加入：指纹比对通过后确认入组（组密钥落 keyring） */
  async syncGroupJoinConfirm(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_join_confirm', { sessionId });
  },


  /** 同步组加入：取消（指纹不通过 / 放弃；幂等） */
  async syncGroupJoinCancel(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_join_cancel', { sessionId });
  },
};
