import { invoke } from './invoke';

import type {
  ApiResponse,
  QuickAccessStatus,
  FillTargetStatus,
  DesktopFillResult,
  GeneratorStatus,
} from '@/types';

export const desktopApi = {

  // -------------------------------------------------------------------------
  // Quick Access（OS 级全局热键 + 浮窗）
  // -------------------------------------------------------------------------

  /** 读状态面（免解锁）：configured = DB 真值，registered = 真实抢注结果 */
  async quickAccessStatus(): Promise<ApiResponse<QuickAccessStatus>> {
    return invoke('quick_access_status');
  },


  /**
   * 改开关/绑定。accelerator 传 null/空串 = 恢复平台默认绑定。
   * 返回体带 `error` 表示绑定已落库但 OS 抢注失败（设置页如实显示）
   */
  async quickAccessSet(
    enabled: boolean,
    accelerator: string | null,
  ): Promise<ApiResponse<QuickAccessStatus>> {
    return invoke('quick_access_set', { enabled, accelerator });
  },


  /** 拉起浮窗（托盘/设置页入口；热键被占用时的兜底） */
  async quickAccessOpen(): Promise<ApiResponse<boolean>> {
    return invoke('quick_access_open');
  },


  /** 浮窗 → 主窗口跨窗跳转（切身份 + 选中条目 + 主窗口前置） */
  async quickAccessOpenCredential(
    identityId: string,
    credentialId: string,
  ): Promise<ApiResponse<boolean>> {
    return invoke('quick_access_open_credential', {
      request: { identity_id: identityId, credential_id: credentialId },
    });
  },


  /** 桌面填充注入目标状态（#12：浮窗填充动作可用性探测 + 确认面目标信息） */
  async fillTargetStatus(): Promise<ApiResponse<FillTargetStatus>> {
    return invoke('fill_target_status');
  },


  /**
   * 桌面应用内填充注入（#12：注入到浮窗唤起前的前台窗口）。`confirmed`
   * 必须来自用户对浮窗确认面（目标应用名 + 窗口标题）的显式确认——
   * 后端对 confirmed=false 一律拒绝，不存在静默注入路径。`snapshotId`
   * 是确认面从 fill_target_status 拿到的快照标识（P1 确认绑定）：后端
   * 按它把确认绑定到具体快照——在途请求期间目标被重新捕获/浮窗收起
   * 都会如实拒绝（FILL_TARGET_CHANGED / FILL_TARGET_DISCARDED），绝不
   * 转投新目标。
   */
  async desktopFillCredential(
    credentialId: string,
    confirmed: boolean,
    snapshotId: string,
  ): Promise<ApiResponse<DesktopFillResult>> {
    return invoke('desktop_fill_credential', {
      credential_id: credentialId,
      confirmed,
      snapshot_id: snapshotId,
    });
  },


  /** 主窗口拉到前台（浮窗锁定态的"去解锁"出口） */
  async focusMainWindow(): Promise<ApiResponse<boolean>> {
    return invoke('focus_main_window');
  },


  // -------------------------------------------------------------------------
  // 生成器热键（gap #9 余项：OS 级呼出生成器浮窗；与 Quick Access 同一套
  // 门禁/落库/抢注语义，窗口与槽位独立）
  // -------------------------------------------------------------------------

  /** 读生成器热键状态面（免解锁，同 quickAccessStatus） */
  async generatorStatus(): Promise<ApiResponse<GeneratorStatus>> {
    return invoke('generator_status');
  },


  /**
   * 改生成器开关/绑定。accelerator 传 null/空串 = 恢复平台默认绑定。
   * 返回体带 `error` 表示绑定已落库但 OS 抢注失败（设置页如实显示）
   */
  async generatorSet(
    enabled: boolean,
    accelerator: string | null,
  ): Promise<ApiResponse<GeneratorStatus>> {
    return invoke('generator_set', { enabled, accelerator });
  },


  /** 拉起生成器浮窗（托盘/设置页入口；热键被占用时的兜底） */
  async generatorOpen(): Promise<ApiResponse<boolean>> {
    return invoke('generator_open');
  },
};
