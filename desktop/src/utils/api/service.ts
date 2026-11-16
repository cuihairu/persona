import { invoke } from './invoke';

import type {
  ApiResponse,
  InitRequest,
  FeatureFlags,
  BiometricStatus,
  WorkspaceSettings,
  TrayLocaleLabels,
  AutoLockConfigRequest,
  AutoLockStatus,
} from '@/types';

export const serviceApi = {
  async initService(request: InitRequest): Promise<ApiResponse<boolean>> {
    return invoke('init_service', { request });
  },


  async lockService(): Promise<ApiResponse<boolean>> {
    return invoke('lock_service');
  },


  async isServiceUnlocked(): Promise<ApiResponse<boolean>> {
    return invoke('is_service_unlocked');
  },


  async getWorkspaceSettings(): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('get_workspace_settings');
  },


  /** 窄写 features 四个开关位，返回更新后的全量设置作为服务端真相 */
  async setFeatureFlags(flags: FeatureFlags): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_feature_flags', {
      ssh_agent: flags.ssh_agent,
      wallet: flags.wallet,
      passkeys: flags.passkeys,
      fetch_favicons: flags.fetch_favicons,
    });
  },


  /** 窄写主密码过期策略（天）；null = 不过期。返回更新后的全量设置 */
  async setPasswordExpiry(days: number | null): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_password_expiry', { days });
  },


  /** 窄写界面语言（"zh-CN" / "en"）。返回更新后的全量设置 */
  async setLocale(locale: string): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_locale', { locale });
  },


  /** 托盘右键菜单文案换语言：真值在 i18n locale 表（tray.*），Rust 只渲染 */
  async setTrayLocale(labels: TrayLocaleLabels): Promise<ApiResponse<boolean>> {
    return invoke('set_tray_locale', { labels });
  },


  /** 修改主密码（旧密码仅存在于本次请求，不落盘不进日志）；成功后前端需重新 init */
  async changeMasterPassword(
    oldPassword: string,
    newPassword: string,
    dbPath?: string,
  ): Promise<ApiResponse<boolean>> {
    return invoke('change_master_password', {
      request: {
        old_password: oldPassword,
        new_password: newPassword,
        db_path: dbPath ?? null,
      },
    });
  },


  // -------------------------------------------------------------------------
  // Auto-lock
  // -------------------------------------------------------------------------

  async configureAutoLock(request: AutoLockConfigRequest): Promise<ApiResponse<boolean>> {
    return invoke('configure_auto_lock', { request });
  },


  async getAutoLockStatus(): Promise<ApiResponse<AutoLockStatus>> {
    return invoke('get_auto_lock_status');
  },


  async touchActivity(): Promise<ApiResponse<boolean>> {
    return invoke('touch_activity');
  },


  async startAutoLockMonitoring(): Promise<ApiResponse<boolean>> {
    return invoke('start_auto_lock_monitoring');
  },


  async stopAutoLockMonitoring(): Promise<ApiResponse<boolean>> {
    return invoke('stop_auto_lock_monitoring');
  },


  /** biometric unlock 状态（免解锁只读；解锁屏 mount 即查，决定指纹按钮显隐） */
  async biometricStatus(dbPath?: string): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_status', { dbPath: dbPath ?? null });
  },


  /** 启用 biometric unlock：后端先验密码再弹 OS 认证框，然后托管进 keyring */
  async biometricEnable(masterPassword: string): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_enable', { request: { master_password: masterPassword } });
  },


  /** 禁用 biometric unlock：幂等删 keyring 条目 */
  async biometricDisable(): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_disable');
  },


  /** biometric 解锁：OS 认证 → keyring 取回主密码走 init_service（密码不出进程） */
  async biometricUnlock(dbPath?: string): Promise<ApiResponse<boolean>> {
    return invoke('biometric_unlock', { request: { db_path: dbPath ?? null } });
  },


  async reauthVerify(masterPassword: string): Promise<ApiResponse<boolean>> {
    return invoke('reauth_verify', { request: { master_password: masterPassword } });
  },
};
