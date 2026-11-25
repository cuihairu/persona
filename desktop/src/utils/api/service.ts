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


  /** Narrow write of the four feature switches; returns the updated full settings as the server's truth */
  async setFeatureFlags(flags: FeatureFlags): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_feature_flags', {
      ssh_agent: flags.ssh_agent,
      wallet: flags.wallet,
      passkeys: flags.passkeys,
      fetch_favicons: flags.fetch_favicons,
    });
  },


  /** Narrow write of the master password expiry policy (days); null = never expires. Returns the updated full settings */
  async setPasswordExpiry(days: number | null): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_password_expiry', { days });
  },


  /** Narrow write of the UI language ("zh-CN" / "en"). Returns the updated full settings */
  async setLocale(locale: string): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_locale', { locale });
  },


  /** Re-language the tray right-click menu labels: the truth is in the i18n locale table (tray.*), Rust only renders */
  async setTrayLocale(labels: TrayLocaleLabels): Promise<ApiResponse<boolean>> {
    return invoke('set_tray_locale', { labels });
  },


  /** Change the master password (the old password exists only within this request, never on disk or in logs); after success the frontend must re-init */
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


  /** Biometric unlock status (read-only without unlocking; queried at unlock-screen mount to decide whether the fingerprint button shows) */
  async biometricStatus(dbPath?: string): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_status', { dbPath: dbPath ?? null });
  },


  /** Enable biometric unlock: the backend verifies the password, then pops the OS auth prompt, then hosts the secret into the keyring */
  async biometricEnable(masterPassword: string): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_enable', { request: { master_password: masterPassword } });
  },


  /** Disable biometric unlock: idempotently deletes the keyring entry */
  async biometricDisable(): Promise<ApiResponse<BiometricStatus>> {
    return invoke('biometric_disable');
  },


  /** Biometric unlock: OS authentication → fetch the master password from the keyring and run init_service (the password never leaves the process) */
  async biometricUnlock(dbPath?: string): Promise<ApiResponse<boolean>> {
    return invoke('biometric_unlock', { request: { db_path: dbPath ?? null } });
  },


  async reauthVerify(masterPassword: string): Promise<ApiResponse<boolean>> {
    return invoke('reauth_verify', { request: { master_password: masterPassword } });
  },
};
