import { invoke } from '@tauri-apps/api/core';
import type {
  ApiResponse,
  Identity,
  Credential,
  CredentialData,
  CredentialHistoryEntry,
  AttachmentEntry,
  CreateIdentityRequest,
  UpdateIdentityRequest,
  CreateCredentialRequest,
  UpdateCredentialRequest,
  UpdateCredentialDataRequest,
  Statistics,
  InitRequest,
  FeatureFlags,
  SyncConfig,
  FaviconData,
  WorkspaceSettings,
  SshAgentStatus,
  SshAgentKey,
  WalletListResponse,
  WalletAddressesResponse,
  WalletGenerateRequest,
  WalletGenerateResponse,
  WalletImportRequest,
  WalletExportRequest,
  WalletSummary,
  WalletAddress,
  TotpCodeResponse,
  AutoLockConfigRequest,
  AutoLockStatus,
  AuditLogEntry,
  AuditQueryRequest,
  AuditStatistics,
  HealthReport,
  HealthScanRequest,
  Passkey,
  CreatePasskeyRequest,
  PasskeyCreationResponse,
  SecretField,
  SecretReveal,
  IdentityExport,
  CreateTransactionRequest,
  SignTransactionRequest,
  WalletTransaction,
  WalletSignedTransaction,
} from '@/types';

class PersonaAPI {
  async initService(request: InitRequest): Promise<ApiResponse<boolean>> {
    return invoke('init_service', { request });
  }

  async lockService(): Promise<ApiResponse<boolean>> {
    return invoke('lock_service');
  }

  async isServiceUnlocked(): Promise<ApiResponse<boolean>> {
    return invoke('is_service_unlocked');
  }

  async createIdentity(request: CreateIdentityRequest): Promise<ApiResponse<Identity>> {
    return invoke('create_identity', { request });
  }

  async updateIdentity(request: UpdateIdentityRequest): Promise<ApiResponse<Identity>> {
    return invoke('update_identity', { request });
  }

  async deleteIdentity(identityId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_identity', { identity_id: identityId });
  }

  async getIdentities(): Promise<ApiResponse<Identity[]>> {
    return invoke('get_identities');
  }

  async getIdentity(id: string): Promise<ApiResponse<Identity | null>> {
    return invoke('get_identity', { id });
  }

  async getActiveIdentity(): Promise<ApiResponse<string | null>> {
    return invoke('get_active_identity');
  }

  async setActiveIdentity(identityId: string): Promise<ApiResponse<boolean>> {
    return invoke('set_active_identity', { identity_id: identityId });
  }

  async clearActiveIdentity(): Promise<ApiResponse<boolean>> {
    return invoke('clear_active_identity');
  }

  async getWorkspaceSettings(): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('get_workspace_settings');
  }

  /** 窄写 features 四个开关位，返回更新后的全量设置作为服务端真相 */
  async setFeatureFlags(flags: FeatureFlags): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_feature_flags', {
      ssh_agent: flags.ssh_agent,
      wallet: flags.wallet,
      passkeys: flags.passkeys,
      fetch_favicons: flags.fetch_favicons,
    });
  }

  /** 窄写主密码过期策略（天）；null = 不过期。返回更新后的全量设置 */
  async setPasswordExpiry(days: number | null): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_password_expiry', { days });
  }

  /** 窄写界面语言（"zh-CN" / "en"）。返回更新后的全量设置 */
  async setLocale(locale: string): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_locale', { locale });
  }

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
  }

  /** 窄写同步服务器配置；server_token 空串 = 后端保留旧 token（真值存 OS keyring） */
  async setSyncConfig(config: SyncConfig): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_config', {
      enabled: config.enabled,
      server_url: config.server_url,
      server_token: config.server_token,
    });
  }

  /** OS keyring 里是否存有 sync token（免解锁只读；真值不经 IPC） */
  async syncTokenPresent(): Promise<ApiResponse<boolean>> {
    return invoke('sync_token_present');
  }

  async createCredential(request: CreateCredentialRequest): Promise<ApiResponse<Credential>> {
    return invoke('create_credential', { request });
  }

  async updateCredential(request: UpdateCredentialRequest): Promise<ApiResponse<Credential>> {
    return invoke('update_credential', { request });
  }

  async updateCredentialData(
    request: UpdateCredentialDataRequest
  ): Promise<ApiResponse<Credential>> {
    return invoke('update_credential_data', { request });
  }

  async getCredentialsForIdentity(identityId: string): Promise<ApiResponse<Credential[]>> {
    return invoke('get_credentials_for_identity', { identity_id: identityId });
  }

  async getCredentialData(credentialId: string): Promise<ApiResponse<CredentialData | null>> {
    return invoke('get_credential_data', { credential_id: credentialId });
  }

  async getCredentialHistory(credentialId: string): Promise<ApiResponse<CredentialHistoryEntry[]>> {
    return invoke('get_credential_history', { credential_id: credentialId });
  }

  async listAttachments(credentialId: string): Promise<ApiResponse<AttachmentEntry[]>> {
    return invoke('list_attachments', { credential_id: credentialId });
  }

  async attachFileToCredential(
    credentialId: string,
    filePath: string,
    encrypt: boolean
  ): Promise<ApiResponse<AttachmentEntry>> {
    return invoke('attach_file_to_credential', {
      credential_id: credentialId,
      file_path: filePath,
      encrypt,
    });
  }

  async saveAttachmentToFile(
    attachmentId: string,
    outputPath: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('save_attachment_to_file', {
      attachment_id: attachmentId,
      output_path: outputPath,
    });
  }

  async deleteAttachment(attachmentId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_attachment', { attachment_id: attachmentId });
  }

  async getTotpCode(credentialId: string): Promise<ApiResponse<TotpCodeResponse>> {
    return invoke('get_totp_code', { credential_id: credentialId });
  }

  async searchCredentials(query: string): Promise<ApiResponse<Credential[]>> {
    return invoke('search_credentials', { query });
  }

  async generatePassword(length: number, includeSymbols: boolean): Promise<ApiResponse<string>> {
    return invoke('generate_password', { length, include_symbols: includeSymbols });
  }

  async getStatistics(): Promise<ApiResponse<Statistics>> {
    return invoke('get_statistics');
  }

  async toggleCredentialFavorite(credentialId: string): Promise<ApiResponse<Credential>> {
    return invoke('toggle_credential_favorite', { credential_id: credentialId });
  }

  /** 按需抓取凭据站点的 favicon（唯一外联入口；flag 关时后端兜底拒绝） */
  async fetchCredentialFavicon(credentialId: string): Promise<ApiResponse<FaviconData>> {
    return invoke('fetch_credential_favicon', { credential_id: credentialId });
  }

  /** 批量读已缓存 favicon（纯本地读；flag 关时后端静默回空数组） */
  async getFavicons(hosts: string[]): Promise<ApiResponse<FaviconData[]>> {
    return invoke('get_favicons', { hosts });
  }

  async deleteCredential(credentialId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_credential', { credential_id: credentialId });
  }

  async getSshAgentStatus(): Promise<ApiResponse<SshAgentStatus>> {
    return invoke('get_ssh_agent_status');
  }

  async startSshAgent(masterPassword?: string): Promise<ApiResponse<SshAgentStatus>> {
    return invoke('start_ssh_agent', { request: { master_password: masterPassword } });
  }

  async stopSshAgent(): Promise<ApiResponse<boolean>> {
    return invoke('stop_ssh_agent');
  }

  async getSshKeys(): Promise<ApiResponse<SshAgentKey[]>> {
    return invoke('get_ssh_keys');
  }

  async walletList(identityId?: string): Promise<ApiResponse<WalletListResponse>> {
    if (identityId) {
      return invoke('wallet_list', { identity_id: identityId });
    }
    return invoke('wallet_list');
  }

  async walletListAddresses(walletId: string): Promise<ApiResponse<WalletAddressesResponse>> {
    return invoke('wallet_list_addresses', { wallet_id: walletId });
  }

  async walletGenerate(
    identityId: string,
    request: WalletGenerateRequest,
  ): Promise<ApiResponse<WalletGenerateResponse>> {
    return invoke('wallet_generate', { identity_id: identityId, request });
  }

  async walletImport(
    identityId: string,
    request: WalletImportRequest,
  ): Promise<ApiResponse<WalletSummary>> {
    return invoke('wallet_import', { identity_id: identityId, request });
  }

  async walletAddAddress(walletId: string, password: string): Promise<ApiResponse<WalletAddress>> {
    return invoke('wallet_add_address', { wallet_id: walletId, password });
  }

  async walletDelete(walletId: string): Promise<ApiResponse<boolean>> {
    return invoke('wallet_delete', { wallet_id: walletId });
  }

  async walletExport(request: WalletExportRequest): Promise<ApiResponse<string>> {
    return invoke('wallet_export', { request });
  }

  // -------------------------------------------------------------------------
  // Auto-lock
  // -------------------------------------------------------------------------

  async configureAutoLock(request: AutoLockConfigRequest): Promise<ApiResponse<boolean>> {
    return invoke('configure_auto_lock', { request });
  }

  async getAutoLockStatus(): Promise<ApiResponse<AutoLockStatus>> {
    return invoke('get_auto_lock_status');
  }

  async touchActivity(): Promise<ApiResponse<boolean>> {
    return invoke('touch_activity');
  }

  async startAutoLockMonitoring(): Promise<ApiResponse<boolean>> {
    return invoke('start_auto_lock_monitoring');
  }

  async stopAutoLockMonitoring(): Promise<ApiResponse<boolean>> {
    return invoke('stop_auto_lock_monitoring');
  }

  // -------------------------------------------------------------------------
  // 审计
  // -------------------------------------------------------------------------

  async auditQuery(request: AuditQueryRequest): Promise<ApiResponse<AuditLogEntry[]>> {
    return invoke('audit_query', { request });
  }

  async auditStatistics(): Promise<ApiResponse<AuditStatistics>> {
    return invoke('audit_statistics');
  }

  async auditCleanup(retainDays: number): Promise<ApiResponse<number>> {
    return invoke('audit_cleanup', { retain_days: retainDays });
  }

  // -------------------------------------------------------------------------
  // Watchtower 健康扫描
  // -------------------------------------------------------------------------

  async healthScan(request?: HealthScanRequest): Promise<ApiResponse<HealthReport>> {
    return invoke('health_scan', { request: request ?? {} });
  }

  // -------------------------------------------------------------------------
  // Passkey
  // -------------------------------------------------------------------------

  async passkeyList(identityId: string): Promise<ApiResponse<Passkey[]>> {
    return invoke('passkey_list', { identity_id: identityId });
  }

  async passkeyListByRp(rpId: string): Promise<ApiResponse<Passkey[]>> {
    return invoke('passkey_list_by_rp', { rp_id: rpId });
  }

  async passkeyGet(id: string): Promise<ApiResponse<Passkey | null>> {
    return invoke('passkey_get', { id });
  }

  async passkeyDelete(id: string): Promise<ApiResponse<boolean>> {
    return invoke('passkey_delete', { id });
  }

  async passkeyCreate(request: CreatePasskeyRequest): Promise<ApiResponse<PasskeyCreationResponse>> {
    return invoke('passkey_create', { request });
  }

  async passkeySelfTest(id: string): Promise<ApiResponse<boolean>> {
    return invoke('passkey_self_test', { id });
  }

  async passkeyExportPrivateKey(id: string): Promise<ApiResponse<string>> {
    return invoke('passkey_export_private_key', { id });
  }

  // -------------------------------------------------------------------------
  // 导出 / 敏感字段 reveal / 重新认证
  // -------------------------------------------------------------------------

  async exportIdentity(identityId: string): Promise<ApiResponse<IdentityExport>> {
    return invoke('export_identity', { identity_id: identityId });
  }

  async revealCredentialSecret(
    credentialId: string,
    field: SecretField,
  ): Promise<ApiResponse<SecretReveal>> {
    return invoke('reveal_credential_secret', {
      request: { credential_id: credentialId, field },
    });
  }

  async reauthVerify(masterPassword: string): Promise<ApiResponse<boolean>> {
    return invoke('reauth_verify', { request: { master_password: masterPassword } });
  }

  // -------------------------------------------------------------------------
  // 钱包交易
  // -------------------------------------------------------------------------

  async walletCreateTransaction(
    request: CreateTransactionRequest,
  ): Promise<ApiResponse<WalletTransaction>> {
    return invoke('wallet_create_transaction', { request });
  }

  async walletPendingTransactions(walletId: string): Promise<ApiResponse<WalletTransaction[]>> {
    return invoke('wallet_pending_transactions', { wallet_id: walletId });
  }

  async walletSignTransaction(
    request: SignTransactionRequest,
  ): Promise<ApiResponse<WalletSignedTransaction>> {
    return invoke('wallet_sign_transaction', { request });
  }

  // -------------------------------------------------------------------------
  // SSH 签名审批
  // -------------------------------------------------------------------------

  async sshApprovalRespond(requestId: string, allow: boolean): Promise<ApiResponse<boolean>> {
    return invoke('ssh_approval_respond', { request: { request_id: requestId, allow } });
  }

  // -------------------------------------------------------------------------
  // Passkey 审批（bridge 经 Unix socket 转来的 create/assert 请求）
  // -------------------------------------------------------------------------

  async passkeyApprovalRespond(requestId: string, allow: boolean): Promise<ApiResponse<boolean>> {
    return invoke('passkey_approval_respond', { request: { request_id: requestId, allow } });
  }
}

export const personaAPI = new PersonaAPI();
