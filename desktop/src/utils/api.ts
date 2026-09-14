import { invoke } from '@tauri-apps/api/core';
import type {
  ApiResponse,
  Identity,
  Credential,
  CredentialData,
  CreateIdentityRequest,
  UpdateIdentityRequest,
  CreateCredentialRequest,
  Statistics,
  InitRequest,
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

  async createCredential(request: CreateCredentialRequest): Promise<ApiResponse<Credential>> {
    return invoke('create_credential', { request });
  }

  async getCredentialsForIdentity(identityId: string): Promise<ApiResponse<Credential[]>> {
    return invoke('get_credentials_for_identity', { identity_id: identityId });
  }

  async getCredentialData(credentialId: string): Promise<ApiResponse<CredentialData | null>> {
    return invoke('get_credential_data', { credential_id: credentialId });
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
}

export const personaAPI = new PersonaAPI();
