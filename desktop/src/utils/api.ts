import { invoke } from '@tauri-apps/api/tauri';
import type {
  ApiResponse,
  Identity,
  Credential,
  CredentialData,
  CreateIdentityRequest,
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

  async getIdentities(): Promise<ApiResponse<Identity[]>> {
    return invoke('get_identities');
  }

  async getIdentity(id: string): Promise<ApiResponse<Identity | null>> {
    return invoke('get_identity', { id });
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

  async walletExport(request: WalletExportRequest): Promise<ApiResponse<string>> {
    return invoke('wallet_export', { request });
  }
}

export const personaAPI = new PersonaAPI();
