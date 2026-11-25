import { invoke } from './invoke';

import type {
  ApiResponse,
  Credential,
  CredentialData,
  CredentialHistoryEntry,
  AttachmentEntry,
  CustomField,
  CreateCredentialRequest,
  UpdateCredentialRequest,
  UpdateCredentialDataRequest,
  GeneratedPasswords,
  FaviconData,
  TotpCodeResponse,
  SecretField,
  SecretReveal,
} from '@/types';

export const credentialApi = {

  async createCredential(request: CreateCredentialRequest): Promise<ApiResponse<Credential>> {
    return invoke('create_credential', { request });
  },


  async updateCredential(request: UpdateCredentialRequest): Promise<ApiResponse<Credential>> {
    return invoke('update_credential', { request });
  },


  async updateCredentialData(
    request: UpdateCredentialDataRequest
  ): Promise<ApiResponse<Credential>> {
    return invoke('update_credential_data', { request });
  },


  async getCredentialsForIdentity(identityId: string): Promise<ApiResponse<Credential[]>> {
    return invoke('get_credentials_for_identity', { identity_id: identityId });
  },


  async getCredentialData(credentialId: string): Promise<ApiResponse<CredentialData | null>> {
    return invoke('get_credential_data', { credential_id: credentialId });
  },


  async getCredentialHistory(credentialId: string): Promise<ApiResponse<CredentialHistoryEntry[]>> {
    return invoke('get_credential_history', { credential_id: credentialId });
  },


  async restoreCredentialVersion(
    credentialId: string,
    version: number
  ): Promise<ApiResponse<Credential>> {
    return invoke('restore_credential_version', { credential_id: credentialId, version });
  },


  /** Structured custom fields (1Password-aligned): sealed with the per-item key, reading requires an unlock */
  async getCredentialCustomFields(
    credentialId: string
  ): Promise<ApiResponse<CustomField[]>> {
    return invoke('get_credential_custom_fields', { credential_id: credentialId });
  },


  /** Replaces the whole table (empty table = remove); pass an empty string for new rows' id and the backend generates it */
  async setCredentialCustomFields(
    credentialId: string,
    fields: CustomField[]
  ): Promise<ApiResponse<CustomField[]>> {
    return invoke('set_credential_custom_fields', {
      credential_id: credentialId,
      fields,
    });
  },


  async listAttachments(credentialId: string): Promise<ApiResponse<AttachmentEntry[]>> {
    return invoke('list_attachments', { credential_id: credentialId });
  },


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
  },


  async saveAttachmentToFile(
    attachmentId: string,
    outputPath: string
  ): Promise<ApiResponse<boolean>> {
    return invoke('save_attachment_to_file', {
      attachment_id: attachmentId,
      output_path: outputPath,
    });
  },


  async deleteAttachment(attachmentId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_attachment', { attachment_id: attachmentId });
  },


  async getTotpCode(credentialId: string): Promise<ApiResponse<TotpCodeResponse>> {
    return invoke('get_totp_code', { credential_id: credentialId });
  },


  async searchCredentials(query: string): Promise<ApiResponse<Credential[]>> {
    return invoke('search_credentials', { query });
  },


  async generatePassword(length: number, includeSymbols: boolean): Promise<ApiResponse<string>> {
    return invoke('generate_password', { length, include_symbols: includeSymbols });
  },


  /** Full-options generator (used by the Generator panel; pure computation, no unlock needed) */
  async generatePasswordAdvanced(options: {
    length: number;
    include_lowercase: boolean;
    include_uppercase: boolean;
    include_numbers: boolean;
    include_symbols: boolean;
    pronounceable: boolean;
    count: number;
    words?: number;
  }): Promise<ApiResponse<GeneratedPasswords>> {
    return invoke('generate_password_advanced', options);
  },


  async toggleCredentialFavorite(credentialId: string): Promise<ApiResponse<Credential>> {
    return invoke('toggle_credential_favorite', { credential_id: credentialId });
  },


  /** Fetches a credential site's favicon on demand (the only outbound path; the backend refuses as a fallback when the flag is off) */
  async fetchCredentialFavicon(credentialId: string): Promise<ApiResponse<FaviconData>> {
    return invoke('fetch_credential_favicon', { credential_id: credentialId });
  },


  /** Bulk read of cached favicons (purely local; the backend silently returns an empty array when the flag is off) */
  async getFavicons(hosts: string[]): Promise<ApiResponse<FaviconData[]>> {
    return invoke('get_favicons', { hosts });
  },


  async deleteCredential(credentialId: string): Promise<ApiResponse<boolean>> {
    return invoke('delete_credential', { credential_id: credentialId });
  },


  async revealCredentialSecret(
    credentialId: string,
    field: SecretField,
    itemPassword?: string,
  ): Promise<ApiResponse<SecretReveal>> {
    return invoke('reveal_credential_secret', {
      request: { credential_id: credentialId, field, item_password: itemPassword ?? null },
    });
  },
};
