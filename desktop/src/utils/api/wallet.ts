import { invoke } from './invoke';

import type {
  ApiResponse,
  WalletListResponse,
  WalletAddressesResponse,
  WalletGenerateRequest,
  WalletGenerateResponse,
  WalletImportRequest,
  WalletExportRequest,
  WalletSummary,
  WalletAddress,
  CreateTransactionRequest,
  SignTransactionRequest,
  WalletTransaction,
  WalletSignedTransaction,
} from '@/types';

export const walletApi = {

  async walletList(identityId?: string): Promise<ApiResponse<WalletListResponse>> {
    if (identityId) {
      return invoke('wallet_list', { identity_id: identityId });
    }
    return invoke('wallet_list');
  },


  async walletListAddresses(walletId: string): Promise<ApiResponse<WalletAddressesResponse>> {
    return invoke('wallet_list_addresses', { wallet_id: walletId });
  },


  async walletGenerate(
    identityId: string,
    request: WalletGenerateRequest,
  ): Promise<ApiResponse<WalletGenerateResponse>> {
    return invoke('wallet_generate', { identity_id: identityId, request });
  },


  async walletImport(
    identityId: string,
    request: WalletImportRequest,
  ): Promise<ApiResponse<WalletSummary>> {
    return invoke('wallet_import', { identity_id: identityId, request });
  },


  async walletAddAddress(walletId: string, password: string): Promise<ApiResponse<WalletAddress>> {
    return invoke('wallet_add_address', { wallet_id: walletId, password });
  },


  async walletDelete(walletId: string): Promise<ApiResponse<boolean>> {
    return invoke('wallet_delete', { wallet_id: walletId });
  },


  async walletExport(request: WalletExportRequest): Promise<ApiResponse<string>> {
    return invoke('wallet_export', { request });
  },


  /** Validates a BIP-39 mnemonic (wordlist + checksum + word count); pure computation, never touches the database */
  async walletValidateMnemonic(phrase: string): Promise<ApiResponse<{ valid: boolean; word_count: number | null; error: string | null }>> {
    return invoke('wallet_validate_mnemonic', { phrase });
  },


  /** Generates a BIP-39 mnemonic (12/15/18/21/24 words); pure computation, never touches the database */
  async walletGenerateMnemonic(wordCount: number): Promise<ApiResponse<string>> {
    return invoke('wallet_generate_mnemonic', { word_count: wordCount });
  },


  /** Sets or replaces the wallet entry's item password (Argon2id-hashed and stored alongside the entry's ciphertext) */
  async walletSetItemPassword(
    credentialId: string,
    password: string,
    hint?: string,
  ): Promise<ApiResponse<boolean>> {
    return invoke('wallet_set_item_password', {
      credential_id: credentialId,
      password,
      hint: hint ?? null,
    });
  },


  /** Clears the wallet entry's item password (requires the current item password, so an unlocked session cannot just strip the protection) */
  async walletClearItemPassword(credentialId: string, itemPassword: string): Promise<ApiResponse<boolean>> {
    return invoke('wallet_clear_item_password', {
      credential_id: credentialId,
      item_password: itemPassword,
    });
  },


  // -------------------------------------------------------------------------
  // Wallet transactions
  // -------------------------------------------------------------------------

  async walletCreateTransaction(
    request: CreateTransactionRequest,
  ): Promise<ApiResponse<WalletTransaction>> {
    return invoke('wallet_create_transaction', { request });
  },


  async walletPendingTransactions(walletId: string): Promise<ApiResponse<WalletTransaction[]>> {
    return invoke('wallet_pending_transactions', { wallet_id: walletId });
  },


  async walletSignTransaction(
    request: SignTransactionRequest,
  ): Promise<ApiResponse<WalletSignedTransaction>> {
    return invoke('wallet_sign_transaction', { request });
  },
};
