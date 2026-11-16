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


  /** BIP-39 助记词校验（词表+校验和+词数），纯计算不触库 */
  async walletValidateMnemonic(phrase: string): Promise<ApiResponse<{ valid: boolean; word_count: number | null; error: string | null }>> {
    return invoke('wallet_validate_mnemonic', { phrase });
  },


  /** 生成 BIP-39 助记词（12/15/18/21/24 词），纯计算不触库 */
  async walletGenerateMnemonic(wordCount: number): Promise<ApiResponse<string>> {
    return invoke('wallet_generate_mnemonic', { word_count: wordCount });
  },


  /** 设置/更换钱包条目独立密码（Argon2id hash 后随条目密文存储） */
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


  /** 清除钱包条目独立密码（需当前条目密码验证，防解锁态直接摘除保护） */
  async walletClearItemPassword(credentialId: string, itemPassword: string): Promise<ApiResponse<boolean>> {
    return invoke('wallet_clear_item_password', {
      credential_id: credentialId,
      item_password: itemPassword,
    });
  },


  // -------------------------------------------------------------------------
  // 钱包交易
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
