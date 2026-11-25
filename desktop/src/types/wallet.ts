/** Wallet domain: address book, transaction construction/signing, generation/import-export. */

/** Transaction awaiting signature (returned by wallet_create_transaction) */
export interface WalletTransaction {
  id: string;
  wallet_id: string;
  network: string;
  from_address: string;
  to_address: string;
  /** String in the smallest unit (wei / satoshi / lamport) */
  amount: string;
  fee: string;
  gas_price?: string;
  gas_limit?: number;
  nonce?: number;
  memo?: string;
  required_signatures: number;
  created_at: string;
  expires_at?: string;
  metadata: Record<string, string>;
}

export interface WalletSignature {
  [key: string]: unknown;
}

/** Signed transaction (returned by wallet_sign_transaction) */
export interface WalletSignedTransaction {
  id: string;
  request: WalletTransaction;
  signatures: WalletSignature[];
  raw_signed_transaction: number[];
  transaction_hash: string;
  signed_at: string;
  broadcast_status: string;
}

export interface CreateTransactionRequest {
  wallet_id: string;
  to_address: string;
  amount: string;
  fee: string;
  gas_price?: string;
  gas_limit?: number;
  nonce?: number;
  memo?: string;
  expires_in_minutes?: number;
}

export interface SignTransactionRequest {
  transaction_id: string;
  password: string;
  /** Explicit second confirmation after the dialog showed the address-poisoning warning (the backend refuses to sign without the ack) */
  confirm_poisoning_check?: boolean;
}

export interface WalletSummary {
  id: string;
  name: string;
  network: string;
  wallet_type: string;
  balance: string;
  address_count: number;
  watch_only: boolean;
  security_level: string;
  created_at: string;
  updated_at: string;
}

export interface WalletAddress {
  address: string;
  address_type: string;
  index: number;
  used: boolean;
  balance: string;
  derivation_path?: string | null;
}

export interface WalletListResponse {
  wallets: WalletSummary[];
}

export interface WalletAddressesResponse {
  addresses: WalletAddress[];
}

export interface WalletGenerateRequest {
  name: string;
  network: string;
  wallet_type: 'hd';
  password: string;
  address_count?: number;
}

export interface WalletGenerateResponse {
  wallet_id: string;
  name: string;
  network: string;
  mnemonic: string;
  first_address: string;
}

export interface WalletImportRequest {
  name: string;
  network: string;
  import_type: 'mnemonic' | 'private_key' | 'wif' | 'keystore';
  data: string;
  password: string;
  address_count?: number;
}

export interface WalletExportRequest {
  wallet_id: string;
  format: 'json' | 'mnemonic' | 'xpub' | 'private_key' | 'wif' | 'keystore';
  include_private: boolean;
  password?: string;
}
