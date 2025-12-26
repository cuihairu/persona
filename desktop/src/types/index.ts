export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface Identity {
  id: string;
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
  ssh_key?: string;
  gpg_key?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  is_active: boolean;
}

export interface Credential {
  id: string;
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url?: string;
  username?: string;
  notes?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  last_accessed?: string;
  is_active: boolean;
  is_favorite: boolean;
}

export interface CredentialData {
  credential_type: string;
  data: any;
}

export interface CreateIdentityRequest {
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
}

export interface UpdateIdentityRequest {
  id: string;
  name: string;
  identity_type: string;
  description?: string;
  email?: string;
  phone?: string;
  tags?: string[];
}

export interface CreateCredentialRequest {
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url?: string;
  username?: string;
  notes?: string;
  tags?: string[];
  credential_data: CredentialDataRequest;
}

export type CredentialDataRequest =
  | { type: 'Password'; password: string; email?: string; security_questions: SecurityQuestion[] }
  | { type: 'CryptoWallet'; wallet_type: string; mnemonic_phrase?: string; private_key?: string; public_key: string; address: string; network: string }
  | { type: 'SshKey'; private_key: string; public_key: string; key_type: string; passphrase?: string }
  | { type: 'ApiKey'; api_key: string; api_secret?: string; token?: string; permissions: string[]; expires_at?: string }
  | { type: 'TwoFactor'; secret_key: string; issuer: string; account_name: string; algorithm: string; digits: number; period: number }
  | { type: 'Raw'; data: number[] };

export interface SecurityQuestion {
  question: string;
  answer: string;
}

export interface SshAgentStatus {
  running: boolean;
  socket_path?: string;
  pid?: number;
  key_count?: number;
  state_dir: string;
}

export interface SshAgentKey {
  id: string;
  identity_id: string;
  identity_name: string;
  name: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Statistics {
  total_identities: number;
  total_credentials: number;
  active_credentials: number;
  favorite_credentials: number;
  credential_types: Record<string, number>;
  security_levels: Record<string, number>;
}

export interface TotpCodeResponse {
  code: string;
  remaining_seconds: number;
  period: number;
  digits: number;
  algorithm: string;
  issuer: string;
  account_name: string;
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
  import_type: 'mnemonic' | 'private_key';
  data: string;
  password: string;
  address_count?: number;
}

export interface WalletExportRequest {
  wallet_id: string;
  format: 'json' | 'mnemonic' | 'xpub' | 'private_key';
  include_private: boolean;
  password?: string;
}

export type IdentityType = 'Personal' | 'Work' | 'Social' | 'Financial' | 'Gaming';
export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor';
export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export interface InitRequest {
  master_password: string;
  db_path?: string;
}
