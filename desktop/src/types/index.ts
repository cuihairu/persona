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

export interface CreateCredentialRequest {
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url?: string;
  username?: string;
  credential_data: CredentialDataRequest;
}

export type CredentialDataRequest =
  | { type: 'Password'; password: string; email?: string; security_questions: SecurityQuestion[] }
  | { type: 'CryptoWallet'; wallet_type: string; mnemonic_phrase?: string; private_key?: string; public_key: string; address: string; network: string }
  | { type: 'SshKey'; private_key: string; public_key: string; key_type: string; passphrase?: string }
  | { type: 'ApiKey'; api_key: string; api_secret?: string; token?: string; permissions: string[]; expires_at?: string }
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

export type IdentityType = 'Personal' | 'Work' | 'Social' | 'Financial' | 'Gaming';
export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor';
export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export interface InitRequest {
  master_password: string;
  db_path?: string;
}
