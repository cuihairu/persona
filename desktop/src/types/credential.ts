/** Credential domain: identities/credentials/attachments/history/custom fields, passkeys and reveal, quick access and fill confirmation. */

/** Payload of the persona://passkey-approval event (corresponds to PasskeyApprovalRequest on the Rust side) */
export interface PasskeyApprovalRequest {
  request_id: string;
  /** Operation name on the bridge wire: "passkey_create" | "passkey_assert" */
  operation: string;
  /** Relying party to verify by hand (null for assert: the rp lives on the vault item) */
  rp_id: string | null;
  /** Full page origin that issued the request */
  origin: string;
  /** Account name at create time */
  user_name: string | null;
  /** UUID of the vault item for assert */
  item_id: string | null;
}

/**
 * Quick Access status surface (mirrors Rust quick_access::QuickAccessStatus).
 * configured (the DB truth) and registered (the actual grab result) are kept
 * separate: when the grab fails, the former has a value while the latter is
 * null, so the UI can show "not in effect + reason".
 */
export interface QuickAccessStatus {
  enabled: boolean;
  configured_accelerator: string;
  registered_accelerator: string | null;
  error: string | null;
}

/**
 * Generator hotkey status surface (mirrors Rust quick_access::GeneratorStatus;
 * same semantics as QuickAccessStatus: configured = the DB truth, registered =
 * the actual grab result).
 */
export interface GeneratorStatus {
  enabled: boolean;
  configured_accelerator: string;
  registered_accelerator: string | null;
  error: string | null;
}

/** Payload of the persona://quick-access-open-credential event (floating panel → main window cross-window jump) */
export interface QuickAccessOpenCredential {
  identity_id: string;
  credential_id: string;
}

/** Desktop fill injection target status (fill_target_status command response; snake_case matched field-for-field) */
export interface FillTargetStatus {
  supported: boolean;
  /** A target that has been captured and whose fingerprint (window/process/class name/executable) is still unchanged */
  ready: boolean;
  target_title: string | null;
  /** Executable name of the target application (e.g. "notepad.exe"; shown on the confirmation surface) */
  target_app: string | null;
  /** Currently valid snapshot identifier (P1 confirmation binding): the injection request must return it verbatim */
  snapshot_id: string | null;
}

/** Desktop fill injection result (desktop_fill_credential command response; snake_case matched field-for-field) */
export interface DesktopFillResult {
  username_filled: boolean;
  password_filled: boolean;
  target_title: string;
  warning: string | null;
}

/** Passkey list entry (never contains private key fields) */
export interface Passkey {
  id: string;
  identity_id: string;
  rp_id: string;
  rp_name?: string;
  user_handle_b64: string;
  user_name?: string;
  user_display_name?: string;
  credential_id_b64: string;
  uv_initialized: boolean;
  export_allowed: boolean;
  created_at: string;
  last_used_at?: string;
}

export interface CreatePasskeyRequest {
  identity_id: string;
  rp_id: string;
  origin: string;
  /** clientDataJSON as base64(UTF-8 JSON) */
  client_data_json_b64: string;
  user_handle_b64?: string;
  user_name?: string;
  user_display_name?: string;
  user_verification: boolean;
}

export interface PasskeyCreationResponse {
  passkey: Passkey;
  /** The `none`-format attestation object, base64 encoded */
  attestation_object_b64: string;
}

/** Sensitive field names (the field set of Rust reveal_credential_secret) */
export type SecretField =
  | 'password'
  | 'security_questions'
  | 'ssh_private_key'
  | 'ssh_passphrase'
  | 'api_key'
  | 'api_secret'
  | 'token'
  | 'wallet_private_key'
  | 'wallet_mnemonic'
  | 'wallet_bip39_passphrase'
  | 'raw_data';

export interface SecretReveal {
  field: SecretField;
  value: string;
}

export interface IdentityExport {
  exported_at: string;
  data: { identity: Identity; credentials: Credential[] };
}

// ---------------------------------------------------------------------------
// Wallet transactions (correspond to the serde output of Rust TransactionRequest/SignedTransaction)
// ---------------------------------------------------------------------------

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
  /** Travel mode marker: leaves this device together with the identity on enter */
  travel_marked: boolean;
}

// ---------------------------------------------------------------------------
// Travel mode (correspond to the serde output of Rust TravelStatus/TravelCounts)
// ---------------------------------------------------------------------------

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

/**
 * Structured custom fields (1Password-aligned, mirrors Rust SerializableCustomField).
 * The whole table is sealed with the per-item key and stored in credential.metadata,
 * so reading requires an unlock; the value of a `concealed` row is plaintext
 * decrypted from the ciphertext, masked only in the UI layer.
 */
export interface CustomField {
  id: string;
  label: string;
  value: string;
  type: 'text' | 'concealed' | 'date';
  section: string | null;
}

/** Field-level diff (mirrors Rust SerializableFieldChange; snapshot JSON is never sent back) */
export interface FieldChangeEntry {
  field: string;
  old_value: string;
  new_value: string;
}

/** Credential history row (mirrors Rust SerializableChangeHistory; newest version first) */
export interface CredentialHistoryEntry {
  id: string;
  entity_id: string;
  change_type: 'created' | 'updated' | 'deleted' | 'restored' | 'archived' | 'activated' | 'deactivated';
  version: number;
  timestamp: string;
  changes: FieldChangeEntry[];
  /** Whether this version can be restored (deletion rows have no new_state and cannot) */
  restorable: boolean;
}

/** Attachment metadata (mirrors Rust SerializableAttachment; the blob content is never sent back in full) */
export interface AttachmentEntry {
  id: string;
  credential_id: string;
  filename: string;
  mime_type: string;
  size: number;
  is_encrypted: boolean;
  content_hash: string;
  created_at: string;
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

/** Metadata edit request (the item type is immutable; payload edits go through UpdateCredentialDataRequest) */
export interface UpdateCredentialRequest {
  id: string;
  name: string;
  security_level?: string;
  url?: string;
  username?: string;
  notes?: string;
  tags?: string[];
}

/** Ciphertext payload edit request (sensitive: re-seals with the original item key + passes the sensitive-operation gate) */
export interface UpdateCredentialDataRequest {
  credential_id: string;
  credential_data: CredentialDataRequest;
}

export type CredentialDataRequest =
  | { type: 'Password'; password: string; email?: string; security_questions: SecurityQuestion[] }
  | { type: 'CryptoWallet'; wallet_type: string; mnemonic_phrase?: string; private_key?: string; public_key: string; address: string; network: string; bip39_passphrase?: string }
  | { type: 'SshKey'; private_key: string; public_key: string; key_type: string; passphrase?: string }
  | { type: 'ApiKey'; api_key: string; api_secret?: string; token?: string; permissions: string[]; expires_at?: string }
  | { type: 'TwoFactor'; secret_key: string; issuer: string; account_name: string; algorithm: string; digits: number; period: number; hotp?: boolean; initial_counter?: number }
  | { type: 'GameToken'; provider: string; secret_key: string; issuer: string; account_name: string; url?: string }
  | { type: 'SecureNote'; note: string }
  | {
      type: 'Identity';
      first_name: string;
      last_name: string;
      username?: string;
      email?: string;
      phone?: string;
      birthday?: string;
      address?: string;
      id_number?: string;
      passport_number?: string;
      driver_license?: string;
      tax_id?: string;
      organization?: string;
      job_title?: string;
    }
  | {
      type: 'SoftwareLicense';
      license_key: string;
      version?: string;
      publisher?: string;
      purchase_date?: string;
      order_number?: string;
      support_email?: string;
      download_url?: string;
      seats?: number;
      valid_until?: string;
    }
  | { type: 'Raw'; data: number[] };

export interface SecurityQuestion {
  question: string;
  answer: string;
}

export type IdentityType = 'Personal' | 'Work' | 'Social' | 'Financial' | 'Gaming';

export type CredentialType = 'Password' | 'CryptoWallet' | 'SshKey' | 'ApiKey' | 'BankCard' | 'GameAccount' | 'ServerConfig' | 'Certificate' | 'TwoFactor' | 'GameToken' | 'SecureNote' | 'Identity' | 'SoftwareLicense';

export type SecurityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/**
 * 1Password-style credential categories (sidebar "Categories" group + list filtering).
 * Each category maps to a set of credential_type values (see CATEGORY_TYPES in
 * sidebarNav.ts); passkeys are not among them — they live in a separate passkeys
 * table and are managed by the { kind: 'passkeys' } view.
 */
export type CredentialCategory =
  | 'passwords'
  | 'secure_notes'
  | 'api_keys'
  | 'ssh_keys'
  | 'software_licenses'
  | 'identity_documents'
  | 'crypto_wallets'
  | 'game_tokens';

/** Single-select filter state of the sidebar category tree (defaults to { kind: 'all' }; not persisted to localStorage) */
export type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'category'; value: CredentialCategory }
  | { kind: 'identity'; value: string } // identity id
  | { kind: 'tag'; value: string }
  // Special views (excluded from credential filtering; render their own panel directly)
  | { kind: 'statistics' }
  | { kind: 'sshAgent' }
  | { kind: 'wallets' }
  | { kind: 'watchtower' }
  | { kind: 'passkeys' }
  | { kind: 'generator' };

/**
 * Pending credential selection to inject (used by global search to jump across
 * identities): QuickSearch writes it, and CredentialList consumes and clears it
 * once the target identity's credentials have loaded.
 */
export type PendingCredentialSelection = { identityId: string; credentialId: string };
