/** Account domain: binding, SRP registration/challenge, passkey options, session and device listing, travel mode, Connect tokens. */

/** Account-domain binding (mirror of core `AccountBinding`). Non-sensitive
 * identity only; the token secret lives in the OS keyring and never crosses
 * into the frontend. */
export interface AccountBinding {
  account_id: string;
  username: string;
  /** Device name of this machine's SRP credential */
  device_name?: string | null;
}

/** Travel mode status (read without unlocking and without the travel passphrase) */
export interface TravelStatus {
  /** The travel_mode flag from settings */
  active: boolean;
  /** When it was entered (RFC3339; written by enter, cleared by exit) */
  entered_at: string | null;
  /** Whether `<db dir>/travel.persenc` exists */
  sidecar_exists: boolean;
  /** active && !sidecar_exists: the data container is gone — data is lost */
  inconsistent: boolean;
}

/** Counts reported after an enter/exit completes */
export interface TravelCounts {
  identities: number;
  credentials: number;
  attachments: number;
  passkeys: number;
  wallets: number;
  history_rows: number;
  files: number;
}

/** Connect listener running status (settings page rendering + automation switch decision) */
export interface ConnectServerStatus {
  running: boolean;
  /** Actual listener port (not running = null; port 0 = the real value after OS allocation) */
  port: number | null;
}

/** Token grant scope (three dimensions: empty identity list = all, type enumeration, verb; read is the only legal starting value) */
export interface ConnectTokenScope {
  identities: string[];
  /** snake_case type vocabulary (password/api_key/totp/…; passkey/wallet/ssh are never grantable) */
  item_types: string[];
  verbs: string[];
}

/** Token management list entry (the hash never leaves the store; only the fingerprint is shown) */
export interface ConnectTokenView {
  id: string;
  label: string;
  /** First 8 bytes of SHA-256 in hex, for manual verification */
  fingerprint: string;
  scope: ConnectTokenScope;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** Success response for creation: the plaintext token is shown this once and cannot be viewed again once the dialog is closed */
export interface ConnectTokenCreatedView {
  token: string;
  info: ConnectTokenView;
}

/* account system (M2) */
export interface AccountRegistrationResponse {
  account_id: string;
  username: string;
  display_name?: string;
}

export interface AccountSrpRegisterResponse {
  device_name: string;
}

export interface AccountSrpChallengeResponse {
  session_id: string;
  salt: string;
  server_public: string;
}

export interface AccountSrpVerifyResponse {
  server_proof: string;
  token: string;
  expires_in_secs: number;
}

/** passkeys/create-options response (the WebAuthn creation options carrying a
 * server-issued challenge; kept separate from the local vault's passkey types —
 * this is the RP-side account domain). */
export interface AccountPasskeyCreationOptions {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: string; alg: number }[];
  authenticatorSelection: {
    authenticatorAttachment?: string;
    userVerification?: string;
    residentKey?: string;
  };
  timeout: number;
  attestation: string;
}

/** passkeys/login-options response: the server challenge obtained in the first step of the login ceremony. */
export interface AccountPasskeyLoginOptions {
  challenge: string;
  rp_id: string;
}

/** Passkey assertion evidence for the sessions endpoint (all fields are base64url encoded). */
export interface AccountPasskeyAssertion {
  credential_id: string;
  client_data_json: string;
  origin: string;
  authenticator_data: string;
  signature: string;
}

/** Evidence for the sessions endpoint: either the SRP 15-minute token or a passkey assertion, never both. */
export type AccountSessionEvidence =
  | { srp_token: string }
  | { passkey_assertion: AccountPasskeyAssertion };

export interface AccountDeviceInfo {
  id: string;
  device_id: string;
  device_name: string;
  public_key: string;
  status: string;
}

export interface AccountDevicesList {
  devices: AccountDeviceInfo[];
}

export interface AccountRecoveryCodes {
  codes: string[];
}

export interface AccountSessionInfo {
  session_token: string;
  expires_in_secs: number;
}

/* end account system */
