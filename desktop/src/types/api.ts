/** Platform API surface: error codes and the unified response envelope, auto-lock/biometric/feature flags, tray and utility payloads. */

/**
 * Backend error codes (correspond to map_persona_error in desktop/src-tauri/src/error.rs).
 * REAUTH_REQUIRED: a sensitive operation needs re-authentication → the frontend opens ReauthModal.
 * SERVICE_LOCKED: the service is locked → the frontend goes back to the unlock screen.
 * PASSWORD_CHANGE_REQUIRED: policy requires rotating the master password → the frontend opens the forced-change dialog.
 * BIOMETRIC_RESET: the biometric-hosted entry does not exist or has been
 * self-deleted as stale → the unlock screen hides the fingerprint button and
 * suggests signing in with the master password.
 * BIOMETRIC_CANCELLED: the user pressed cancel in the biometric prompt → return
 * silently to the unlock screen, keep the fingerprint button, and show no error
 * toast (design doc §3.4).
 * TRAVEL_MODE_ACTIVE: travel mode is in effect and incompatible operations such
 * as changing the password are refused → tell the user to exit travel mode first.
 * CONCURRENT_CONFLICT: two exclusive operations raced (the epoch optimistic lock
 * on group key rotation missed because another device rotated first) → say the
 * sync state has changed and ask the user to retry the rotation.
 * ITEM_PASSWORD_REQUIRED / ITEM_PASSWORD_WRONG: the per-item password guard for
 * wallet entries (reveal seed material missing/mismatched) → RevealSecretButton
 * appends an inline password field.
 * FILL_TARGET_SNAPSHOT_REQUIRED / FILL_TARGET_DISCARDED / FILL_TARGET_CHANGED:
 * desktop autofill confirmation binding (P1) — the request carries no snapshot_id
 * / the target was discarded after confirmation (the floating panel collapsed and
 * cleared its slot) / the target was recaptured and replaced after confirmation
 * → report it honestly and have the user run the confirmation flow again.
 * SYNC_SERVER_UNREACHABLE / SYNC_CLOUD_FOLDER_UNAVAILABLE: transport-layer I/O
 * failures during a sync cycle (CLOUD_DRIVE_SYNC §9.4) — the server side is
 * unreachable / the cloud-drive directory is unavailable (missing, deleted, or the
 * OS cloud placeholder not materialized). The two have different fixes, so the
 * frontend branches on the code and does not collapse them into one generic
 * "sync failed".
 */
export type ApiErrorCode =
  | 'REAUTH_REQUIRED'
  | 'SERVICE_LOCKED'
  | 'PASSWORD_CHANGE_REQUIRED'
  | 'BIOMETRIC_RESET'
  | 'BIOMETRIC_CANCELLED'
  | 'TRAVEL_MODE_ACTIVE'
  | 'CONCURRENT_CONFLICT'
  | 'ITEM_PASSWORD_REQUIRED'
  | 'ITEM_PASSWORD_WRONG'
  | 'FILL_TARGET_SNAPSHOT_REQUIRED'
  | 'FILL_TARGET_DISCARDED'
  | 'FILL_TARGET_CHANGED'
  | 'SYNC_SERVER_UNREACHABLE'
  | 'SYNC_CLOUD_FOLDER_UNAVAILABLE';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  error_code?: ApiErrorCode;
}

/** Biometric unlock status (mirrors Rust BiometricStatusResponse; enabled is only
 * the metadata bit meaning "this vault has biometric unlock configured" — the real
 * hosted master password never leaves the keyring; wrap_tier is the backend's
 * three-tier wrapping level: "hardware-bound" / "os-gate" / "unsupported") */
export interface BiometricStatus {
  available: boolean;
  enabled: boolean;
  platform: string;
  wrap_tier: string;
}

/** Payload of the persona://auto-lock event (corresponds to SerializableAutoLockEvent on the Rust side) */
export type AutoLockEventPayload =
  | { type: 'lock_pending'; session_id: string; seconds_remaining: number }
  | { type: 'locked'; session_id: string; reason: string }
  | { type: 'unlocked'; session_id: string }
  | { type: 'activity'; session_id: string };

/** Auto-lock configuration (mirrors Rust AutoLockConfigRequest; 0 = disabled) */
export interface AutoLockConfigRequest {
  inactivity_timeout_secs: number;
  absolute_timeout_secs?: number;
  require_reauth_sensitive?: boolean;
}

export interface AutoLockStatus {
  is_unlocked: boolean;
  session_locked: boolean;
  needs_reauth: boolean;
  inactivity_timeout_secs: number;
}

/** Advanced feature switches (mirrors Rust FeatureFlags; 1Password-style, all off by default, opted in from the settings page) */
export interface FeatureFlags {
  /** SSH agent (browsers/terminals fetch the key via socket and sign) */
  ssh_agent: boolean;
  /** Wallet panel */
  wallet: boolean;
  /** Passkey management and approval server */
  passkeys: boolean;
  /** On-demand fetching and display of site favicons (the only outbound path = the Fetch icon button in the detail panel) */
  fetch_favicons: boolean;
}

/** Cached site icon (mirrors Rust SerializableFavicon; data is the base64 image bytes) */
export interface FaviconData {
  host: string;
  mime_type: string;
  data: string;
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

/** Three theme preference levels; 'system' follows prefers-color-scheme */
export type ThemePreference = 'system' | 'light' | 'dark';

export interface InitRequest {
  master_password: string;
  db_path?: string;
}

// ---------------------------------------------------------------------------
// Local automation for Connect (corresponds to the serde output of Rust connect_server/commands)
// ---------------------------------------------------------------------------

/** `generate_password_advanced` response: candidate passwords plus the estimated
 * entropy and character-pool size for display (a display hint, not a security
 * guarantee; drawn from the same character set as the core generator). */
export interface GeneratedPasswords {
  passwords: string[];
  entropy_bits: number;
  pool_size: number;
}

/** `ssh_agent_integration_status` return (mirrors Rust SshIntegrationStatus):
 *  three-state snapshot of the IdentityAgent anchor block in ~/.ssh/config */
/** Tray right-click menu labels (the i18n locale table is the source of truth; Rust only renders, it stores no strings) */
export interface TrayLocaleLabels {
  open: string;
  quickAccess: string;
  generator: string;
  lock: string;
  quit: string;
}
