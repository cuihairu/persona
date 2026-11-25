/** Sync domain: configuration, devices, pairing/join outcomes, conflict and rotation reports. */

import type { AccountBinding } from './account';
import type { BackupEvidence } from './backup';
import type { FeatureFlags } from './api';

/** Client configuration for the sync server (persona-server Events API) (mirrors Rust SyncConfig) */
export interface SyncConfig {
  enabled: boolean;
  server_url: string;
  /**
   * The backend always returns an empty string — the real token lives in the
   * OS keyring and is never read back over IPC.
   * Submitting an empty string = keep the token already in the keyring
   * (the frontend does not echo it, so it never sits in memory).
   */
  server_token: string;
  /**
   * Local path of the sync folder for the cloud-drive transport (Phase 2)
   * (the local sync directory of iCloud Drive / Dropbox / Google Drive).
   * Not a secret, stored in the settings JSON; null = not configured.
   * Only meaningful when `sync_transport === 'cloud'`.
   */
  cloud_drive_dir?: string | null;
  /** Which transport carries the command stream: `server` (persona-server
   * HTTP, default) / `cloud` (file exchange in a cloud-drive directory).
   * A missing key in older JSON is defaulted to `server` by backend serde. */
  sync_transport?: 'server' | 'cloud';
}

/** E2EE sync device management (mirrors Rust SyncDeviceStatus / SyncJoinOutcome / SyncDeviceView) */
export interface SyncDeviceStatus {
  joined: boolean;
  /** The keyring has a record but it fails to parse — the UI guides a re-join */
  corrupted: boolean;
  device_id: string | null;
  device_name: string | null;
}

export interface SyncJoinOutcome {
  device_id: string;
  device_name: string;
  /** Registered but not yet authorized (authorize it from another authorized device) */
  pending: boolean;
}

export interface SyncDeviceView {
  id: string;
  device_name: string;
  created_at: string;
  /** Free-form remark from the device owner (writable by that device only, readable by all) */
  remark: string;
  authorized: boolean;
  this_device: boolean;
}

/** `sync_now` return: counts from one round of sync (mirrors Rust SyncNowReport) */
export interface SyncNowReport {
  /** Remote ops newly pulled and stored */
  pulled: number;
  /** Items materialized into the main database (new rows or updates) */
  materialized: number;
  /** Items currently awaiting conflict resolution (open the conflict dialog when > 0) */
  conflicts: number;
  /** Items held back because their identity is not synced yet (filled in next round) */
  pending_identity: number;
  /** Local ops pushed out */
  pushed: number;
  /** Pre-existing credentials backfilled into the oplog this round (non-zero usually only on the first sync) */
  backfilled: number;
}

/** `sync_rotate` return: counts from one group key rotation (mirrors Rust SyncRotateReport) */
export interface SyncRotateReport {
  /** Credentials re-wrapped under the new group key */
  rewrapped: number;
  /** Entries skipped due to legacy format / decryption failure (still only the old group ciphertext after rotation) */
  skipped: number;
  /** Total ops pushed across the whole rotation */
  pushed: number;
}

/** Sync snapshot plaintext (mirrors Rust SyncItemSnapshot; used for conflict comparison display, data is not expanded) */
export interface SyncItemSnapshotView {
  identity_id: string;
  name: string;
  credential_type: string;
  security_level: string;
  url: string | null;
  username: string | null;
  notes: string | null;
  tags: string[];
  is_favorite: boolean;
  is_active: boolean;
  /** Credential data (serde shape of Rust CredentialData; the frontend only compares it as a whole) */
  data: unknown;
}

/** A single version of a conflicted entry (mirrors Rust desktop SyncConflictVersion) */
export interface SyncConflictVersion {
  /** Op id passed to sync_conflict_resolve when adopting */
  op_id: string;
  /** Device id that produced this version (compared against this device's device_id to mark "this device") */
  device_id: string;
  lamport: number;
  /** Display only, does not participate in resolution ordering (LWW only looks at lamport + device) */
  timestamp: string | null;
  /** Tombstone version: adopting = delete the entry; no snapshot in that case */
  deleted: boolean;
  snapshot: SyncItemSnapshotView | null;
}

/** Conflict view for one entry (mirrors Rust desktop SyncConflictEntry) */
export interface SyncConflictEntry {
  item_id: string;
  /** Current version (the LWW primary — doing nothing keeps it) */
  primary: SyncConflictVersion;
  /** Copies awaiting resolution (each can be adopted; adopting eliminates the other versions) */
  copies: SyncConflictVersion[];
}

/** Full workspace settings (mirrors Rust WorkspaceSettings; returned by the settings command) */
export interface WorkspaceSettings {
  encryption_enabled: boolean;
  auto_backup_hours: number;
  backup_retention_count: number;
  session_timeout_seconds: number;
  require_confirmation: boolean;
  default_identity_type: string;
  features: FeatureFlags;
  /** Master password validity period (days); null = never expires (default; null when the key is missing from older JSON) */
  password_expiry_days: number | null;
  /** UI language ("zh-CN" / "en"); null = the default base language zh-CN */
  locale: string | null;
  /** Optional sync server configuration (null when the key is missing from older JSON) */
  sync: SyncConfig | null;
  /** Sync-method switches (cross-device sync on by default, account sync off by default; missing keys in older JSON fall back to the defaults).
   * Only controls whether the settings-page entries are available — off ≠ leaving the sync group, it neither deletes the keyring nor triggers network traffic. */
  sync_methods: { cross_device_sync: boolean; account_sync: boolean };
  /** Whether the Quick Access global hotkey is enabled (default true; true when the key is missing from older JSON) */
  quick_access_enabled: boolean;
  /** Quick Access global hotkey binding string; null = the desktop's platform default binding */
  quick_access_hotkey: string | null;
  /** Account-domain binding (null = not bound; account features are off by default, binding is an explicit action) */
  account: AccountBinding | null;
  /** Recovery-phrase backup evidence (null = never exported on this machine; null when the key is missing from older JSON) */
  backup: BackupEvidence | null;
}

/** Sync-group pairing (mirrors Rust SyncPairingCreateOutcome): what the host presents */
export interface SyncPairingCreateOutcome {
  /** Dynamic code (9-digit Crockford base32, verified manually with the other side) */
  code: string;
  /** Invite string persona-pair-1.{b64url payload} (handed over via QR / clipboard) */
  invite_link: string;
  /** Relay session id (locates the session for poll / cancel) */
  session_id: string;
  /** Remaining validity of the relay session (seconds) */
  expires_in_secs: number;
}

/** `sync_group_pairing_poll` return (mirrors Rust SyncPairingPollOutcome) */
export interface SyncPairingPollOutcome {
  completed: boolean;
  /** Host-side 6-digit short fingerprint (compared against what the guest displays) */
  fingerprint: string | null;
}

/** `sync_group_join_begin` return (mirrors Rust SyncJoinBeginOutcome) */
export interface SyncJoinBeginOutcome {
  /** Guest-side 6-digit short fingerprint (compared with the host side; confirm only when they match) */
  fingerprint: string;
  /** Dynamic code from the invite string (verified against the code typed by hand) */
  code: string;
  /** Relay session id (locates the session for confirm / cancel) */
  session_id: string;
}

/** `sync_status` return (mirrors Rust SyncStatusInfo): watermark snapshot of group sync */
export interface SyncStatusReport {
  /** Newest group version (max seq in the server command stream; 0 for an empty group) */
  headSeq: number;
  /** This device's synced watermark (the seq it has pulled; 0 if never pulled) */
  localWatermark: number;
  /** How many commands behind the group */
  behind: number;
  /** Commands produced locally but not yet pushed to the group */
  pendingPush: number;
  /** Last successful sync (RFC3339; null = never synced) */
  lastSyncAt: string | null;
}
