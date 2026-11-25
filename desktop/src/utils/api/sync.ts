import { invoke } from './invoke';

import type {
  ApiResponse,
  SyncConfig,
  SyncConflictEntry,
  SyncDeviceStatus,
  SyncDeviceView,
  SyncJoinBeginOutcome,
  SyncJoinOutcome,
  SyncNowReport,
  SyncPairingCreateOutcome,
  SyncPairingPollOutcome,
  SyncRotateReport,
  SyncStatusReport,
  ConnectServerStatus,
  ConnectTokenScope,
  ConnectTokenView,
  ConnectTokenCreatedView,
  WorkspaceSettings,
} from '@/types';

export const syncApi = {

  // ---------------------------------------------------------------------
  // Local Connect automation (secrets automation)
  // ---------------------------------------------------------------------

  /** Start the Connect listener (binds 127.0.0.1; port null = OS-assigned) */
  async connectServerStart(port?: number | null): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_start', { port: port ?? null });
  },


  /** Stop the Connect listener (idempotent) */
  async connectServerStop(): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_stop');
  },


  /** Connect listener running status */
  async connectServerStatus(): Promise<ApiResponse<ConnectServerStatus>> {
    return invoke('connect_server_status');
  },


  /** Create a Connect token (sensitive operation: reauth gate; the plaintext is returned only once) */
  async connectTokenCreate(
    label: string,
    scope: ConnectTokenScope,
  ): Promise<ApiResponse<ConnectTokenCreatedView>> {
    return invoke('connect_token_create', { label, scope });
  },


  /** Token management list (includes revoked ones; the hash never leaves the store) */
  async connectTokenList(): Promise<ApiResponse<ConnectTokenView[]>> {
    return invoke('connect_token_list');
  },


  /** Revoke a Connect token (idempotent, takes effect immediately) */
  async connectTokenRevoke(id: string): Promise<ApiResponse<boolean>> {
    return invoke('connect_token_revoke', { id });
  },


  /** Narrow write of the sync server configuration; an empty server_token = the backend keeps the old token (the real value lives in the OS keyring) */
  async setSyncConfig(config: SyncConfig): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_config', {
      enabled: config.enabled,
      server_url: config.server_url,
      server_token: config.server_token,
    });
  },


  /**
   * Narrow write of the sync transport choice (whether the command stream runs
   * over persona-server or over a cloud-drive directory).
   *
   * Semantic red line: `cloud` must carry a non-empty directory (validated on
   * the backend; an empty directory is rejected); a `null` directory = keep the
   * old value (switching back to server and then to cloud needs no re-selection).
   * On success the full settings are returned so the caller refreshes the truth
   * (no optimistic flip).
   */
  async setSyncTransport(
    syncTransport: 'server' | 'cloud',
    cloudDriveDir: string | null = null,
  ): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_transport', { syncTransport, cloudDriveDir });
  },


  /**
   * Narrow write of the sync-method switches (cross-device sync / account sync,
   * independent of each other).
   *
   * Semantic red line: this only writes the preference (settings.sync_methods) —
   * it **never deletes the keyring and never triggers network traffic**;
   * turning a method off ≠ leaving the sync group. On success the full settings
   * are returned so the caller refreshes the truth.
   */
  async setSyncMethods(
    cross_device_sync: boolean,
    account_sync: boolean,
  ): Promise<ApiResponse<WorkspaceSettings>> {
    return invoke('set_sync_methods', { cross_device_sync, account_sync });
  },


  /** Whether a sync token is stored in the OS keyring (read-only without unlocking; the real value never crosses IPC) */
  async syncTokenPresent(): Promise<ApiResponse<boolean>> {
    return invoke('sync_token_present');
  },


  /** E2EE sync device identity status (purely local keyring, no unlock needed) */
  async syncDeviceStatus(): Promise<ApiResponse<SyncDeviceStatus>> {
    return invoke('sync_device_status');
  },


  /** Join E2EE sync (generates the device keypair and registers it with the server; a failure leaves no half state) */
  async syncJoin(deviceName: string): Promise<ApiResponse<SyncJoinOutcome>> {
    return invoke('sync_join', { deviceName });
  },


  /** Leave sync (local cleanup first; server-side revocation is best effort) */
  async syncLeave(): Promise<ApiResponse<boolean>> {
    return invoke('sync_leave');
  },


  /** Sync-group device list (includes authorization status and the this-device flag) */
  async syncListDevices(): Promise<ApiResponse<SyncDeviceView[]>> {
    return invoke('sync_list_devices');
  },


  /** Set this device's remark (locked server-side by token ownership; empty/whitespace-only = clear; returns the normalized remark) */
  async syncSetDeviceRemark(remark: string): Promise<ApiResponse<string>> {
    return invoke('sync_set_device_remark', { remark });
  },


  /** Authorize the target device (unwraps this device's envelope and re-wraps for the target public key; fails closed when this device is not authorized) */
  async syncAuthorize(targetDeviceId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_authorize', { targetDeviceId });
  },


  /** Revoke a device (idempotent; revoking yourself goes through syncLeave) */
  async syncRevoke(targetDeviceId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_revoke', { targetDeviceId });
  },


  /** Sync now: backfill the existing data, then the pull/materialize/push cycle; returns the count summary */
  async syncNow(): Promise<ApiResponse<SyncNowReport>> {
    return invoke('sync_now');
  },


  /** Sync status snapshot: newest group version / local watermark / behind N / pending push N / last sync time (read-only) */
  async syncStatus(): Promise<ApiResponse<SyncStatusReport>> {
    return invoke('sync_status');
  },


  /** Group key rotation: swap the envelope and re-wrap everything (the security operation that actually closes the loop after revoking a device) */
  async syncRotate(): Promise<ApiResponse<SyncRotateReport>> {
    return invoke('sync_rotate');
  },


  /** All conflict entries awaiting resolution (primary + decrypted snapshot copies; read-only) */
  async syncConflictsList(): Promise<ApiResponse<SyncConflictEntry[]>> {
    return invoke('sync_conflicts_list');
  },


  /** Resolve a conflict: adopt one copy (the remaining versions drop out of the resolution view, no data is lost) */
  async syncConflictResolve(itemId: string, adoptOpId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_conflict_resolve', { itemId, adoptOpId });
  },


  /** Sync group: whether this vault has joined (keyring group key entry, read-only without unlocking) */
  async syncGroupStatus(): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_status');
  },


  /** Sync-group pairing: the host presents the code (dynamic code + invite string; the session suspends waiting for the other side to join) */
  async syncGroupPairingCreate(): Promise<ApiResponse<SyncPairingCreateOutcome>> {
    return invoke('sync_group_pairing_create');
  },


  /**
   * Sync-group pairing: the host waits for the guest to join (blocks until
   * completion or a 90s timeout; cancellation goes through
   * syncGroupPairingCancel, and once the relay mailbox is deleted this call
   * returns with an error)
   */
  async syncGroupPairingPoll(sessionId: string): Promise<ApiResponse<SyncPairingPollOutcome>> {
    return invoke('sync_group_pairing_poll', { sessionId });
  },


  /** Sync-group pairing: cancel the session (shared by host/guest; idempotent, cleans up the relay mailbox best effort) */
  async syncGroupPairingCancel(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_pairing_cancel', { sessionId });
  },


  /** Sync-group join: the guest parses the invite string and starts pairing, returning the short fingerprint (to compare with the host side) */
  async syncGroupJoinBegin(inviteLink: string): Promise<ApiResponse<SyncJoinBeginOutcome>> {
    return invoke('sync_group_join_begin', { inviteLink });
  },


  /** Sync-group join: confirm joining once the fingerprint comparison passes (the group key lands in the keyring) */
  async syncGroupJoinConfirm(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_join_confirm', { sessionId });
  },


  /** Sync-group join: cancel (fingerprint mismatch / give up; idempotent) */
  async syncGroupJoinCancel(sessionId: string): Promise<ApiResponse<boolean>> {
    return invoke('sync_group_join_cancel', { sessionId });
  },
};