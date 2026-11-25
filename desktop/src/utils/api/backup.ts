import { invoke } from './invoke';

import type {
  ApiResponse,
  BackupExportOutcome,
  BackupRestoreOutcome,
  BackupPushOutcome,
  BackupVersionView,
  BackupServerDeleteOutcome,
} from '@/types';

export const backupApi = {

  /** Exports an encrypted full-database backup to a local file (the S5 self-rescue hatch):
   * passphrase-encrypted, the main database is never decrypted.
   * On success settings.backup holds the export evidence (the server's truth is
   * the returned outcome). */
  async backupExportToFile(
    path: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupExportOutcome>> {
    return invoke('backup_export_to_file', { request: { path, passphrase } });
  },


  /** Restores the whole database from a local backup file (second batch of the S5
   * self-rescue hatch; same semantics as the CLI `restore --file`).
   * A wrong passphrase / corrupt file fails at the staged re-verification stage —
   * the existing database and session are untouched; once the database has been
   * swapped, the backend service is torn down and the caller must follow up with
   * `checkServiceStatus` to drive the UI back to the unlock screen (the restored
   * database's master password may differ from the current session's). */
  async backupRestoreFromFile(
    path: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupRestoreOutcome>> {
    return invoke('backup_restore_from_file', { request: { path, passphrase } });
  },


  /** Pushes an encrypted full-database backup to the server ciphertext vault (S5-d).
   * The snapshot goes out over the network only after local encryption finishes;
   * the passphrase and master password never leave this machine; on success
   * settings.backup holds the destination=server evidence. */
  async backupPushToServer(
    passphrase: string,
  ): Promise<ApiResponse<BackupPushOutcome>> {
    return invoke('backup_push_to_server', { request: { passphrase } });
  },


  /** Lists the backup versions in the server ciphertext vault (newest first). No unlock needed — rescuing the database from the lock screen must still allow reading the list. */
  async backupListServerVersions(
    limit?: number,
  ): Promise<ApiResponse<BackupVersionView[]>> {
    return invoke('backup_list_server_versions', {
      request: { limit: limit ?? null },
    });
  },


  /** Restores the whole database from the server ciphertext vault. No unlock needed
   * (same treatment as a file restore from the lock screen); once the database has
   * been swapped, the backend service is torn down and the caller must follow up
   * with `checkServiceStatus` to drive the UI back to the unlock screen. */
  async backupRestoreFromServer(
    backupId: string,
    passphrase: string,
  ): Promise<ApiResponse<BackupRestoreOutcome>> {
    return invoke('backup_restore_from_server', {
      request: { backup_id: backupId, passphrase },
    });
  },


  /** Deletes a backup version on the server (idempotent: already deleted counts as success). */
  async backupDeleteServerVersion(
    backupId: string,
  ): Promise<ApiResponse<BackupServerDeleteOutcome>> {
    return invoke('backup_delete_server_version', {
      request: { backup_id: backupId },
    });
  },
};