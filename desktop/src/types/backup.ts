/** Backup domain: evidence, export/restore/push outcomes, versions and remote deletion. */

/** Export record of one full-vault encrypted backup (mirror of core `BackupEvidence`).
 * Non-sensitive metadata; the backup passphrase is never written to disk. */
export interface BackupEvidence {
  /** When the export happened (RFC3339) */
  exported_at: string;
  /** Destination type: "file" (local file) / "server" (server ciphertext vault, later batch) */
  destination: string;
  /** Ciphertext size in bytes */
  size_bytes: number;
}

/** `backup_export_to_file` return (metadata reconcilable with BackupEvidence). */
export interface BackupExportOutcome {
  path: string;
  size_bytes: number;
  sha256: string;
  exported_at: string;
}

/** `backup_restore_from_file` return: path of the `.bak` copy of the original
 * vault left behind during the swap (null when there was no original vault —
 * a first restore on a fresh install has nothing to preserve). */
export interface BackupRestoreOutcome {
  backup_copy: string | null;
}

/** `backup_push_to_server` return (server-returned metadata + the local export timestamp). */
export interface BackupPushOutcome {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
  /** Server deduped because it matches the device's newest version sha256 (no new version produced) */
  deduplicated: boolean;
  exported_at: string;
}

/** One backup version in the server ciphertext vault (list view). */
export interface BackupVersionView {
  backup_id: string;
  device_name: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

/** `backup_delete_server_version` return (server 404s are idempotent, always true). */
export interface BackupServerDeleteOutcome {
  deleted: boolean;
}
