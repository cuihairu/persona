import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { open as openFileDialog, save as saveFileDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { BackupEvidence, BackupVersionView } from '@/types';

/** Byte count → human-readable size (KB/MB to one decimal; small files stay as a raw byte count). */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Default backup file name: persona-backup-2026-10-07T09-45-12.enc (local time). */
function defaultBackupName(): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, '-')
    .slice(0, 19);
  return `persona-backup-${stamp}.enc`;
}

/** Display time for a server version row (RFC3339 → local time). */
function formatWhen(rfc3339: string): string {
  const at = new Date(rfc3339);
  return Number.isNaN(at.getTime()) ? rfc3339 : at.toLocaleString();
}

/**
 * Self-rescue backup section (S5): encrypted full-database backup export to a
 * local file + restore from a backup file + server ciphertext vault
 * (S5-d: push / version list / restore / delete).
 *
 * The backup chain is independent of the master password (the main vault is
 * not decrypted); the backup passphrase is user-chosen and **never written to
 * disk, never leaves the device**; the risk disclosure is permanent (design
 * spec §6.5): lose the device = lose the vault, the only self-rescue is the
 * backup file. Export evidence (time/target/size, non-sensitive metadata) is
 * written by the backend into settings.backup and read back on mount to show
 * the last export here.
 *
 * The server ciphertext vault is **backup**, not sync: off by default, only
 * usable after the user explicitly configures persona-server (address +
 * token); the only thing that leaves the machine is the passphrase-encrypted
 * ciphertext, and neither the passphrase nor the master password takes part
 * in any network structure (scope spelled out in serverDescription). Push
 * requires unlock (the snapshot has to read the vault); list/restore works
 * while locked (rescue the vault from the lock screen).
 *
 * Restore (file and server share the semantics) is a replace operation:
 * second confirmation comes first; if the backend staged re-validation fails
 * the vault is untouched; after the vault-swap stage drains the service, the
 * frontend calls `finalizeVaultRestore` to clear memory and re-probe the
 * unlock state — App then switches to the unlock screen (the restored vault's
 * master password may differ); the `.bak` copy path is surfaced via toast
 * (the unlock screen has its own Toaster, in-section state is gone on
 * unmount).
 */
const BackupSection: React.FC = () => {
  const { t } = useTranslation();
  const { finalizeVaultRestore } = usePersonaService();
  const [evidence, setEvidence] = useState<BackupEvidence | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** sha256 of the latest export (shown on success so the user can reconcile it against the file fingerprint) */
  const [lastSha, setLastSha] = useState<string | null>(null);
  /** Restore area: selected backup file, restore passphrase, error and in-progress state (mutually exclusive with export) */
  const [restorePath, setRestorePath] = useState('');
  const [restorePass, setRestorePass] = useState('');
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  /** Server ciphertext vault: version list (null = never queried), error and per-operation in-progress state */
  const [serverItems, setServerItems] = useState<BackupVersionView[] | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);
  const [pushBusy, setPushBusy] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  /** Restore/delete are mutually exclusive per row (only one inline operation runs at a time) */
  const [rowBusyId, setRowBusyId] = useState<string | null>(null);
  /** Restore passphrase for a server version (the backup passphrase used when that version was pushed; independent of the file restore passphrase) */
  const [serverPass, setServerPass] = useState('');

  /** Vault-writing operations (export/file restore/push/server restore) are globally mutually exclusive; delete only touches the server */
  const anyWriter = busy || restoreBusy || pushBusy || rowBusyId !== null;

  const refreshEvidence = useCallback(async (): Promise<void> => {
    try {
      const resp = await personaAPI.getWorkspaceSettings();
      if (resp.success && resp.data) setEvidence(resp.data.backup);
    } catch {
      // On a state-read failure keep the old value (same convention as SyncGroupSection); do not interrupt the UI
    }
  }, []);

  useEffect(() => {
    void refreshEvidence();
  }, [refreshEvidence]);

  const refreshServerList = useCallback(async (): Promise<void> => {
    setListBusy(true);
    try {
      const resp = await personaAPI.backupListServerVersions();
      if (resp.success && resp.data) {
        setServerItems(resp.data);
        setServerError(null);
      } else {
        setServerError(resp.error ?? t('settings.backup.serverListFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverListFailed'));
    } finally {
      setListBusy(false);
    }
  }, [t]);

  const validate = (): string | null => {
    if (!passphrase || !confirm) return t('settings.backup.passRequired');
    if (passphrase.length < 8) return t('settings.backup.passTooShort');
    if (passphrase !== confirm) return t('settings.backup.passMismatch');
    return null;
  };

  const handleExport = async (): Promise<void> => {
    if (anyWriter) return;
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    const outputPath = await saveFileDialog({
      title: t('settings.backup.saveTitle'),
      defaultPath: defaultBackupName(),
    });
    if (!outputPath) return; // user cancelled
    setBusy(true);
    try {
      const resp = await personaAPI.backupExportToFile(outputPath, passphrase);
      if (resp.success && resp.data) {
        setLastSha(resp.data.sha256);
        setPassphrase('');
        setConfirm('');
        toast.success(t('settings.backup.exported'));
        await refreshEvidence();
      } else {
        setError(resp.error ?? t('settings.saveFailed'));
      }
    } catch {
      setError(t('settings.saveFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** Picking a backup file: cancel (null) or a dialog failure both keep the current state, retryable. */
  const handlePickRestoreFile = async (): Promise<void> => {
    try {
      const picked = await openFileDialog({
        title: t('settings.backup.restorePickTitle'),
        multiple: false,
      });
      if (typeof picked === 'string') setRestorePath(picked);
    } catch {
      // A dialog failure itself does not interrupt the UI (the user can just click again)
    }
  };

  const handleRestore = async (): Promise<void> => {
    if (anyWriter) return;
    if (!restorePath.trim()) {
      setRestoreError(t('settings.backup.restoreNeedFile'));
      return;
    }
    if (!restorePass) {
      setRestoreError(t('settings.backup.restoreNeedPass'));
      return;
    }
    if (!window.confirm(t('settings.backup.restoreConfirm'))) return;
    setRestoreError(null);
    setRestoreBusy(true);
    try {
      const resp = await personaAPI.backupRestoreFromFile(restorePath, restorePass);
      if (resp.success && resp.data) {
        setRestorePass('');
        // The .bak path only goes into the toast: once the vault-swap stage succeeds the unlock screen takes over, and in-section state is gone on unmount
        toast.success(
          resp.data.backup_copy
            ? t('settings.backup.restoredWithBak', { path: resp.data.backup_copy })
            : t('settings.backup.restored'),
          { duration: 10_000 },
        );
        await refreshEvidence();
        // Clear the old vault's in-memory identities/credentials + re-probe the unlock state (the service has already been taken down by the vault-swap stage)
        await finalizeVaultRestore();
      } else {
        setRestoreError(resp.error ?? t('settings.backup.restoreFailed'));
      }
    } catch (err) {
      setRestoreError(err instanceof Error ? err.message : t('settings.backup.restoreFailed'));
    } finally {
      setRestoreBusy(false);
    }
  };

  /** Push: reuses the export passphrase pair (same validate gate) — the snapshot is encrypted locally before it leaves the machine. */
  const handleServerPush = async (): Promise<void> => {
    if (anyWriter) return;
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    setPushBusy(true);
    try {
      const resp = await personaAPI.backupPushToServer(passphrase);
      if (resp.success && resp.data) {
        setPassphrase('');
        setConfirm('');
        toast.success(
          resp.data.deduplicated
            ? t('settings.backup.serverPushedDedup')
            : t('settings.backup.serverPushed'),
        );
        await refreshEvidence();
        await refreshServerList();
      } else {
        setServerError(resp.error ?? t('settings.backup.serverPushFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverPushFailed'));
    } finally {
      setPushBusy(false);
    }
  };

  /** Server version restore: same convention as file restore (confirmation first; a successful vault swap switches to the unlock screen). */
  const handleServerRestore = async (item: BackupVersionView): Promise<void> => {
    if (anyWriter || listBusy) return;
    if (!serverPass) {
      setServerError(t('settings.backup.restoreNeedPass'));
      return;
    }
    if (
      !window.confirm(
        t('settings.backup.serverRestoreConfirm', { created: formatWhen(item.created_at) }),
      )
    ) {
      return;
    }
    setServerError(null);
    setRowBusyId(item.backup_id);
    try {
      const resp = await personaAPI.backupRestoreFromServer(item.backup_id, serverPass);
      if (resp.success && resp.data) {
        setServerPass('');
        // The .bak path only goes into the toast: once the vault-swap stage succeeds the unlock screen takes over, and in-section state is gone on unmount
        toast.success(
          resp.data.backup_copy
            ? t('settings.backup.restoredWithBak', { path: resp.data.backup_copy })
            : t('settings.backup.restored'),
          { duration: 10_000 },
        );
        await refreshEvidence();
        await finalizeVaultRestore();
      } else {
        setServerError(resp.error ?? t('settings.backup.restoreFailed'));
      }
    } catch (err) {
      setServerError(err instanceof Error ? err.message : t('settings.backup.restoreFailed'));
    } finally {
      setRowBusyId(null);
    }
  };

  /** Deleting a server version: only touches the server-side copy (404 is idempotent); the local vault is never touched. */
  const handleServerDelete = async (item: BackupVersionView): Promise<void> => {
    if (rowBusyId !== null || listBusy) return;
    if (
      !window.confirm(
        t('settings.backup.serverDeleteConfirm', { created: formatWhen(item.created_at) }),
      )
    ) {
      return;
    }
    setServerError(null);
    setRowBusyId(item.backup_id);
    try {
      const resp = await personaAPI.backupDeleteServerVersion(item.backup_id);
      if (resp.success && resp.data) {
        toast.success(t('settings.backup.serverDeleted'));
        await refreshServerList();
      } else {
        setServerError(resp.error ?? t('settings.backup.serverDeleteFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverDeleteFailed'));
    } finally {
      setRowBusyId(null);
    }
  };

  return (
    <section className="mb-5" data-testid="backup-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.backup.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
        {t('settings.backup.description')}
      </p>
      <p
        className="text-xs text-red-600 dark:text-red-400 mb-2"
        data-testid="backup-disclosure"
      >
        {t('settings.backup.disclosure')}
      </p>

      <p className="text-sm text-gray-700 dark:text-gray-300 mb-2" data-testid="backup-evidence">
        {evidence
          ? t('settings.backup.lastExport', {
              time: new Date(evidence.exported_at).toLocaleString(),
              size: formatSize(evidence.size_bytes),
            })
          : t('settings.backup.neverExported')}
      </p>

      <div className="grid gap-2 max-w-md">
        <input
          type="password"
          data-testid="backup-passphrase"
          aria-label={t('settings.backup.passphrase')}
          placeholder={t('settings.backup.passphrase')}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoComplete="new-password"
          className="input"
        />
        <input
          type="password"
          data-testid="backup-passphrase-confirm"
          aria-label={t('settings.backup.passphraseConfirm')}
          placeholder={t('settings.backup.passphraseConfirm')}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          className="input"
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 dark:text-red-400 mt-2" data-testid="backup-error">
          {error}
        </p>
      )}

      <button
        type="button"
        onClick={() => void handleExport()}
        disabled={anyWriter}
        data-testid="backup-export-button"
        className="btn-secondary mt-3 inline-flex items-center gap-1.5 text-sm"
      >
        {busy ? t('settings.backup.exporting') : t('settings.backup.exportNow')}
      </button>

      {lastSha && (
        <p
          className="text-xs text-gray-400 dark:text-gray-500 mt-1 break-all"
          data-testid="backup-sha"
        >
          {t('settings.backup.sha256', { sha: lastSha })}
        </p>
      )}

      {/* Restore area (S5 restore-from-file): a replace operation — permanent warning + second confirmation first.
          Runs mutually exclusive with export (shared vault-lock operation cadence, avoiding concurrent reads/writes of the vault file) */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700" data-testid="backup-restore">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.backup.restoreTitle')}
        </p>
        <p
          className="text-xs text-red-600 dark:text-red-400 mb-2"
          data-testid="backup-restore-disclosure"
        >
          {t('settings.backup.restoreDisclosure')}
        </p>

        <div className="flex gap-2 max-w-md">
          <input
            readOnly
            data-testid="backup-restore-path"
            aria-label={t('settings.backup.restorePick')}
            placeholder={t('settings.backup.restorePathPlaceholder')}
            value={restorePath}
            className="input"
          />
          <button
            type="button"
            onClick={() => void handlePickRestoreFile()}
            disabled={anyWriter}
            data-testid="backup-restore-pick"
            className="btn-secondary shrink-0 text-sm"
          >
            {t('settings.backup.restorePick')}
          </button>
        </div>

        <div className="grid gap-2 max-w-md mt-2">
          <input
            type="password"
            data-testid="backup-restore-passphrase"
            aria-label={t('settings.backup.restorePassphrase')}
            placeholder={t('settings.backup.restorePassphrase')}
            value={restorePass}
            onChange={(e) => setRestorePass(e.target.value)}
            autoComplete="off"
            className="input"
          />
        </div>

        {restoreError && (
          <p
            className="text-sm text-red-600 dark:text-red-400 mt-2"
            data-testid="backup-restore-error"
          >
            {restoreError}
          </p>
        )}

        <button
          type="button"
          onClick={() => void handleRestore()}
          disabled={anyWriter}
          data-testid="backup-restore-button"
          className="btn-secondary mt-3 inline-flex items-center gap-1.5 text-sm"
        >
          {restoreBusy ? t('settings.backup.restoring') : t('settings.backup.restoreNow')}
        </button>
      </div>

      {/* Server ciphertext vault (S5-d): off by default — only usable after persona-server is explicitly configured;
          only the passphrase-encrypted ciphertext leaves the machine (scope in serverDescription). Push needs unlock,
          list/restore works while locked (rescue the vault from the lock screen); restore follows the file-restore convention, confirmation first */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700" data-testid="backup-server">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.backup.serverTitle')}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
          {t('settings.backup.serverDescription')}
        </p>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void handleServerPush()}
            disabled={anyWriter}
            data-testid="backup-server-push"
            className="btn-secondary inline-flex items-center gap-1.5 text-sm"
          >
            {pushBusy ? t('settings.backup.serverPushing') : t('settings.backup.serverPushNow')}
          </button>
          <button
            type="button"
            onClick={() => void refreshServerList()}
            disabled={listBusy || anyWriter}
            data-testid="backup-server-refresh"
            className="btn-secondary inline-flex items-center gap-1.5 text-sm"
          >
            {listBusy ? t('settings.backup.serverListing') : t('settings.backup.serverRefresh')}
          </button>
        </div>

        <input
          type="password"
          data-testid="backup-server-passphrase"
          aria-label={t('settings.backup.serverRestorePassphrase')}
          placeholder={t('settings.backup.serverRestorePassphrase')}
          value={serverPass}
          onChange={(e) => setServerPass(e.target.value)}
          autoComplete="off"
          className="input mt-2 max-w-md"
        />

        {serverError && (
          <p
            className="text-sm text-red-600 dark:text-red-400 mt-2"
            data-testid="backup-server-error"
          >
            {serverError}
          </p>
        )}

        <div className="mt-2" data-testid="backup-server-list">
          {serverItems !== null && serverItems.length === 0 && (
            <p
              className="text-xs text-gray-500 dark:text-gray-400"
              data-testid="backup-server-empty"
            >
              {t('settings.backup.serverEmpty')}
            </p>
          )}
          {(serverItems ?? []).map((item) => (
            <div
              key={item.backup_id}
              data-testid="backup-server-item"
              className="flex flex-wrap items-center gap-2 py-1"
            >
              <span className="text-xs text-gray-700 dark:text-gray-300 break-all">
                {t('settings.backup.serverRow', {
                  device: item.device_name,
                  time: formatWhen(item.created_at),
                  size: formatSize(item.size_bytes),
                })}
              </span>
              <button
                type="button"
                onClick={() => void handleServerRestore(item)}
                disabled={anyWriter || listBusy}
                data-testid="backup-server-restore"
                className="btn-secondary text-xs"
              >
                {t('settings.backup.serverRestore')}
              </button>
              <button
                type="button"
                onClick={() => void handleServerDelete(item)}
                disabled={rowBusyId !== null || listBusy}
                data-testid="backup-server-delete"
                className="btn-secondary text-xs"
              >
                {t('settings.backup.serverDelete')}
              </button>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default BackupSection;
