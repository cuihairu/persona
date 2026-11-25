import React, { useCallback, useEffect, useState } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';
import { personaAPI } from '@/utils/api';
import type { SyncConflictEntry, SyncConflictVersion } from '@/types';

/** Whether two versions' credential data differ (whole-object comparison, no field interpretation — DR-4 atomic choice) */
const dataDiffers = (a: SyncConflictVersion, b: SyncConflictVersion): boolean =>
  JSON.stringify(a.snapshot?.data ?? null) !== JSON.stringify(b.snapshot?.data ?? null);

/** Single-version summary card: name + username/URL line + tombstone marker */
const VersionCard: React.FC<{
  version: SyncConflictVersion;
  badge: string | null;
  action?: React.ReactNode;
}> = ({ version, badge, action }) => {
  const { t } = useTranslation();
  return (
    <div
      className="border border-gray-200 dark:border-gray-700 rounded-lg p-3 text-sm"
      data-testid={`sync-conflict-version-${version.op_id}`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="font-medium text-gray-900 dark:text-gray-100 truncate">
            {version.snapshot?.name ?? t('settings.syncConflicts.deletedTitle')}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
            {version.snapshot?.username || version.snapshot?.url || ''}
          </p>
        </div>
        {badge && (
          <span
            className="flex-shrink-0 text-xs text-blue-600 dark:text-blue-400"
            data-testid="sync-conflict-badge"
          >
            {badge}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
        {t('settings.syncConflicts.versionMeta', {
          lamport: version.lamport,
          time: version.timestamp ?? '',
        })}
      </p>
      {action && <div className="mt-2 flex justify-end">{action}</div>}
    </div>
  );
};

/**
 * Conflict arbitration dialog (E2EE sync stage 3c): lists every pending entry,
 * comparing the primary (current version) against the copies side by side;
 * adopting any copy retires the remaining versions from the view (the data is
 * not lost, it just stops appearing in the arbitration view) and the list
 * refreshes immediately. A credential is an atomic whole — pick or drop, never
 * field-level merge.
 */
const SyncConflictsModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<SyncConflictEntry[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncConflictsList();
      if (resp.success && resp.data) {
        setEntries(resp.data);
        setLoadFailed(false);
      } else {
        setLoadFailed(true);
      }
    } catch {
      setLoadFailed(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Auto-close once arbitration has cleared every entry (no conflict left to resolve)
  useEffect(() => {
    if (entries !== null && !loadFailed && entries.length === 0) onClose();
  }, [entries, loadFailed, onClose]);

  const adopt = async (entry: SyncConflictEntry, version: SyncConflictVersion): Promise<void> => {
    setBusyId(version.op_id);
    try {
      const resp = await personaAPI.syncConflictResolve(entry.item_id, version.op_id);
      if (resp.success) {
        toast.success(t('settings.syncConflicts.resolved'));
        await refresh();
      } else {
        toast.error(resp.error || t('settings.syncConflicts.resolveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncConflicts.resolveFailed'));
    } finally {
      setBusyId(null);
    }
  };

  useEscapeToClose(true, onClose);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="sync-conflicts-modal"
      onMouseDown={(e) => {
        // Clicking the backdrop = deal with it later (the conflict stays unresolved, same rule as Esc/close)
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
              {t('settings.syncConflicts.title')}
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.syncConflicts.description')}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            aria-label={t('common.close')}
          >
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4 overflow-y-auto">
          {loadFailed && (
            <p className="text-sm text-red-600 dark:text-red-400" data-testid="sync-conflicts-error">
              {t('settings.syncConflicts.loadFailed')}
            </p>
          )}
          {entries === null && !loadFailed && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {t('settings.syncConflicts.loading')}
            </p>
          )}
          {entries?.map((entry) => (
            <div key={entry.item_id} data-testid={`sync-conflict-entry-${entry.item_id}`}>
              <div className="grid gap-3 sm:grid-cols-2">
                <VersionCard
                  version={entry.primary}
                  badge={t('settings.syncConflicts.currentBadge')}
                />
                {entry.copies.map((copy) => (
                  <VersionCard
                    key={copy.op_id}
                    version={copy}
                    badge={
                      copy.deleted
                        ? t('settings.syncConflicts.deletedBadge')
                        : dataDiffers(entry.primary, copy)
                          ? t('settings.syncConflicts.differsBadge')
                          : null
                    }
                    action={
                      <button
                        type="button"
                        data-testid={`sync-conflict-adopt-${copy.op_id}`}
                        onClick={() => void adopt(entry, copy)}
                        disabled={busyId !== null}
                        className="btn-secondary text-xs"
                      >
                        {busyId === copy.op_id
                          ? t('settings.saving')
                          : t('settings.syncConflicts.adopt')}
                      </button>
                    }
                  />
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end">
          <button type="button" onClick={onClose} className="btn-ghost">
            {t('settings.syncConflicts.keepCurrent')}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SyncConflictsModal;
