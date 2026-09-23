import React, { useCallback, useEffect, useState } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';
import { personaAPI } from '@/utils/api';
import type { SyncConflictEntry, SyncConflictVersion } from '@/types';

/** 两版本凭据数据是否不同（整体对比，不解释字段——DR-4 原子取舍） */
const dataDiffers = (a: SyncConflictVersion, b: SyncConflictVersion): boolean =>
  JSON.stringify(a.snapshot?.data ?? null) !== JSON.stringify(b.snapshot?.data ?? null);

/** 单版本摘要卡：名称 + 用户名/URL 行 + tombstone 标记 */
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
 * 冲突裁决弹窗（E2EE sync 阶段 3c）：列出全部待裁决条目，主位（当前
 * 版本）与副本并排对比；采纳任一副本后其余版本淘汰出视图（数据不丢，
 * 只是不再出现在裁决视图），列表即时刷新。凭据是原子整体——只做取舍
 * 不做字段级合并。
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

  // 裁决清空全部条目后自动关窗（无冲突可裁决）
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
