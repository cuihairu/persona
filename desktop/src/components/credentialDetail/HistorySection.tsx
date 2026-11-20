import React from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronDownIcon, ChevronUpIcon, ClockIcon } from '@heroicons/react/24/outline';
import type { CredentialHistoryEntry } from '@/types';

/** 变更历史区（原 JSX 块平移）：懒加载时间线与版本恢复入口由父级驱动。 */
const HistorySection: React.FC<{
  isHistoryOpen: boolean;
  setIsHistoryOpen: React.Dispatch<React.SetStateAction<boolean>>;
  history: CredentialHistoryEntry[] | null;
  isRestoringVersion: boolean;
  handleRestoreVersion: (entry: CredentialHistoryEntry) => Promise<void>;
}> = ({
  isHistoryOpen,
  setIsHistoryOpen,
  history,
  isRestoringVersion,
  handleRestoreVersion,
}) => {
  const { t } = useTranslation();

// Item history（1Password 对齐）：懒加载的变更时间线
  return (
    <div className="border-t pt-3">
      <button
        type="button"
        onClick={() => setIsHistoryOpen(!isHistoryOpen)}
        data-testid="history-toggle"
        className="whitespace-nowrap flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-100"
      >
        <ClockIcon className="w-4 h-4" />
        {t('detail.itemHistory')}
        {isHistoryOpen ? (
          <ChevronUpIcon className="w-4 h-4" />
        ) : (
          <ChevronDownIcon className="w-4 h-4" />
        )}
      </button>

      {isHistoryOpen && (
        <div className="mt-2" data-testid="history-list">
          {history === null ? (
            <p className="text-xs text-gray-400 dark:text-gray-500">{t('common.loading')}</p>
          ) : history.length === 0 ? (
            <p className="text-xs text-gray-400 dark:text-gray-500">
              {t('detail.noChanges')}
            </p>
          ) : (
            <ul className="space-y-2">
              {history.map((entry) => (
                <li
                  key={entry.id}
                  className="text-xs bg-gray-50 dark:bg-gray-800 rounded p-2"
                  data-testid="history-entry"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-gray-700 dark:text-gray-200">
                      v{entry.version} · {entry.change_type}
                    </span>
                    <span className="flex items-center gap-2 text-gray-400 dark:text-gray-500">
                      {entry.restorable && (
                        <button
                          type="button"
                          data-testid="history-restore"
                          disabled={isRestoringVersion}
                          onClick={() => handleRestoreVersion(entry)}
                          className="px-1.5 py-0.5 rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                        >
                          {t('detail.restoreVersion')}
                        </button>
                      )}
                      {new Date(entry.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {entry.changes.length > 0 && (
                    <ul className="mt-1 space-y-0.5 font-mono text-gray-600 dark:text-gray-300">
                      {entry.changes.map((change) => (
                        <li key={change.field}>
                          {change.field}:{' '}
                          <span className="text-red-500 dark:text-red-400">
                            {change.old_value || t('detail.emptyValue')}
                          </span>{' '}
                          →{' '}
                          <span className="text-green-600 dark:text-green-400">
                            {change.new_value || t('detail.emptyValue')}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}
          {history !== null && history.length > 0 && (
            <p className="mt-2 text-[10px] text-gray-400 dark:text-gray-500">
              {t('detail.restoreHint')}
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default HistorySection;
