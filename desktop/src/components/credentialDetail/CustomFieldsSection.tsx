import React from 'react';
import { useTranslation } from 'react-i18next';
import { DocumentDuplicateIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import type { CustomField } from '@/types';

/** 自定义字段区（原条件 JSX 块平移）：concealed 行打码/揭示由父级持有；
 *  加载中/空表整节隐藏的判定与原文一致，经 fragment 原样返回。 */
const CustomFieldsSection: React.FC<{
  customFields: CustomField[] | null;
  customFieldsError: string | null;
  revealedFieldIds: Set<string>;
  setRevealedFieldIds: React.Dispatch<React.SetStateAction<Set<string>>>;
  onCopy: (text: string, label: string) => void;
}> = ({
  customFields,
  customFieldsError,
  revealedFieldIds,
  setRevealedFieldIds,
  onCopy,
}) => {
  const { t } = useTranslation();

// 自定义字段（1Password 对齐）：per-item key 密封的整表，读失败如实显示；
// 加载中/空表整节隐藏（不闪空标题）
  return (
    <>
    {((customFields !== null && customFields.length > 0) || customFieldsError) && (
      <div className="border-t pt-3" data-testid="custom-fields-section">
        <span className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300">
          <DocumentDuplicateIcon className="w-4 h-4" />
          {t('detail.customFields')}
        </span>
        {customFieldsError ? (
          <p className="mt-2 text-xs text-red-500 dark:text-red-400" data-testid="custom-fields-error">
            {customFieldsError}
          </p>
        ) : customFields === null ? null : (
          <ul className="mt-2 space-y-1.5">
            {customFields.map((field) => {
              const revealed = revealedFieldIds.has(field.id);
              return (
                <li
                  key={field.id}
                  className="flex items-center justify-between gap-2 text-xs bg-gray-50 dark:bg-gray-800 rounded p-2"
                  data-testid="custom-field-entry"
                >
                  <div className="min-w-0">
                    <p
                      className="truncate font-medium text-gray-700 dark:text-gray-200"
                      data-testid="custom-field-label"
                    >
                      {field.label}
                    </p>
                    <p
                      className={clsx(
                        'font-mono break-all',
                        field.type === 'concealed' && !revealed
                          ? 'tracking-widest select-none'
                          : 'text-gray-600 dark:text-gray-300'
                      )}
                      data-testid={`custom-field-value-${field.id}`}
                    >
                      {field.type === 'concealed' && !revealed
                        ? '••••••••'
                        : field.value}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {field.type === 'concealed' && (
                      <button
                        type="button"
                        onClick={() =>
                          setRevealedFieldIds((prev) => {
                            const next = new Set(prev);
                            if (next.has(field.id)) next.delete(field.id);
                            else next.add(field.id);
                            return next;
                          })
                        }
                        title={revealed ? t('detail.hideFieldValue') : t('detail.showFieldValue')}
                        aria-label={revealed ? t('detail.hideFieldValue') : t('detail.showFieldValue')}
                        data-testid={`custom-field-reveal-${field.id}`}
                        className="p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                      >
                        {revealed ? (
                          <EyeSlashIcon className="w-4 h-4" />
                        ) : (
                          <EyeIcon className="w-4 h-4" />
                        )}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onCopy(field.value, field.label)}
                      title={t('detail.copyLabel', { name: field.label })}
                      aria-label={t('detail.copyLabel', { name: field.label })}
                      data-testid={`custom-field-copy-${field.id}`}
                      className="p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                    >
                      <DocumentDuplicateIcon className="w-4 h-4" />
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    )}
    </>
  );
};

export default CustomFieldsSection;
