import React from 'react';
import { useTranslation } from 'react-i18next';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import type { CustomField } from '@/types';

/** 自定义字段编辑器（gap #5 余项）：整表替换语义。读取失败只渲染错误
 *  ——读不到旧表还盲存会把既有字段清掉。行状态由父级持有，经 props 下发。 */
const CustomFieldsEditor: React.FC<{
  customFieldsError: string | null;
  customFields: CustomField[];
  revealedFieldIds: Set<string>;
  addCustomField: () => void;
  updateCustomField: (id: string, patch: Partial<CustomField>) => void;
  removeCustomField: (id: string) => void;
  toggleRevealField: (id: string) => void;
}> = ({
  customFieldsError,
  customFields,
  revealedFieldIds,
  addCustomField,
  updateCustomField,
  removeCustomField,
  toggleRevealField,
}) => {
  const { t } = useTranslation();

  return (
    customFieldsError ? (
  <p className="text-xs text-red-500 dark:text-red-400" data-testid="custom-fields-editor-error">
    {customFieldsError}
  </p>
) : (
  <div data-testid="custom-fields-editor">
    <div className="flex items-center justify-between mb-2">
      <label className="label">{t('credForm.customFields')}</label>
      <button
        type="button"
        onClick={addCustomField}
        className="btn-secondary text-xs"
        data-testid="custom-field-add"
      >
        {t('credForm.addCustomField')}
      </button>
    </div>
    {customFields.length === 0 ? (
      <p className="text-xs text-gray-500 dark:text-gray-400" data-testid="custom-fields-empty">
        {t('credForm.noCustomFields')}
      </p>
    ) : (
      <ul className="space-y-2">
        {customFields.map((field, index) => {
          const revealed = revealedFieldIds.has(field.id);
          const rowId = field.id || `row-${index}`;
          return (
            <li
              key={rowId}
              className="bg-gray-50 dark:bg-gray-800 rounded p-2 space-y-2"
              data-testid="custom-field-row"
            >
              <div className="flex gap-2">
                <input
                  type="text"
                  value={field.label}
                  onChange={(e) => updateCustomField(field.id, { label: e.target.value })}
                  className="input flex-1"
                  placeholder={t('credForm.customFieldLabelPlaceholder')}
                  data-testid={`custom-field-label-${rowId}`}
                />
                <select
                  value={field.type}
                  onChange={(e) =>
                    updateCustomField(field.id, {
                      type: e.target.value as CustomField['type'],
                    })
                  }
                  className="input w-auto"
                  aria-label={t('detail.customFields')}
                  data-testid={`custom-field-type-${rowId}`}
                >
                  <option value="text">{t('credForm.fieldTypeText')}</option>
                  <option value="concealed">{t('credForm.fieldTypeConcealed')}</option>
                  <option value="date">{t('credForm.fieldTypeDate')}</option>
                </select>
                <button
                  type="button"
                  onClick={() => removeCustomField(field.id)}
                  className="p-2 rounded text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                  aria-label={t('credForm.customFieldRemove')}
                  title={t('credForm.customFieldRemove')}
                  data-testid={`custom-field-remove-${rowId}`}
                >
                  ×
                </button>
              </div>
              <div className="flex gap-2 items-center">
                <div className="relative flex-1">
                  <input
                    type={
                      field.type === 'concealed' && !revealed
                        ? 'password'
                        : field.type === 'date'
                          ? 'date'
                          : 'text'
                    }
                    value={field.value}
                    onChange={(e) => updateCustomField(field.id, { value: e.target.value })}
                    className={field.type === 'concealed' ? 'input pr-10' : 'input'}
                    placeholder={t('credForm.customFieldValuePlaceholder')}
                    data-testid={`custom-field-value-${rowId}`}
                  />
                  {field.type === 'concealed' && (
                    <button
                      type="button"
                      onClick={() => toggleRevealField(field.id)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      aria-label={revealed ? t('detail.hideFieldValue') : t('detail.showFieldValue')}
                      title={revealed ? t('detail.hideFieldValue') : t('detail.showFieldValue')}
                      data-testid={`custom-field-reveal-${rowId}`}
                    >
                      {revealed ? (
                        <EyeSlashIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                      ) : (
                        <EyeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                      )}
                    </button>
                  )}
                </div>
              </div>
              <input
                type="text"
                value={field.section ?? ''}
                onChange={(e) => updateCustomField(field.id, { section: e.target.value })}
                className="input text-xs"
                placeholder={t('credForm.customFieldSectionPlaceholder')}
                data-testid={`custom-field-section-${rowId}`}
              />
            </li>
          );
        })}
      </ul>
    )}
  </div>
)
  );
};

export default CustomFieldsEditor;
