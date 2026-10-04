import React from 'react';
import { ShieldCheckIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

/** 披露面：audit = 同步服务器开关（审计事件上报）；e2ee = 加入端到端同步；
 * account = 注册/绑定 persona-server 账号（账号材料外发面） */
export type DataScope = 'audit' | 'e2ee' | 'account';

interface DataScopeConsentModalProps {
  scope: DataScope;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * 隐私红线「默认关闭、显式开启、开启时明示数据范围」的披露确认弹窗：
 * 逐条列出该通道服务器会看到什么 / 永不出本机什么，用户显式确认后才
 * 放行——audit 面确认后展开同步服务器配置表单，e2ee 面确认后才执行
 * sync_join。取消 / Esc / 点空白一律不放行（开关保持关闭、不加入）。
 */
const DataScopeConsentModal: React.FC<DataScopeConsentModalProps> = ({
  scope,
  onConfirm,
  onCancel,
}) => {
  const { t } = useTranslation();
  const base =
    scope === 'audit'
      ? 'settings.sync.consent'
      : scope === 'e2ee'
        ? 'settings.syncDevices.consent'
        : 'settings.account.consent';
  // 文案为固定数组（i18n 资源内联，模块加载即在位）；returnObjects 取整组
  const sees = t(`${base}.sees`, { returnObjects: true }) as string[];
  const notSees = t(`${base}.no`, { returnObjects: true }) as string[];

  useEscapeToClose(true, onCancel);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="data-scope-modal"
      data-scope={scope}
      onMouseDown={(e) => {
        // 点空白 = 不放行，与 Esc / 关闭按钮同口径
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-lg mx-4"
        role="dialog"
        aria-modal="true"
        aria-label={t(`${base}.title`)}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="flex min-w-0 items-center gap-2 text-base font-semibold text-gray-900 dark:text-gray-100">
            <ShieldCheckIcon className="h-5 w-5 shrink-0 text-primary-600 dark:text-primary-400" />
            <span className="truncate">{t(`${base}.title`)}</span>
          </h2>
          <button
            type="button"
            onClick={onCancel}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            aria-label={t('common.close')}
          >
            <XMarkIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <div className="space-y-3 px-5 py-4">
          <p className="text-sm text-gray-600 dark:text-gray-300">{t(`${base}.intro`)}</p>
          <div data-testid="data-scope-sees">
            <p className="text-xs font-semibold tracking-wide text-gray-500 dark:text-gray-400">
              {t(`${base}.seesTitle`)}
            </p>
            <ul className="mt-1 list-inside list-disc space-y-1 text-sm text-gray-700 dark:text-gray-300">
              {sees.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          <div data-testid="data-scope-not-sees">
            <p className="text-xs font-semibold tracking-wide text-gray-500 dark:text-gray-400">
              {t(`${base}.noTitle`)}
            </p>
            <ul className="mt-1 list-inside list-disc space-y-1 text-sm text-gray-700 dark:text-gray-300">
              {notSees.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
          {scope === 'audit' && (
            <p className="text-xs text-gray-500 dark:text-gray-400">{t(`${base}.note`)}</p>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-gray-200 px-5 py-4 dark:border-gray-700">
          <button type="button" onClick={onCancel} className="btn-ghost" data-testid="data-scope-cancel">
            {t(`${base}.cancel`)}
          </button>
          <button type="button" onClick={onConfirm} className="btn-primary" data-testid="data-scope-confirm">
            {t(`${base}.confirm`)}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DataScopeConsentModal;
