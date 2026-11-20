import React from 'react';
import { useTranslation } from 'react-i18next';
import { formatLabel, type WalletExportFormat } from './walletExport';

interface ExportWalletModalProps {
  /** 目标钱包名；null 时文案走通用提示 */
  walletName: string | null;
  /** 可用格式与限制提示由父层按钱包派生 */
  formats: WalletExportFormat[];
  restrictionHint: string | null;
  format: WalletExportFormat;
  /** 切格式时父层复位导出输出与 includePrivate */
  onFormatChange: (format: WalletExportFormat) => void;
  includePrivate: boolean;
  onIncludePrivateChange: (value: boolean) => void;
  password: string;
  onPasswordChange: (value: string) => void;
  /** 导出结果（json 走文件下载不展示在这里） */
  output: string | null;
  onPerform: () => void;
  onClose: () => void;
}

const needsPassword = (format: WalletExportFormat, includePrivate: boolean): boolean =>
  format === 'mnemonic' ||
  format === 'private_key' ||
  format === 'wif' ||
  format === 'keystore' ||
  (format === 'json' && includePrivate);

/** 导出钱包弹窗：格式选择 + 限制提示 + 敏感格式密码门 + 结果展示 */
const ExportWalletModal: React.FC<ExportWalletModalProps> = ({
  walletName,
  formats,
  restrictionHint,
  format,
  onFormatChange,
  includePrivate,
  onIncludePrivateChange,
  password,
  onPasswordChange,
  output,
  onPerform,
  onClose,
}) => {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold mb-4">{t('wallet.exportTitle')}</h3>
        <div className="text-sm text-gray-600 dark:text-gray-300 mb-4">
          {walletName ? (
            <>
              {t('wallet.exportWalletPrefix')}<span className="font-medium">{walletName}</span>
            </>
          ) : (
            t('wallet.exportWalletGeneric')
          )}
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.format')}</label>
            <select
              value={format}
              onChange={(e) => onFormatChange(e.target.value as WalletExportFormat)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
            >
              {formats.map((f) => (
                <option key={f} value={f}>
                  {formatLabel(t, f)}
                </option>
              ))}
            </select>
          </div>

          {restrictionHint && (
            <div className="rounded-lg bg-amber-50 dark:bg-amber-500/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-300">
              {restrictionHint}
            </div>
          )}

          {format === 'json' && (
            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <input
                type="checkbox"
                checked={includePrivate}
                onChange={(e) => onIncludePrivateChange(e.target.checked)}
              />
              {t('wallet.includePrivate')}
            </label>
          )}

          {needsPassword(format, includePrivate) && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.walletPassword')}</label>
              <input
                type="password"
                value={password}
                onChange={(e) => onPasswordChange(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                placeholder={t('wallet.passwordPlaceholder')}
              />
            </div>
          )}

          {output && format !== 'json' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.exportedData')}</label>
              <textarea
                readOnly
                value={output}
                className="w-full h-28 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm"
              />
              <button
                onClick={() => {
                  navigator.clipboard.writeText(output).catch(() => {});
                }}
                className="whitespace-nowrap mt-2 w-full px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
              >
                {t('common.copy')}
              </button>
            </div>
          )}

          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="whitespace-nowrap flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
            >
              {t('common.close')}
            </button>
            <button
              onClick={onPerform}
              className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
            >
              {t('wallet.export')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExportWalletModal;
