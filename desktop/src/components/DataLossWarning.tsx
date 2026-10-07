import React from 'react';
import { useTranslation } from 'react-i18next';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { useDataLossRisk } from '@/hooks/useDataLossRisk';

/** 滚动到目标设置节（自救动作的跳转；目标节都在同一 GeneralPane 里）。 */
function scrollToSection(testid: string): void {
  document
    .querySelector(`[data-testid="${testid}"]`)
    ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/**
 * 数据丢失强提示（S5-b，设计稿 §6.5 硬要求）。
 *
 * - `strong`：同步组「首次启用」场景的在位强提示（挂在入组成功块内），
 *   文案明示两种救法（④）：再连一台设备，或立即导出加密备份。
 * - `banner`：设置页顶部常驻横幅（②红点常驻，不做一次性弹窗）。
 *
 * 档位与解除全部由 [`useDataLossRisk`] 驱动：第二台设备到位或已导出
 * 备份自动解除（③）；账号绑定降一档（有找回路径）。
 */
const DataLossWarning: React.FC<{ variant?: 'strong' | 'banner' }> = ({
  variant = 'banner',
}) => {
  const { t } = useTranslation();
  const { loading, level } = useDataLossRisk();

  if (loading || level === 'none') return null;
  const high = level === 'high';

  if (variant === 'strong') {
    return (
      <div
        role={high ? 'alert' : 'status'}
        data-testid="data-loss-strong"
        className={`mt-3 rounded-lg border p-4 ${
          high
            ? 'border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-950/40'
            : 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40'
        }`}
      >
        <p
          className={`flex items-center gap-1.5 text-sm font-semibold ${
            high ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'
          }`}
          data-testid="data-loss-strong-title"
        >
          <ExclamationTriangleIcon className="w-4 h-4" aria-hidden />
          {t('settings.dataLoss.strongTitle')}
        </p>
        <p className="text-sm text-gray-800 dark:text-gray-200 mt-1" data-testid="data-loss-strong-body">
          {t(high ? 'settings.dataLoss.strongBodyHigh' : 'settings.dataLoss.strongBodyMedium')}
        </p>
        <div className="flex flex-wrap gap-2 mt-3">
          <button
            type="button"
            data-testid="data-loss-backup-action"
            onClick={() => scrollToSection('backup-section')}
            className="btn-primary text-sm"
          >
            {t('settings.dataLoss.actionBackup')}
          </button>
          <button
            type="button"
            data-testid="data-loss-device-action"
            onClick={() => scrollToSection('sync-devices-section')}
            className="btn-secondary text-sm"
          >
            {t('settings.dataLoss.actionDevice')}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      role={high ? 'alert' : 'status'}
      data-testid="data-loss-banner"
      className={`mb-5 flex items-center justify-between gap-3 rounded-lg border px-4 py-3 ${
        high
          ? 'border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-950/40'
          : 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40'
      }`}
    >
      <p
        className={`flex items-center gap-2 text-sm font-medium min-w-0 ${
          high ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'
        }`}
        data-testid="data-loss-banner-text"
      >
        <span
          aria-hidden
          className={`inline-block w-2 h-2 rounded-full shrink-0 ${
            high ? 'bg-red-500' : 'bg-amber-500'
          }`}
        />
        {t(high ? 'settings.dataLoss.bannerTitleHigh' : 'settings.dataLoss.bannerTitleMedium')}
      </p>
      <button
        type="button"
        data-testid="data-loss-banner-action"
        onClick={() => scrollToSection('backup-section')}
        className={`text-sm font-medium shrink-0 underline underline-offset-2 ${
          high ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'
        }`}
      >
        {t('settings.dataLoss.bannerAction')}
      </button>
    </div>
  );
};

export default DataLossWarning;
