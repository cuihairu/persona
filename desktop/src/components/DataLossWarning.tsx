import React from 'react';
import { useTranslation } from 'react-i18next';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { useDataLossRisk } from '@/hooks/useDataLossRisk';

/** Scrolls to the target settings section (jump target of the self-rescue actions; all target sections live in the same GeneralPane). */
function scrollToSection(testid: string): void {
  document
    .querySelector(`[data-testid="${testid}"]`)
    ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/**
 * Data loss strong prompt (S5-b, a hard requirement of the design spec §6.5).
 *
 * - `strong`: the in-place strong prompt for the sync group "first enable" scenario
 *   (nested inside the join-success block); the copy spells out the two ways out (④):
 *   connect another device, or export an encrypted backup right away.
 * - `banner`: the resident banner at the top of the settings page
 *   (② the red dot stays resident; no one-shot dialog).
 *
 * The level and its clearing are all driven by [`useDataLossRisk`]: a second device
 * in place or a backup already exported clears it automatically (③); a bound account
 * drops the level by one (a recovery path exists).
 */
const DataLossWarning: React.FC<{ variant?: 'strong' | 'banner' }> = ({
  variant = 'banner',
}) => {
  const { t } = useTranslation();
  const { loading, level, crossDeviceSyncEnabled } = useDataLossRisk();

  if (loading || level === 'none') return null;
  const high = level === 'high';
  // Cross-device sync is off but the data still lives in the group (a keyring fact): point back at the
  // enable entry honestly, and do not withdraw the risk warning just because the preference is off
  // (the level decision does not degrade with the preference).
  const syncDisabledNote = !crossDeviceSyncEnabled ? (
    <p
      className="text-xs text-gray-600 dark:text-gray-300 mt-1"
      data-testid="data-loss-sync-disabled-note"
    >
      {t('settings.dataLoss.syncDisabledNote')}
    </p>
  ) : null;

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
        {syncDisabledNote}
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
      <div className="min-w-0">
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
        {syncDisabledNote}
      </div>
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
