import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowPathIcon } from '@heroicons/react/24/outline';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import {
  checkForUpdate,
  getBuildMeta,
  getLastCheckedAt,
  isUpdateCheckEnabled,
  setLastCheckedAt,
  setUpdateCheckEnabled,
  type UpdateChannel,
  type UpdateCheckResult,
} from '@/utils/updateCheck';

/** 渠道 → 文案键（settings.updateCheck.channel*） */
const CHANNEL_LABEL_KEY: Record<UpdateChannel, string> = {
  dev: 'settings.updateCheck.channelDev',
  nightly: 'settings.updateCheck.channelNightly',
  release: 'settings.updateCheck.channelRelease',
};

/** unavailable 原因 → 文案键 */
const REASON_LABEL_KEY: Record<NonNullable<UpdateCheckResult['reason']>, string> = {
  'no-release': 'settings.updateCheck.reasonNoRelease',
  'dev-channel': 'settings.updateCheck.reasonDev',
  network: 'settings.updateCheck.reasonOffline',
  'no-current-version': 'settings.updateCheck.reasonNoVersion',
};

/**
 * 版本更新检测设置区：按构建渠道检查新版本——nightly（每日构建）看
 * desktop-build workflow 最近一次成功 run，release 看 GitHub Releases
 * latest。只查询不下载；启动时自动检查的开关也在这里。
 */
const UpdateCheckSection: React.FC = () => {
  const { t } = useTranslation();
  const meta = getBuildMeta();
  const [enabled, setEnabled] = useState(isUpdateCheckEnabled());
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<UpdateCheckResult | null>(null);
  const [lastCheckedAt, setLastChecked] = useState(getLastCheckedAt());

  const toggle = () => {
    const next = !enabled;
    setEnabled(next);
    setUpdateCheckEnabled(next);
  };

  const runCheck = async () => {
    setChecking(true);
    try {
      const outcome = await checkForUpdate();
      setResult(outcome);
      const now = new Date().toISOString();
      setLastChecked(now);
      setLastCheckedAt(now);
    } finally {
      setChecking(false);
    }
  };

  const copyLink = () => {
    if (result?.detailUrl) {
      void copyToClipboardWithToast(result.detailUrl, t('settings.updateCheck.copyLink'));
    }
  };

  return (
    <section className="mb-5" data-testid="update-check-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.updateCheck.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
        {t('settings.updateCheck.description')}
      </p>

      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm text-gray-900 dark:text-gray-100">{t('settings.updateCheck.enable')}</p>
          <p
            className="text-xs text-gray-500 dark:text-gray-400"
            data-testid="update-check-channel"
          >
            {t('settings.updateCheck.channel')}: {t(CHANNEL_LABEL_KEY[meta.channel])}
            {result?.currentVersion ? ` · ${t('settings.updateCheck.currentVersion', { version: result.currentVersion })}` : ''}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label={t('settings.updateCheck.enable')}
          data-testid="update-check-toggle"
          onClick={toggle}
          className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${
            enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
              enabled ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
      </div>

      <div className="flex items-center gap-2 mt-3">
        <button
          type="button"
          onClick={() => void runCheck()}
          disabled={checking}
          data-testid="update-check-button"
          className="btn-secondary inline-flex items-center gap-1.5 text-sm"
        >
          <ArrowPathIcon className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} />
          {checking ? t('settings.updateCheck.checking') : t('settings.updateCheck.checkNow')}
        </button>

        {result?.status === 'update-available' && result.detailUrl && (
          <button
            type="button"
            onClick={copyLink}
            data-testid="update-check-copy-link"
            className="btn-secondary text-sm"
          >
            {t('settings.updateCheck.copyLink')}
          </button>
        )}
      </div>

      {result && (
        <p
          className={`text-sm mt-2 ${
            result.status === 'update-available'
              ? 'text-primary-700 dark:text-primary-300'
              : 'text-gray-500 dark:text-gray-400'
          }`}
          data-testid="update-check-status"
        >
          {result.status === 'update-available' &&
            t('settings.updateCheck.available', { version: result.latestVersion ?? '' })}
          {result.status === 'up-to-date' &&
            t('settings.updateCheck.upToDate', { version: result.latestVersion ?? '' })}
          {result.status === 'unavailable' &&
            t('settings.updateCheck.unavailable', {
              reason: result.reason ? t(REASON_LABEL_KEY[result.reason]) : '',
            })}
        </p>
      )}

      <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
        {lastCheckedAt
          ? t('settings.updateCheck.lastChecked', {
              time: new Date(lastCheckedAt).toLocaleString(),
            })
          : t('settings.updateCheck.neverChecked')}
      </p>
    </section>
  );
};

export default UpdateCheckSection;
