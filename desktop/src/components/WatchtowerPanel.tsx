import React, { useState } from 'react';
import { ShieldCheckIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { personaAPI } from '@/utils/api';
import { credentialTypeLabel } from './credentialDisplay';
import type { HealthIssue, HealthIssueKindPayload, HealthReport, HealthSeverity } from '@/types';

const getSeverityColor = (severity: HealthSeverity) => {
  switch (severity) {
    case 'high':
      return 'bg-red-100 dark:bg-red-500/10 text-red-800 dark:text-red-300 border-red-200 dark:border-red-500/20';
    case 'medium':
      return 'bg-orange-100 dark:bg-orange-500/10 text-orange-800 dark:text-orange-300 border-orange-200 dark:border-orange-500/20';
    case 'low':
      return 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-500/20';
  }
};

/** 规则短标签的 i18n key（渲染处 t()）；措辞与 CLI `persona watchtower` 对应 */
const KIND_LABELS: Record<HealthIssueKindPayload['type'], string> = {
  weak_password: 'watchtower.kind.weak_password',
  reused_password: 'watchtower.kind.reused_password',
  breached_password: 'watchtower.kind.breached_password',
  expired: 'watchtower.kind.expired',
  expiring_soon: 'watchtower.kind.expiring_soon',
  stale_unchanged: 'watchtower.kind.stale_unchanged',
  two_factor_available: 'watchtower.kind.two_factor_available',
};

/**
 * 本地化 detail：按结构化 type 字段渲染（后端 detail 是英文固定模板，供 CLI
 * 消费；前端不复用，保证界面语言一致）。
 */
const detailFor = (
  issue: HealthIssue,
  t: (key: string, opts?: Record<string, unknown>) => string,
): string => {
  switch (issue.type) {
    case 'weak_password':
      return t('watchtower.detail.weak', { score: issue.score ?? 0 });
    case 'reused_password':
      return t('watchtower.detail.reused', { group_size: issue.group_size ?? 0 });
    case 'breached_password':
      return t('watchtower.detail.breached', { count: issue.count ?? 0 });
    case 'expired':
      return t('watchtower.detail.expired');
    case 'expiring_soon':
      return t('watchtower.detail.expiring', { days: issue.days ?? 0 });
    case 'stale_unchanged':
      return t('watchtower.detail.stale', { days: issue.days ?? 0 });
    case 'two_factor_available':
      return t('watchtower.detail.twoFactor', { site: issue.site ?? '' });
  }
};

const SEVERITIES: HealthSeverity[] = ['high', 'medium', 'low'];

const WatchtowerPanel: React.FC = () => {
  const { t } = useTranslation();
  const [report, setReport] = useState<HealthReport | null>(null);
  const [checkBreaches, setCheckBreaches] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await personaAPI.healthScan({ check_breaches: checkBreaches });
      if (res.success && res.data) {
        setReport(res.data);
      } else if (res.error_code === 'SERVICE_LOCKED') {
        setError(t('watchtower.serviceLocked'));
      } else {
        setError(res.error ?? t('watchtower.scanFailed'));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="bg-white dark:bg-gray-900 shadow rounded-xl p-6 border border-gray-100 dark:border-gray-800">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{t('watchtower.title')}</p>
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
              {t('watchtower.description')}
            </p>
            <label className="mt-3 flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                checked={checkBreaches}
                onChange={(e) => setCheckBreaches(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-gray-300 dark:border-gray-600 text-primary-600 dark:text-primary-400 focus:ring-primary-500"
              />
              <span>
                {t('watchtower.checkBreaches')}
                <span className="block text-xs text-gray-500 dark:text-gray-400">
                  {t('watchtower.checkBreachesHint')}
                </span>
              </span>
            </label>
          </div>
          <button
            onClick={handleScan}
            disabled={isLoading}
            className="btn-primary inline-flex items-center self-start md:self-auto"
          >
            <ShieldCheckIcon className="w-4 h-4 mr-1" />
            {isLoading ? t('watchtower.scanning') : t('watchtower.runScan')}
          </button>
        </div>
      </section>

      <section className="bg-white dark:bg-gray-900 shadow rounded-xl border border-gray-100 dark:border-gray-800">
        <div className="p-6 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div>
            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{t('watchtower.results')}</p>
            {report && (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {t('watchtower.scannedSummary', {
                  total: report.total_credentials,
                  time: new Date(report.scanned_at).toLocaleString(),
                })}
              </p>
            )}
          </div>
          {report && (
            <button
              onClick={handleScan}
              disabled={isLoading}
              className="btn-ghost inline-flex items-center"
            >
              <ArrowPathIcon className="w-4 h-4 mr-1" />
              {t('watchtower.rescan')}
            </button>
          )}
        </div>

        {error && (
          <div className="mx-6 mt-6 rounded-md bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 px-4 py-3 text-sm text-red-800 dark:text-red-300">
            {error}
          </div>
        )}

        {!report ? (
          <div className="p-8 text-center text-sm text-gray-500 dark:text-gray-400">
            {t('watchtower.guidance')}
          </div>
        ) : report.issues.length === 0 ? (
          <div className="p-8 text-center text-sm text-green-700 dark:text-green-300">
            {t('watchtower.noIssues', { total: report.total_credentials })}
          </div>
        ) : (
          <>
            <div className="px-6 pt-4 flex flex-wrap gap-2">
              {SEVERITIES.map((sev) => (
                <span
                  key={sev}
                  className={clsx(
                    'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border',
                    getSeverityColor(sev),
                  )}
                >
                  {report.counts[sev] ?? 0} {t(`watchtower.severity.${sev}`)}
                </span>
              ))}
            </div>
            <ul className="divide-y divide-gray-200 dark:divide-gray-700 mt-2">
              {report.issues.map((issue, idx) => (
                <li
                  key={`${issue.credential_id}-${issue.type}-${idx}`}
                  className="px-6 py-4 flex items-start gap-3"
                >
                  <span
                    className={clsx(
                      'mt-0.5 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border',
                      getSeverityColor(issue.severity),
                    )}
                  >
                    {t(`watchtower.severity.${issue.severity}`)}
                  </span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {issue.credential_name}
                      </span>
                      <span className="px-2 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full">
                        {t(KIND_LABELS[issue.type])}
                      </span>
                      <span className="text-xs text-gray-400 dark:text-gray-500">{credentialTypeLabel(t, issue.credential_type)}</span>
                    </div>
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">{detailFor(issue, t)}</p>
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
};

export default WatchtowerPanel;
