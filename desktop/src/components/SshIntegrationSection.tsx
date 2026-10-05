import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { personaAPI } from '@/utils/api';
import type { SshIntegrationStatus } from '@/types';

/**
 * 设置页「SSH 走 persona agent」：检测/一键启用 ~/.ssh/config 的
 * IdentityAgent 锚点块，纯文件操作不解锁。文案解释原理（IdentityAgent
 * 等效 host 级 SSH_AUTH_SOCK）与手动配置片段；三平台兼容随文案说明。
 */
const SshIntegrationSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<SshIntegrationStatus | null>(null);
  const [busy, setBusy] = useState<'enable' | 'disable' | null>(null);
  const [showManual, setShowManual] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const resp = await personaAPI.sshAgentIntegrationStatus();
      if (resp.success && resp.data) setStatus(resp.data);
      // 状态查询失败：行保持隐藏，不谎报未启用
    } catch {
      /* 同上 */
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const apply = async (op: 'enable' | 'disable'): Promise<void> => {
    setBusy(op);
    try {
      const resp =
        op === 'enable'
          ? await personaAPI.sshAgentIntegrationEnable()
          : await personaAPI.sshAgentIntegrationDisable();
      if (resp.success && resp.data) {
        setStatus(resp.data);
        toast.success(
          t(
            op === 'enable'
              ? 'settings.sshIntegration.enableSuccess'
              : 'settings.sshIntegration.disableSuccess',
          ),
        );
      } else {
        toast.error(
          resp.error ||
            t(
              op === 'enable'
                ? 'settings.sshIntegration.enableFailed'
                : 'settings.sshIntegration.disableFailed',
            ),
        );
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  if (!status) return null;

  const { enabled, anomaly, manualEntry, socketPath, configPath } = status;
  const manualSnippet = [
    '# persona managed begin',
    `IdentityAgent ${socketPath}`,
    '# persona managed end',
  ].join('\n');

  const badge = anomaly
    ? { cls: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-500/15 dark:text-yellow-300', key: 'anomaly' }
    : enabled
      ? { cls: 'bg-green-100 text-green-800 dark:bg-green-500/15 dark:text-green-300', key: 'enabled' }
      : { cls: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300', key: 'disabled' };

  return (
    <div data-testid="ssh-integration-section">
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.sshIntegration.title')}
          </h3>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {t('settings.sshIntegration.description')}
          </p>
        </div>
        <span
          data-testid="ssh-integration-badge"
          className={`shrink-0 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${badge.cls}`}
        >
          {t(`settings.sshIntegration.${badge.key}`)}
        </span>
      </div>

      <div className="rounded-md border border-gray-200 dark:border-gray-700 p-3 space-y-1.5 text-xs text-gray-600 dark:text-gray-300">
        <p className="flex gap-2 break-all">
          <span className="shrink-0 text-gray-400 dark:text-gray-500">
            {t('settings.sshIntegration.socketLabel')}
          </span>
          <span className="font-mono" data-testid="ssh-integration-socket">
            {socketPath}
          </span>
        </p>
        <p className="flex gap-2 break-all">
          <span className="shrink-0 text-gray-400 dark:text-gray-500">
            {t('settings.sshIntegration.configLabel')}
          </span>
          <span className="font-mono" data-testid="ssh-integration-config">
            {configPath}
          </span>
        </p>
        <p className="text-gray-500 dark:text-gray-400">
          {t('settings.sshIntegration.manualHint')}
        </p>
      </div>

      {anomaly && (
        <div
          data-testid="ssh-integration-anomaly"
          className="mt-2 rounded-md bg-yellow-50 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-500/20 px-3 py-2 text-xs text-yellow-800 dark:text-yellow-300"
        >
          {t('settings.sshIntegration.anomalyHint', { found: anomaly })}
        </div>
      )}
      {manualEntry && (
        <div
          data-testid="ssh-integration-manual-entry"
          className="mt-2 rounded-md bg-yellow-50 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-500/20 px-3 py-2 text-xs text-yellow-800 dark:text-yellow-300"
        >
          {t('settings.sshIntegration.manualEntryHint')}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          data-testid="ssh-integration-toggle"
          className={enabled ? 'btn-secondary' : 'btn-primary'}
          disabled={busy !== null}
          onClick={() => void apply(enabled ? 'disable' : 'enable')}
        >
          {busy === 'enable'
            ? t('settings.sshIntegration.enabling')
            : busy === 'disable'
              ? t('settings.sshIntegration.disabling')
              : enabled
                ? t('settings.sshIntegration.disable')
                : t('settings.sshIntegration.enable')}
        </button>
        <button
          data-testid="ssh-integration-manual-toggle"
          className="btn-ghost"
          onClick={() => setShowManual((v) => !v)}
        >
          {showManual
            ? t('settings.sshIntegration.hideManual')
            : t('settings.sshIntegration.showManual')}
        </button>
      </div>

      {showManual && (
        <div className="mt-3 rounded-md bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700 p-3 space-y-2">
          <p className="text-xs text-gray-600 dark:text-gray-300">
            {t('settings.sshIntegration.manualConfigHint')}
          </p>
          <pre
            data-testid="ssh-integration-snippet"
            className="text-xs font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap break-all"
          >
            {manualSnippet}
          </pre>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.sshIntegration.compatNote')}
          </p>
        </div>
      )}
    </div>
  );
};

export default SshIntegrationSection;
