import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { personaAPI } from '@/utils/api';
import type { SshConfigAgentAnalysis, SshIntegrationStatus } from '@/types';

/** "OpenSSH_10.2p1" → [10, 2]；解析不了 → null */
const parseSshVersion = (label: string): [number, number] | null => {
  const m = /^OpenSSH_(\d+)\.(\d+)/.exec(label);
  return m ? [Number(m[1]), Number(m[2])] : null;
};

/**
 * 设置页「SSH 走 persona agent」：检测/一键启用 ~/.ssh/config 的
 * IdentityAgent 锚点块，纯文件操作不解锁。文案解释原理（IdentityAgent
 * 等效 host 级 SSH_AUTH_SOCK）与手动配置片段；三平台兼容随文案说明。
 *
 * agent 配置分析面板：读出 ~/.ssh/config（含 Include 展开）的 agent 相关
 * 配置、SSH_AUTH_SOCK 与 socket 连通探测——状态灯=读出来的真状态，不是猜。
 */
const SshIntegrationSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<SshIntegrationStatus | null>(null);
  const [analysis, setAnalysis] = useState<SshConfigAgentAnalysis | null>(null);
  const [busy, setBusy] = useState<'enable' | 'disable' | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [showManual, setShowManual] = useState(false);

  const refreshAnalysis = useCallback(async () => {
    try {
      const resp = await personaAPI.sshAgentConfigAnalysis();
      if (resp.success && resp.data) setAnalysis(resp.data);
      // 分析查询失败：面板保持隐藏，不谎报
    } catch {
      /* 同上 */
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const resp = await personaAPI.sshAgentIntegrationStatus();
      if (resp.success && resp.data) setStatus(resp.data);
      // 状态查询失败：行保持隐藏，不谎报未启用
    } catch {
      /* 同上 */
    }
    await refreshAnalysis();
  }, [refreshAnalysis]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // 手动重读：外部改了 config / 起了 agent 后，面板与状态行同步现状
  const manualRefresh = async (): Promise<void> => {
    setRefreshing(true);
    try {
      await refresh();
    } finally {
      setRefreshing(false);
    }
  };

  const apply = async (op: 'enable' | 'disable'): Promise<void> => {
    setBusy(op);
    try {
      const resp =
        op === 'enable'
          ? await personaAPI.sshAgentIntegrationEnable()
          : await personaAPI.sshAgentIntegrationDisable();
      if (resp.success && resp.data) {
        setStatus(resp.data);
        void refreshAnalysis();
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
  // socket 连通状态灯色：绿=有进程在听 / 红=无人听 / 灰=无法判定
  const aliveDot = (v: boolean | null) =>
    v === true ? 'bg-green-500' : v === false ? 'bg-red-500' : 'bg-gray-400';
  const aliveLabel =
    analysis?.socketAlive === true
      ? t('settings.sshIntegration.analysisAliveListening')
      : analysis?.socketAlive === false
        ? t('settings.sshIntegration.analysisAliveDead')
        : t('settings.sshIntegration.analysisAliveUnknown');

  // OpenSSH 版本兼容判定：IdentityAgent 需 8.3+（探测不到/解析不了则
  // 如实显示无法判定，不猜）
  const parsedVersion = status.sshVersion
    ? parseSshVersion(status.sshVersion)
    : null;
  const versionOk: boolean | null = status.sshVersion
    ? parsedVersion
      ? parsedVersion[0] > 8 || (parsedVersion[0] === 8 && parsedVersion[1] >= 3)
      : null
    : null;
  // Host * 作用域行与后端锚点块同构：块追加在 EOF，若无它会落入用户
  // 最后一个 Host 块的作用域（见 ssh_integration.rs 模块注释）
  const manualSnippet = [
    '# persona managed begin',
    'Host *',
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
        <p className="flex flex-wrap items-center gap-2">
          <span className="shrink-0 text-gray-400 dark:text-gray-500">
            {t('settings.sshIntegration.sshVersionLabel')}
          </span>
          <span className="font-mono" data-testid="ssh-integration-version">
            {status.sshVersion ?? t('settings.sshIntegration.sshVersionUnknown')}
          </span>
          <span
            data-testid="ssh-integration-version-verdict"
            className={
              versionOk === true
                ? 'text-green-600 dark:text-green-400'
                : versionOk === false
                  ? 'text-red-600 dark:text-red-400'
                  : 'text-gray-400 dark:text-gray-500'
            }
          >
            {versionOk === true
              ? t('settings.sshIntegration.sshVersionOk')
              : versionOk === false
                ? t('settings.sshIntegration.sshVersionTooOld')
                : t('settings.sshIntegration.sshVersionRequirement')}
          </span>
        </p>
        <p className="text-gray-500 dark:text-gray-400">
          {t('settings.sshIntegration.manualHint')}
        </p>
      </div>

      {analysis && (
        <div
          data-testid="ssh-analysis-panel"
          className="mt-3 rounded-md border border-gray-200 dark:border-gray-700 p-3 space-y-2 text-xs text-gray-600 dark:text-gray-300"
        >
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.sshIntegration.analysisTitle')}
            </p>
            <button
              data-testid="ssh-analysis-refresh"
              className="btn-ghost text-xs"
              disabled={refreshing}
              onClick={() => void manualRefresh()}
            >
              {refreshing
                ? t('settings.sshIntegration.analysisRefreshing')
                : t('settings.sshIntegration.analysisRefresh')}
            </button>
          </div>

          {/* config 损坏/无权限：如实显示，不崩、不静默 */}
          {analysis.readError && (
            <div
              data-testid="ssh-analysis-read-error"
              className="rounded-md bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 px-2 py-1.5 text-red-800 dark:text-red-300 break-all"
            >
              {t('settings.sshIntegration.analysisReadError', {
                error: analysis.readError,
              })}
            </div>
          )}
          {analysis.warnings.length > 0 && (
            <div
              data-testid="ssh-analysis-warnings"
              className="rounded-md bg-yellow-50 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-500/20 px-2 py-1.5 text-yellow-800 dark:text-yellow-300 space-y-1"
            >
              {analysis.warnings.map((w, i) => (
                <p key={i} className="break-all">
                  {w}
                </p>
              ))}
            </div>
          )}

          <p className="flex gap-2 break-all">
            <span className="shrink-0 text-gray-400 dark:text-gray-500">
              {t('settings.sshIntegration.analysisSockEnv')}
            </span>
            <span className="font-mono" data-testid="ssh-analysis-sock-env">
              {analysis.sshAuthSock ?? t('settings.sshIntegration.analysisUnset')}
            </span>
          </p>
          <p className="flex gap-2 break-all">
            <span className="shrink-0 text-gray-400 dark:text-gray-500">
              {t('settings.sshIntegration.analysisEffectiveAgent')}
            </span>
            <span className="font-mono" data-testid="ssh-analysis-effective-agent">
              {analysis.identityAgentEffective ??
                t('settings.sshIntegration.analysisNone')}
            </span>
          </p>
          <p className="flex items-center gap-2 break-all">
            <span className="shrink-0 text-gray-400 dark:text-gray-500">
              {t('settings.sshIntegration.analysisEffectiveSocket')}
            </span>
            <span className="font-mono" data-testid="ssh-analysis-effective-socket">
              {analysis.effectiveSocket ?? t('settings.sshIntegration.analysisNone')}
            </span>
            <span
              className={`inline-block w-2 h-2 rounded-full shrink-0 ${aliveDot(analysis.socketAlive)}`}
              data-testid="ssh-analysis-alive"
              title={aliveLabel}
            />
            <span className="text-gray-500 dark:text-gray-400">{aliveLabel}</span>
          </p>
          <p className="flex items-center gap-2">
            <span className="shrink-0 text-gray-400 dark:text-gray-500">
              {t('settings.sshIntegration.analysisPersona')}
            </span>
            <span
              className={`inline-block w-2 h-2 rounded-full shrink-0 ${analysis.personaSocketAlive ? 'bg-green-500' : 'bg-gray-400'}`}
              data-testid="ssh-analysis-persona-alive"
            />
            <span className="text-gray-500 dark:text-gray-400">
              {analysis.personaSocketAlive
                ? t('settings.sshIntegration.analysisPersonaAlive')
                : t('settings.sshIntegration.analysisPersonaDead')}
            </span>
          </p>

          <div>
            <p className="text-gray-400 dark:text-gray-500">
              {t('settings.sshIntegration.analysisEntries', {
                count: analysis.entries.length,
              })}
            </p>
            {analysis.entries.length === 0 ? (
              <p className="mt-1" data-testid="ssh-analysis-entries-empty">
                {t('settings.sshIntegration.analysisEmpty')}
              </p>
            ) : (
              <ul data-testid="ssh-analysis-entries" className="mt-1 space-y-1">
                {analysis.entries.map((e, i) => (
                  <li key={`${e.file}:${e.line}:${i}`} className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-gray-800 dark:text-gray-200 break-all">
                      {e.scope ? `${e.scope} → ` : ''}
                      {e.keyword} {e.value}
                    </span>
                    <span className="font-mono text-[11px] text-gray-400 dark:text-gray-500 break-all">
                      {e.file}:{e.line}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

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
