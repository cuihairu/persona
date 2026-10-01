import React, { useEffect, useState } from 'react';
import { ArrowPathIcon, PlayIcon, StopIcon, KeyIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { open as openFileDialog } from '@tauri-apps/plugin-dialog';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { usePersonaService } from '@/hooks/usePersonaService';
import toast from 'react-hot-toast';
import { useAppStore } from '@/stores/appStore';
import type { SshKeyInspection } from '@/types';
import { clsx } from 'clsx';

/// 导入确认弹框的会话状态：文件路径 + 预览 + 表单输入 + 就地错误。
/// 拖拽与文件选择器两条入口都汇聚到同一条 inspect → 确认 → import 流水线。
interface ImportSession {
  path: string;
  inspection: SshKeyInspection;
  name: string;
  passphrase: string;
  error: string | null;
  importing: boolean;
}

const SshAgentPanel: React.FC = () => {
  const { t } = useTranslation();
  const {
    sshAgentStatus,
    sshKeys,
    refreshSshAgentStatus,
    startSshAgent,
    stopSshAgent,
    loadSshKeys,
    inspectSshKeyFile,
    importSshKey,
  } = usePersonaService();
  const currentIdentity = useAppStore((s) => s.currentIdentity);

  const [masterPassword, setMasterPassword] = useState('');
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [importSession, setImportSession] = useState<ImportSession | null>(null);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    refreshSshAgentStatus();
    loadSshKeys();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 文件拖拽：enter/over 点亮拖放区，drop 带路径走与选择器同一条导入
  // 流水线；cancel（拖出窗口）熄灭。无路径的拖入（纯文本等）不响应。
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    const setup = async () => {
      try {
        unlisten = await getCurrentWebview().onDragDropEvent((event) => {
          if (event.payload.type === 'enter' || event.payload.type === 'over') {
            if (event.payload.type === 'enter' && event.payload.paths.length === 0) return;
            setDragActive(true);
          } else if (event.payload.type === 'drop') {
            setDragActive(false);
            if (event.payload.paths.length > 0) {
              void beginImport(event.payload.paths[0]);
            }
          } else {
            setDragActive(false);
          }
        });
      } catch {
        // 非 Tauri 环境（jest/浏览器预览）：拖拽能力静默缺席
      }
    };
    void setup();
    return () => {
      unlisten?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const beginImport = async (path: string) => {
    const response = await inspectSshKeyFile(path);
    if (!response.success || !response.data) {
      toast.error(response.error || t('sshAgent.importFailed'));
      return;
    }
    const inspection = response.data;
    setImportSession({
      path,
      inspection,
      // 条目名回退与 Rust 侧一致：comment > 文件名（用户可改）
      name: inspection.comment || inspection.file_name,
      passphrase: '',
      error: null,
      importing: false,
    });
  };

  const handleImportButtonClick = async () => {
    if (!currentIdentity) {
      toast.error(t('sshAgent.importNoIdentity'));
      return;
    }
    const path = await openFileDialog({
      multiple: false,
      title: t('sshAgent.importTitle'),
    });
    if (typeof path === 'string' && path) {
      await beginImport(path);
    }
  };

  const handleConfirmImport = async () => {
    if (!importSession || !currentIdentity) return;
    setImportSession({ ...importSession, importing: true, error: null });
    const response = await importSshKey({
      identity_id: currentIdentity.id,
      path: importSession.path,
      name: importSession.name,
      passphrase:
        importSession.inspection.encrypted && importSession.passphrase
          ? importSession.passphrase
          : undefined,
    });
    if (response.success && response.data) {
      toast.success(t('sshAgent.importSuccess', { name: response.data.name }));
      setImportSession(null);
      loadSshKeys();
    } else {
      // 错误就地展示（错口令可原地改了重试），弹框不关
      setImportSession((s) =>
        s
          ? { ...s, importing: false, error: response.error || t('sshAgent.importFailed') }
          : s,
      );
    }
  };

  const handleStart = async () => {
    setIsStarting(true);
    await startSshAgent(masterPassword || undefined);
    await refreshSshAgentStatus();
    setMasterPassword('');
    setIsStarting(false);
  };

  const handleStop = async () => {
    setIsStopping(true);
    await stopSshAgent();
    await refreshSshAgentStatus();
    setIsStopping(false);
  };

  return (
    <div className="space-y-6" data-testid="ssh-agent-panel">
      <section className="bg-white dark:bg-gray-900 shadow rounded-xl p-6 border border-gray-100 dark:border-gray-800">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">SSH Agent</p>
            <div className="flex items-center mt-1">
              <span
                className={clsx(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold',
                  sshAgentStatus?.running ? 'bg-green-100 dark:bg-green-500/10 text-green-800 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300',
                )}
              >
                {sshAgentStatus?.running ? t('sshAgent.running') : t('sshAgent.stopped')}
              </span>
              {sshAgentStatus?.socket_path && (
                <span className="ml-3 text-sm text-gray-600 dark:text-gray-300 truncate">
                  {t('sshAgent.socket')} <span className="font-medium">{sshAgentStatus.socket_path}</span>
                </span>
              )}
            </div>
            {sshAgentStatus?.key_count !== undefined && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {t('sshAgent.loadedKeys')} <span className="font-medium">{sshAgentStatus.key_count}</span>
              </p>
            )}
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex gap-2">
              <input
                type="password"
                placeholder={t('sshAgent.passwordPlaceholder')}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                className="input-field w-full sm:w-64"
              />
              <button
                onClick={handleStart}
                disabled={isStarting}
                className="btn-primary inline-flex items-center"
              >
                <PlayIcon className="w-4 h-4 mr-1" />
                {isStarting ? t('sshAgent.starting') : t('sshAgent.start')}
              </button>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleStop}
                disabled={isStopping}
                className="btn-ghost inline-flex items-center text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
              >
                <StopIcon className="w-4 h-4 mr-1" />
                {isStopping ? t('sshAgent.stopping') : t('sshAgent.stop')}
              </button>
              <button
                onClick={refreshSshAgentStatus}
                className="btn-ghost inline-flex items-center"
              >
                <ArrowPathIcon className="w-4 h-4 mr-1" />
                {t('sshAgent.refresh')}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="bg-white dark:bg-gray-900 shadow rounded-xl border border-gray-100 dark:border-gray-800 relative">
        <div className="p-6 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div>
            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{t('sshAgent.keysTitle')}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('sshAgent.keysSubtitle')}</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleImportButtonClick}
              data-testid="ssh-import-button"
              className="btn-ghost inline-flex items-center"
            >
              <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
              {t('sshAgent.importButton')}
            </button>
            <button onClick={loadSshKeys} className="btn-ghost inline-flex items-center">
              <ArrowPathIcon className="w-4 h-4 mr-1" />
              {t('sshAgent.reload')}
            </button>
          </div>
        </div>
        {sshKeys.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-500 dark:text-gray-400">
            {t('sshAgent.noKeys')}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.identityCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.credentialCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.tagsCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.updatedCol')}
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {sshKeys.map((key) => (
                  <tr key={key.id}>
                    <td className="px-6 py-3 text-sm text-gray-900 dark:text-gray-100 font-medium flex items-center gap-2">
                      <KeyIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                      {key.identity_name}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-700 dark:text-gray-300">{key.name}</td>
                    <td className="px-6 py-3 text-sm text-gray-500 dark:text-gray-400">
                      {key.tags.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {key.tags.map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded-full"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-400 dark:text-gray-500">—</span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-500 dark:text-gray-400">
                      {new Date(key.updated_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {dragActive && !importSession && (
          <div
            data-testid="ssh-dropzone"
            className="absolute inset-0 z-10 rounded-xl border-2 border-dashed border-primary-500 bg-primary-50/80 dark:bg-primary-500/10 flex items-center justify-center pointer-events-none"
          >
            <p className="text-sm font-medium text-primary-600 dark:text-primary-300">
              {t('sshAgent.dropHere')}
            </p>
          </div>
        )}
      </section>

      {importSession && (
        <div
          data-testid="ssh-import-modal"
          className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
          onMouseDown={(e) => {
            // 点空白（遮罩自身）= 取消；带未保存口令输入时同样直接取消：
            // 口令本就没有"保存"语义，误触代价只是重拖一次文件
            if (e.target === e.currentTarget) setImportSession(null);
          }}
        >
          <div className="bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-lg w-full p-6 space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                {t('sshAgent.importTitle')}
              </h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 truncate">
                {importSession.inspection.file_name}
              </p>
            </div>

            <dl className="space-y-2 text-sm">
              <div className="flex gap-2">
                <dt className="w-28 shrink-0 text-gray-500 dark:text-gray-400">{t('sshAgent.importType')}</dt>
                <dd className="font-mono text-gray-900 dark:text-gray-100">
                  {importSession.inspection.ssh_algorithm}
                  {importSession.inspection.encrypted && (
                    <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-100 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300">
                      {t('sshAgent.importEncrypted')}
                    </span>
                  )}
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-28 shrink-0 text-gray-500 dark:text-gray-400">{t('sshAgent.importFingerprint')}</dt>
                <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="ssh-import-fingerprint">
                  {importSession.inspection.fingerprint}
                </dd>
              </div>
              {importSession.inspection.comment && (
                <div className="flex gap-2">
                  <dt className="w-28 shrink-0 text-gray-500 dark:text-gray-400">{t('sshAgent.importComment')}</dt>
                  <dd className="text-gray-900 dark:text-gray-100 break-all">{importSession.inspection.comment}</dd>
                </div>
              )}
            </dl>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('sshAgent.importNameLabel')}
              </label>
              <input
                type="text"
                value={importSession.name}
                onChange={(e) =>
                  setImportSession((s) => (s ? { ...s, name: e.target.value } : s))
                }
                className="input-field mt-1 w-full"
                data-testid="ssh-import-name"
              />
            </div>

            {importSession.inspection.encrypted && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {t('sshAgent.importPassphraseLabel')}
                </label>
                <input
                  type="password"
                  value={importSession.passphrase}
                  onChange={(e) =>
                    setImportSession((s) => (s ? { ...s, passphrase: e.target.value } : s))
                  }
                  className="input-field mt-1 w-full"
                  data-testid="ssh-import-passphrase"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {t('sshAgent.importEncryptedHint')}
                </p>
              </div>
            )}

            {importSession.error && (
              <p className="text-sm text-red-600 dark:text-red-400" data-testid="ssh-import-error">
                {importSession.error}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setImportSession(null)}
                className="btn-ghost"
                data-testid="ssh-import-cancel"
              >
                {t('sshAgent.importCancel')}
              </button>
              <button
                onClick={handleConfirmImport}
                disabled={importSession.importing}
                className="btn-primary"
                data-testid="ssh-import-confirm"
              >
                {importSession.importing ? t('sshAgent.importing') : t('sshAgent.importConfirm')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SshAgentPanel;
