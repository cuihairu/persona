import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { open as openFileDialog, save as saveFileDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { BackupEvidence, BackupVersionView } from '@/types';

/** 字节数 → 人类可读尺寸（KB/MB 一位小数；小文件直接给字节数）。 */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** 备份文件默认名：persona-backup-2026-10-07T09-45-12.enc（本地时刻）。 */
function defaultBackupName(): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, '-')
    .slice(0, 19);
  return `persona-backup-${stamp}.enc`;
}

/** 服务器版本行的展示时刻（RFC3339 → 本地时刻）。 */
function formatWhen(rfc3339: string): string {
  const at = new Date(rfc3339);
  return Number.isNaN(at.getTime()) ? rfc3339 : at.toLocaleString();
}

/**
 * 自救口备份节（S5）：整库加密备份导出到本地文件 + 从备份文件恢复 +
 * 服务器密文仓（S5-d：推送/版本列表/恢复/删除）。
 *
 * 备份链与主密码无关（主库不解密），备份口令由用户自定且**永不落盘、
 * 永不出机**；风险披露常驻（设计稿 §6.5）：设备全丢 = 库全丢，唯一自救
 * = 备份文件。导出凭证（时刻/目标/尺寸，非敏感元数据）由后端写入
 * settings.backup，本节挂载时读回展示「上次导出」。
 *
 * 服务器密文仓是**备份**不是同步：默认关闭，仅在用户显式配置 persona-server
 * （地址 + 令牌）后可用；出网的只有口令加密后的密文，口令与主密码不参与
 * 任何网络结构（范围明示见 serverDescription）。推送需解锁（快照要读库），
 * 列表/恢复免解锁（锁屏救库）。
 *
 * 恢复（文件与服务器同语义）是替换式操作：二次确认在前，后端 staged 复验
 * 失败库未动；换库段排空 service 后前端由 `finalizeVaultRestore` 清内存并
 * 重探解锁态——App 随即切解锁屏（恢复出的库主密码可能不同），`.bak` 副本
 * 路径经 toast 展示（解锁屏有自己的 Toaster，节内 state 随卸载不可见）。
 */
const BackupSection: React.FC = () => {
  const { t } = useTranslation();
  const { finalizeVaultRestore } = usePersonaService();
  const [evidence, setEvidence] = useState<BackupEvidence | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** 最近一次导出的 sha256（成功后展示，供用户与文件指纹对账） */
  const [lastSha, setLastSha] = useState<string | null>(null);
  /** 恢复区：选中的备份文件、恢复口令、错误与进行态（与导出互斥） */
  const [restorePath, setRestorePath] = useState('');
  const [restorePass, setRestorePass] = useState('');
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  /** 服务器密文仓：版本列表（null = 尚未查询）、错误与各操作进行态 */
  const [serverItems, setServerItems] = useState<BackupVersionView[] | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);
  const [pushBusy, setPushBusy] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  /** 恢复/删除按行互斥（同一时刻只跑一个行内操作） */
  const [rowBusyId, setRowBusyId] = useState<string | null>(null);
  /** 服务器版本的恢复口令（该版本推送时的备份口令，独立于文件恢复口令） */
  const [serverPass, setServerPass] = useState('');

  /** 写库类操作（导出/文件恢复/推送/服务器恢复）全局互斥；删除只动服务器 */
  const anyWriter = busy || restoreBusy || pushBusy || rowBusyId !== null;

  const refreshEvidence = useCallback(async (): Promise<void> => {
    try {
      const resp = await personaAPI.getWorkspaceSettings();
      if (resp.success && resp.data) setEvidence(resp.data.backup);
    } catch {
      // 状态读取失败保持旧值（同 SyncGroupSection 口径），不打断 UI
    }
  }, []);

  useEffect(() => {
    void refreshEvidence();
  }, [refreshEvidence]);

  const refreshServerList = useCallback(async (): Promise<void> => {
    setListBusy(true);
    try {
      const resp = await personaAPI.backupListServerVersions();
      if (resp.success && resp.data) {
        setServerItems(resp.data);
        setServerError(null);
      } else {
        setServerError(resp.error ?? t('settings.backup.serverListFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverListFailed'));
    } finally {
      setListBusy(false);
    }
  }, [t]);

  const validate = (): string | null => {
    if (!passphrase || !confirm) return t('settings.backup.passRequired');
    if (passphrase.length < 8) return t('settings.backup.passTooShort');
    if (passphrase !== confirm) return t('settings.backup.passMismatch');
    return null;
  };

  const handleExport = async (): Promise<void> => {
    if (anyWriter) return;
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    const outputPath = await saveFileDialog({
      title: t('settings.backup.saveTitle'),
      defaultPath: defaultBackupName(),
    });
    if (!outputPath) return; // 用户取消
    setBusy(true);
    try {
      const resp = await personaAPI.backupExportToFile(outputPath, passphrase);
      if (resp.success && resp.data) {
        setLastSha(resp.data.sha256);
        setPassphrase('');
        setConfirm('');
        toast.success(t('settings.backup.exported'));
        await refreshEvidence();
      } else {
        setError(resp.error ?? t('settings.saveFailed'));
      }
    } catch {
      setError(t('settings.saveFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** 选备份文件：取消（null）/对话框失败都保持现状，可重试。 */
  const handlePickRestoreFile = async (): Promise<void> => {
    try {
      const picked = await openFileDialog({
        title: t('settings.backup.restorePickTitle'),
        multiple: false,
      });
      if (typeof picked === 'string') setRestorePath(picked);
    } catch {
      // 对话框本身失败不打断 UI（用户重新点即可）
    }
  };

  const handleRestore = async (): Promise<void> => {
    if (anyWriter) return;
    if (!restorePath.trim()) {
      setRestoreError(t('settings.backup.restoreNeedFile'));
      return;
    }
    if (!restorePass) {
      setRestoreError(t('settings.backup.restoreNeedPass'));
      return;
    }
    if (!window.confirm(t('settings.backup.restoreConfirm'))) return;
    setRestoreError(null);
    setRestoreBusy(true);
    try {
      const resp = await personaAPI.backupRestoreFromFile(restorePath, restorePass);
      if (resp.success && resp.data) {
        setRestorePass('');
        // .bak 路径只进 toast：换库段成功即切解锁屏，节内 state 随卸载不可见
        toast.success(
          resp.data.backup_copy
            ? t('settings.backup.restoredWithBak', { path: resp.data.backup_copy })
            : t('settings.backup.restored'),
          { duration: 10_000 },
        );
        await refreshEvidence();
        // 清旧库在内存里的身份/凭据 + 重探解锁态（service 已被换库段取下）
        await finalizeVaultRestore();
      } else {
        setRestoreError(resp.error ?? t('settings.backup.restoreFailed'));
      }
    } catch (err) {
      setRestoreError(err instanceof Error ? err.message : t('settings.backup.restoreFailed'));
    } finally {
      setRestoreBusy(false);
    }
  };

  /** 推送：复用导出口令对（同一 validate 门槛）——快照在本地加密后才出网。 */
  const handleServerPush = async (): Promise<void> => {
    if (anyWriter) return;
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    setPushBusy(true);
    try {
      const resp = await personaAPI.backupPushToServer(passphrase);
      if (resp.success && resp.data) {
        setPassphrase('');
        setConfirm('');
        toast.success(
          resp.data.deduplicated
            ? t('settings.backup.serverPushedDedup')
            : t('settings.backup.serverPushed'),
        );
        await refreshEvidence();
        await refreshServerList();
      } else {
        setServerError(resp.error ?? t('settings.backup.serverPushFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverPushFailed'));
    } finally {
      setPushBusy(false);
    }
  };

  /** 服务器版本恢复：与文件恢复同口径（确认在前；换库成功即切解锁屏）。 */
  const handleServerRestore = async (item: BackupVersionView): Promise<void> => {
    if (anyWriter || listBusy) return;
    if (!serverPass) {
      setServerError(t('settings.backup.restoreNeedPass'));
      return;
    }
    if (
      !window.confirm(
        t('settings.backup.serverRestoreConfirm', { created: formatWhen(item.created_at) }),
      )
    ) {
      return;
    }
    setServerError(null);
    setRowBusyId(item.backup_id);
    try {
      const resp = await personaAPI.backupRestoreFromServer(item.backup_id, serverPass);
      if (resp.success && resp.data) {
        setServerPass('');
        // .bak 路径只进 toast：换库段成功即切解锁屏，节内 state 随卸载不可见
        toast.success(
          resp.data.backup_copy
            ? t('settings.backup.restoredWithBak', { path: resp.data.backup_copy })
            : t('settings.backup.restored'),
          { duration: 10_000 },
        );
        await refreshEvidence();
        await finalizeVaultRestore();
      } else {
        setServerError(resp.error ?? t('settings.backup.restoreFailed'));
      }
    } catch (err) {
      setServerError(err instanceof Error ? err.message : t('settings.backup.restoreFailed'));
    } finally {
      setRowBusyId(null);
    }
  };

  /** 删除服务器版本：只动服务器侧副本（404 幂等），不碰本机库。 */
  const handleServerDelete = async (item: BackupVersionView): Promise<void> => {
    if (rowBusyId !== null || listBusy) return;
    if (
      !window.confirm(
        t('settings.backup.serverDeleteConfirm', { created: formatWhen(item.created_at) }),
      )
    ) {
      return;
    }
    setServerError(null);
    setRowBusyId(item.backup_id);
    try {
      const resp = await personaAPI.backupDeleteServerVersion(item.backup_id);
      if (resp.success && resp.data) {
        toast.success(t('settings.backup.serverDeleted'));
        await refreshServerList();
      } else {
        setServerError(resp.error ?? t('settings.backup.serverDeleteFailed'));
      }
    } catch {
      setServerError(t('settings.backup.serverDeleteFailed'));
    } finally {
      setRowBusyId(null);
    }
  };

  return (
    <section className="mb-5" data-testid="backup-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.backup.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
        {t('settings.backup.description')}
      </p>
      <p
        className="text-xs text-red-600 dark:text-red-400 mb-2"
        data-testid="backup-disclosure"
      >
        {t('settings.backup.disclosure')}
      </p>

      <p className="text-sm text-gray-700 dark:text-gray-300 mb-2" data-testid="backup-evidence">
        {evidence
          ? t('settings.backup.lastExport', {
              time: new Date(evidence.exported_at).toLocaleString(),
              size: formatSize(evidence.size_bytes),
            })
          : t('settings.backup.neverExported')}
      </p>

      <div className="grid gap-2 max-w-md">
        <input
          type="password"
          data-testid="backup-passphrase"
          aria-label={t('settings.backup.passphrase')}
          placeholder={t('settings.backup.passphrase')}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoComplete="new-password"
          className="input"
        />
        <input
          type="password"
          data-testid="backup-passphrase-confirm"
          aria-label={t('settings.backup.passphraseConfirm')}
          placeholder={t('settings.backup.passphraseConfirm')}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          className="input"
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 dark:text-red-400 mt-2" data-testid="backup-error">
          {error}
        </p>
      )}

      <button
        type="button"
        onClick={() => void handleExport()}
        disabled={anyWriter}
        data-testid="backup-export-button"
        className="btn-secondary mt-3 inline-flex items-center gap-1.5 text-sm"
      >
        {busy ? t('settings.backup.exporting') : t('settings.backup.exportNow')}
      </button>

      {lastSha && (
        <p
          className="text-xs text-gray-400 dark:text-gray-500 mt-1 break-all"
          data-testid="backup-sha"
        >
          {t('settings.backup.sha256', { sha: lastSha })}
        </p>
      )}

      {/* 恢复区（S5 restore-from-file）：替换式操作——常驻警示 + 二次确认在前。
          与导出互斥进行（共用锁操作节奏，避免同时读写库文件） */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700" data-testid="backup-restore">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.backup.restoreTitle')}
        </p>
        <p
          className="text-xs text-red-600 dark:text-red-400 mb-2"
          data-testid="backup-restore-disclosure"
        >
          {t('settings.backup.restoreDisclosure')}
        </p>

        <div className="flex gap-2 max-w-md">
          <input
            readOnly
            data-testid="backup-restore-path"
            aria-label={t('settings.backup.restorePick')}
            placeholder={t('settings.backup.restorePathPlaceholder')}
            value={restorePath}
            className="input"
          />
          <button
            type="button"
            onClick={() => void handlePickRestoreFile()}
            disabled={anyWriter}
            data-testid="backup-restore-pick"
            className="btn-secondary shrink-0 text-sm"
          >
            {t('settings.backup.restorePick')}
          </button>
        </div>

        <div className="grid gap-2 max-w-md mt-2">
          <input
            type="password"
            data-testid="backup-restore-passphrase"
            aria-label={t('settings.backup.restorePassphrase')}
            placeholder={t('settings.backup.restorePassphrase')}
            value={restorePass}
            onChange={(e) => setRestorePass(e.target.value)}
            autoComplete="off"
            className="input"
          />
        </div>

        {restoreError && (
          <p
            className="text-sm text-red-600 dark:text-red-400 mt-2"
            data-testid="backup-restore-error"
          >
            {restoreError}
          </p>
        )}

        <button
          type="button"
          onClick={() => void handleRestore()}
          disabled={anyWriter}
          data-testid="backup-restore-button"
          className="btn-secondary mt-3 inline-flex items-center gap-1.5 text-sm"
        >
          {restoreBusy ? t('settings.backup.restoring') : t('settings.backup.restoreNow')}
        </button>
      </div>

      {/* 服务器密文仓（S5-d）：默认关闭——仅在显式配置 persona-server 后可用；
          出网的只有口令加密后的密文（范围见 serverDescription）。推送需解锁，
          列表/恢复免解锁（锁屏救库）；恢复同文件恢复口径，二次确认在前 */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700" data-testid="backup-server">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.backup.serverTitle')}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
          {t('settings.backup.serverDescription')}
        </p>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void handleServerPush()}
            disabled={anyWriter}
            data-testid="backup-server-push"
            className="btn-secondary inline-flex items-center gap-1.5 text-sm"
          >
            {pushBusy ? t('settings.backup.serverPushing') : t('settings.backup.serverPushNow')}
          </button>
          <button
            type="button"
            onClick={() => void refreshServerList()}
            disabled={listBusy || anyWriter}
            data-testid="backup-server-refresh"
            className="btn-secondary inline-flex items-center gap-1.5 text-sm"
          >
            {listBusy ? t('settings.backup.serverListing') : t('settings.backup.serverRefresh')}
          </button>
        </div>

        <input
          type="password"
          data-testid="backup-server-passphrase"
          aria-label={t('settings.backup.serverRestorePassphrase')}
          placeholder={t('settings.backup.serverRestorePassphrase')}
          value={serverPass}
          onChange={(e) => setServerPass(e.target.value)}
          autoComplete="off"
          className="input mt-2 max-w-md"
        />

        {serverError && (
          <p
            className="text-sm text-red-600 dark:text-red-400 mt-2"
            data-testid="backup-server-error"
          >
            {serverError}
          </p>
        )}

        <div className="mt-2" data-testid="backup-server-list">
          {serverItems !== null && serverItems.length === 0 && (
            <p
              className="text-xs text-gray-500 dark:text-gray-400"
              data-testid="backup-server-empty"
            >
              {t('settings.backup.serverEmpty')}
            </p>
          )}
          {(serverItems ?? []).map((item) => (
            <div
              key={item.backup_id}
              data-testid="backup-server-item"
              className="flex flex-wrap items-center gap-2 py-1"
            >
              <span className="text-xs text-gray-700 dark:text-gray-300 break-all">
                {t('settings.backup.serverRow', {
                  device: item.device_name,
                  time: formatWhen(item.created_at),
                  size: formatSize(item.size_bytes),
                })}
              </span>
              <button
                type="button"
                onClick={() => void handleServerRestore(item)}
                disabled={anyWriter || listBusy}
                data-testid="backup-server-restore"
                className="btn-secondary text-xs"
              >
                {t('settings.backup.serverRestore')}
              </button>
              <button
                type="button"
                onClick={() => void handleServerDelete(item)}
                disabled={rowBusyId !== null || listBusy}
                data-testid="backup-server-delete"
                className="btn-secondary text-xs"
              >
                {t('settings.backup.serverDelete')}
              </button>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default BackupSection;
