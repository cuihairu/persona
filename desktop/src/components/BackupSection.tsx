import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { save as saveFileDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';
import type { BackupEvidence } from '@/types';

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

/**
 * 自救口备份节（S5 第一批）：整库加密备份导出到本地文件。
 *
 * 备份链与主密码无关（主库不解密），备份口令由用户自定且**永不落盘**；
 * 风险披露常驻（设计稿 §6.5）：设备全丢 = 库全丢，唯一自救 = 备份文件。
 * 导出凭证（时刻/目标/尺寸，非敏感元数据）由后端写入 settings.backup，
 * 本节挂载时读回展示「上次导出」。服务器密文仓目标属后续批。
 */
const BackupSection: React.FC = () => {
  const { t } = useTranslation();
  const [evidence, setEvidence] = useState<BackupEvidence | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** 最近一次导出的 sha256（成功后展示，供用户与文件指纹对账） */
  const [lastSha, setLastSha] = useState<string | null>(null);

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

  const validate = (): string | null => {
    if (!passphrase || !confirm) return t('settings.backup.passRequired');
    if (passphrase.length < 8) return t('settings.backup.passTooShort');
    if (passphrase !== confirm) return t('settings.backup.passMismatch');
    return null;
  };

  const handleExport = async (): Promise<void> => {
    if (busy) return;
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
        disabled={busy}
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
    </section>
  );
};

export default BackupSection;
