import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import BackupSection from './BackupSection';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import type { BackupEvidence, BackupExportOutcome, BackupRestoreOutcome } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getWorkspaceSettings: jest.fn(),
    backupExportToFile: jest.fn(),
    backupRestoreFromFile: jest.fn(),
  },
}));

// 恢复成功后的收尾（清内存 + 重探解锁态）在 hook 里；本文件只关心它被调用
jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

// 原生保存/打开对话框只在用户点击时触发；jsdom 下哑掉
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
  save: jest.fn(),
}));

const mockGetSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockExport = personaAPI.backupExportToFile as jest.Mock;
const mockRestore = personaAPI.backupRestoreFromFile as jest.Mock;
const mockSave = saveDialog as jest.Mock;
const mockOpen = openDialog as jest.Mock;
const mockFinalizeVaultRestore = jest.fn();

const settingsWith = (backup: BackupEvidence | null) => ({
  success: true,
  data: { backup },
});

const evidence = (overrides: Partial<BackupEvidence> = {}): BackupEvidence => ({
  exported_at: '2026-10-07T09:30:00Z',
  destination: 'file',
  size_bytes: 20480,
  ...overrides,
});

const outcome = (overrides: Partial<BackupExportOutcome> = {}): BackupExportOutcome => ({
  path: '/tmp/vault-backup.enc',
  size_bytes: 4096,
  sha256: 'ab'.repeat(32),
  exported_at: '2026-10-07T10:00:00Z',
  ...overrides,
});

const restoreOutcome = (overrides: Partial<BackupRestoreOutcome> = {}): BackupRestoreOutcome => ({
  backup_copy: '/vault/persona.db.bak',
  ...overrides,
});

beforeEach(() => {
  jest.clearAllMocks();
  mockGetSettings.mockResolvedValue(settingsWith(null));
  mockSave.mockResolvedValue('/tmp/vault-backup.enc');
  mockRestore.mockResolvedValue({ success: true, data: restoreOutcome() });
  (usePersonaService as jest.Mock).mockReturnValue({
    finalizeVaultRestore: mockFinalizeVaultRestore,
  });
  mockFinalizeVaultRestore.mockResolvedValue(undefined);
});

function fillValidPassphrases(): void {
  fireEvent.change(screen.getByTestId('backup-passphrase'), {
    target: { value: 'long-enough-pass' },
  });
  fireEvent.change(screen.getByTestId('backup-passphrase-confirm'), {
    target: { value: 'long-enough-pass' },
  });
}

describe('components/BackupSection', () => {
  it('shows the standing data-loss disclosure and never-exported state', async () => {
    render(<BackupSection />);

    expect(screen.getByTestId('backup-disclosure')).toHaveTextContent('设备丢失或损坏');
    await waitFor(() => {
      expect(screen.getByTestId('backup-evidence')).toHaveTextContent('尚未在本机导出过备份');
    });
  });

  it('shows last export evidence read back from settings', async () => {
    mockGetSettings.mockResolvedValue(settingsWith(evidence()));
    render(<BackupSection />);

    await waitFor(() => {
      expect(screen.getByTestId('backup-evidence')).toHaveTextContent('上次导出');
    });
  });

  it('rejects a short passphrase without opening the save dialog', async () => {
    render(<BackupSection />);
    fireEvent.change(screen.getByTestId('backup-passphrase'), {
      target: { value: 'short' },
    });
    fireEvent.change(screen.getByTestId('backup-passphrase-confirm'), {
      target: { value: 'short' },
    });
    fireEvent.click(screen.getByTestId('backup-export-button'));

    await waitFor(() => {
      expect(screen.getByTestId('backup-error')).toHaveTextContent('至少需要 8 位');
    });
    expect(mockSave).not.toHaveBeenCalled();
    expect(mockExport).not.toHaveBeenCalled();
  });

  it('rejects mismatched passphrase confirmation without exporting', async () => {
    render(<BackupSection />);
    fireEvent.change(screen.getByTestId('backup-passphrase'), {
      target: { value: 'long-enough-pass' },
    });
    fireEvent.change(screen.getByTestId('backup-passphrase-confirm'), {
      target: { value: 'different-pass' },
    });
    fireEvent.click(screen.getByTestId('backup-export-button'));

    await waitFor(() => {
      expect(screen.getByTestId('backup-error')).toHaveTextContent('两次输入的备份口令不一致');
    });
    expect(mockSave).not.toHaveBeenCalled();
    expect(mockExport).not.toHaveBeenCalled();
  });

  it('exports via the save dialog, shows sha and refreshes evidence', async () => {
    mockGetSettings
      .mockResolvedValueOnce(settingsWith(null))
      .mockResolvedValueOnce(settingsWith(evidence({ exported_at: '2026-10-07T10:00:00Z' })));
    mockExport.mockResolvedValue({ success: true, data: outcome() });
    render(<BackupSection />);
    await waitFor(() => {
      expect(screen.getByTestId('backup-evidence')).toHaveTextContent('尚未在本机导出过备份');
    });

    fillValidPassphrases();
    fireEvent.click(screen.getByTestId('backup-export-button'));

    await waitFor(() => {
      expect(mockExport).toHaveBeenCalledWith('/tmp/vault-backup.enc', 'long-enough-pass');
    });
    await waitFor(() => {
      expect(screen.getByTestId('backup-sha')).toHaveTextContent(`SHA-256：${'ab'.repeat(32)}`);
    });
    await waitFor(() => {
      expect(screen.getByTestId('backup-evidence')).toHaveTextContent('上次导出');
    });
    // 成功后口令输入清空（不在 state 留密）
    expect((screen.getByTestId('backup-passphrase') as HTMLInputElement).value).toBe('');
    expect((screen.getByTestId('backup-passphrase-confirm') as HTMLInputElement).value).toBe('');
  });

  it('surfaces backend failures inline and keeps the inputs', async () => {
    mockExport.mockResolvedValue({
      success: false,
      error: 'Failed to create backup: bad passphrase',
    });
    render(<BackupSection />);

    fillValidPassphrases();
    fireEvent.click(screen.getByTestId('backup-export-button'));

    await waitFor(() => {
      expect(screen.getByTestId('backup-error')).toHaveTextContent(
        'Failed to create backup: bad passphrase',
      );
    });
    expect((screen.getByTestId('backup-passphrase') as HTMLInputElement).value).toBe(
      'long-enough-pass',
    );
    expect(screen.queryByTestId('backup-sha')).not.toBeInTheDocument();
  });

  it('does nothing when the save dialog is cancelled', async () => {
    mockSave.mockResolvedValue(null);
    render(<BackupSection />);

    fillValidPassphrases();
    fireEvent.click(screen.getByTestId('backup-export-button'));

    await waitFor(() => {
      expect(mockSave).toHaveBeenCalled();
    });
    expect(mockExport).not.toHaveBeenCalled();
    expect(screen.queryByTestId('backup-error')).not.toBeInTheDocument();
  });

  /** 通过打开对话框选中备份文件（默认 /tmp/backup.enc） */
  async function pickRestoreFile(path = '/tmp/backup.enc'): Promise<void> {
    mockOpen.mockResolvedValue(path);
    fireEvent.click(screen.getByTestId('backup-restore-pick'));
    await waitFor(() => {
      expect((screen.getByTestId('backup-restore-path') as HTMLInputElement).value).toBe(path);
    });
  }

  it('restores from a picked file after confirmation, then finalizes the session', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockGetSettings
      .mockResolvedValueOnce(settingsWith(null))
      .mockResolvedValueOnce(settingsWith(evidence()));
    render(<BackupSection />);
    await waitFor(() => {
      expect(screen.getByTestId('backup-evidence')).toHaveTextContent('尚未在本机导出过备份');
    });

    await pickRestoreFile();
    fireEvent.change(screen.getByTestId('backup-restore-passphrase'), {
      target: { value: 'backup-pass' },
    });
    fireEvent.click(screen.getByTestId('backup-restore-button'));

    await waitFor(() => {
      expect(mockRestore).toHaveBeenCalledWith('/tmp/backup.enc', 'backup-pass');
    });
    expect(window.confirm).toHaveBeenCalled();
    // 换库段成功：清旧库内存 + 重探解锁态（App 随即切解锁屏）
    await waitFor(() => {
      expect(mockFinalizeVaultRestore).toHaveBeenCalledTimes(1);
    });
    // 成功后口令清空（不在 state 留密）
    expect((screen.getByTestId('backup-restore-passphrase') as HTMLInputElement).value).toBe('');
    expect(screen.queryByTestId('backup-restore-error')).not.toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it('validates file and passphrase before the confirmation dialog', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BackupSection />);

    fireEvent.click(screen.getByTestId('backup-restore-button'));
    await waitFor(() => {
      expect(screen.getByTestId('backup-restore-error')).toHaveTextContent('请先选择备份文件');
    });

    await pickRestoreFile();
    fireEvent.click(screen.getByTestId('backup-restore-button'));
    await waitFor(() => {
      expect(screen.getByTestId('backup-restore-error')).toHaveTextContent('请输入备份口令');
    });

    expect(confirmSpy).not.toHaveBeenCalled();
    expect(mockRestore).not.toHaveBeenCalled();
    expect(mockFinalizeVaultRestore).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it('does nothing when the restore confirmation is declined', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    render(<BackupSection />);
    await pickRestoreFile();
    fireEvent.change(screen.getByTestId('backup-restore-passphrase'), {
      target: { value: 'backup-pass' },
    });
    fireEvent.click(screen.getByTestId('backup-restore-button'));

    await waitFor(() => expect(confirmSpy).toHaveBeenCalled());
    expect(mockRestore).not.toHaveBeenCalled();
    expect(mockFinalizeVaultRestore).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it('keeps the path empty when the file dialog is cancelled', async () => {
    mockOpen.mockResolvedValue(null);
    render(<BackupSection />);

    fireEvent.click(screen.getByTestId('backup-restore-pick'));
    await waitFor(() => expect(mockOpen).toHaveBeenCalled());
    expect((screen.getByTestId('backup-restore-path') as HTMLInputElement).value).toBe('');
    expect(screen.queryByTestId('backup-restore-error')).not.toBeInTheDocument();
  });

  it('surfaces restore failures inline and keeps the session untouched', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockRestore.mockResolvedValue({
      success: false,
      error: 'Backup restore failed; the current vault was not touched: bad passphrase',
    });
    render(<BackupSection />);
    await pickRestoreFile();
    fireEvent.change(screen.getByTestId('backup-restore-passphrase'), {
      target: { value: 'wrong-pass' },
    });
    fireEvent.click(screen.getByTestId('backup-restore-button'));

    await waitFor(() => {
      expect(screen.getByTestId('backup-restore-error')).toHaveTextContent(
        'Backup restore failed; the current vault was not touched: bad passphrase',
      );
    });
    // staged 复验失败 = 库与会话都没动：输入保留、收尾不跑
    expect((screen.getByTestId('backup-restore-passphrase') as HTMLInputElement).value).toBe(
      'wrong-pass',
    );
    expect(mockFinalizeVaultRestore).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });
});
