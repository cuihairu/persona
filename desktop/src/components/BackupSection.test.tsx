import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import BackupSection from './BackupSection';
import { personaAPI } from '@/utils/api';
import { save as saveDialog } from '@tauri-apps/plugin-dialog';
import type { BackupEvidence, BackupExportOutcome } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getWorkspaceSettings: jest.fn(),
    backupExportToFile: jest.fn(),
  },
}));

// 原生保存对话框只在用户点击导出时触发；jsdom 下哑掉
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
  save: jest.fn(),
}));

const mockGetSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockExport = personaAPI.backupExportToFile as jest.Mock;
const mockSave = saveDialog as jest.Mock;

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

beforeEach(() => {
  jest.clearAllMocks();
  mockGetSettings.mockResolvedValue(settingsWith(null));
  mockSave.mockResolvedValue('/tmp/vault-backup.enc');
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
});
