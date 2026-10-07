import { act, renderHook, waitFor } from '@testing-library/react';
import { computeDataLossRisk, useDataLossRisk } from '@/hooks/useDataLossRisk';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    syncGroupStatus: jest.fn(),
    syncListDevices: jest.fn(),
    getWorkspaceSettings: jest.fn(),
  },
}));

const mockStatus = personaAPI.syncGroupStatus as jest.Mock;
const mockDevices = personaAPI.syncListDevices as jest.Mock;
const mockSettings = personaAPI.getWorkspaceSettings as jest.Mock;

describe('useDataLossRisk', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('merges three sources and reports high on a lone unbacked device', async () => {
    mockStatus.mockResolvedValue({ success: true, data: true });
    mockDevices.mockResolvedValue({ success: true, data: [{ id: 'd1' }] });
    mockSettings.mockResolvedValue({ success: true, data: { backup: null, account: null } });

    const { result } = renderHook(() => useDataLossRisk());
    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    expect(result.current.joined).toBe(true);
    expect(result.current.deviceCount).toBe(1);
    expect(result.current.hasBackup).toBe(false);
    expect(result.current.hasAccount).toBe(false);
    expect(result.current.level).toBe('high');
  });

  it('treats a failed source as not-joined (fail-safe, level none)', async () => {
    mockStatus.mockRejectedValue(new Error('backend down'));
    mockDevices.mockResolvedValue({ success: true, data: [] });
    mockSettings.mockResolvedValue({ success: true, data: {} });

    const { result } = renderHook(() => useDataLossRisk());
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    expect(result.current.level).toBe('none');
  });

  it('counts devices from a failed device list as zero but stays honest on level', async () => {
    mockStatus.mockResolvedValue({ success: true, data: true });
    mockDevices.mockResolvedValue({ success: false, data: null });
    mockSettings.mockResolvedValue({ success: true, data: { backup: null, account: null } });

    const { result } = renderHook(() => useDataLossRisk());
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
    // 设备清单读取失败 → 计 0 台 → 单设备高危（保守口径，不谎报已解除）
    expect(result.current.deviceCount).toBe(0);
    expect(result.current.level).toBe('high');
  });

  it('refresh re-reads the sources and lifts the warning after a backup export', async () => {
    mockStatus.mockResolvedValue({ success: true, data: true });
    mockDevices.mockResolvedValue({ success: true, data: [{ id: 'd1' }] });
    mockSettings.mockResolvedValueOnce({ success: true, data: { backup: null, account: null } });

    const { result } = renderHook(() => useDataLossRisk());
    await waitFor(() => {
      expect(result.current.level).toBe('high');
    });

    mockSettings.mockResolvedValue({
      success: true,
      data: { backup: { exported_at: '2026-10-07T09:30:00Z' }, account: null },
    });
    await act(async () => {
      await result.current.refresh();
    });
    expect(result.current.hasBackup).toBe(true);
    expect(result.current.level).toBe('none');
  });
});

describe('computeDataLossRisk', () => {
  it('returns none when not joined', () => {
    expect(computeDataLossRisk({ joined: false, deviceCount: 1, hasBackup: false, hasAccount: false })).toBe('none');
  });

  it('returns none when deviceCount >= 2', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 2, hasBackup: false, hasAccount: false })).toBe('none');
  });

  it('returns none when hasBackup is true', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: true, hasAccount: false })).toBe('none');
  });

  it('returns medium when hasAccount is true and no backup', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: false, hasAccount: true })).toBe('medium');
  });

  it('returns high when no account, no backup, single device, joined', () => {
    expect(computeDataLossRisk({ joined: true, deviceCount: 1, hasBackup: false, hasAccount: false })).toBe('high');
  });
});