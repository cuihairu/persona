import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import toast from 'react-hot-toast';
import i18n from '@/i18n';
import SyncDevicesSection from './SyncDevicesSection';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    syncDeviceStatus: jest.fn(),
    syncListDevices: jest.fn(),
    syncJoin: jest.fn(),
    syncNow: jest.fn(),
    syncRotate: jest.fn(),
    syncLeave: jest.fn(),
    syncAuthorize: jest.fn(),
    syncRevoke: jest.fn(),
    syncSetDeviceRemark: jest.fn(),
    syncStatus: jest.fn().mockResolvedValue({ success: true, data: null }),
    // SyncConflictsModal（本区块子组件）用到的
    syncConflictsList: jest.fn(),
    syncConflictResolve: jest.fn(),
  },
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const mockStatus = personaAPI.syncDeviceStatus as jest.Mock;
const mockListDevices = personaAPI.syncListDevices as jest.Mock;
const mockSyncNow = personaAPI.syncNow as jest.Mock;
const mockToastError = toast.error as jest.Mock;

/** 已入组态：状态行 + 立即同步按钮可见 */
function mockJoined(): void {
  mockStatus.mockResolvedValue({
    success: true,
    data: {
      joined: true,
      corrupted: false,
      device_id: 'd1',
      device_name: '我的笔记本',
    },
  });
  mockListDevices.mockResolvedValue({ success: true, data: [] });
}

beforeEach(() => {
  jest.clearAllMocks();
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('components/settings/SyncDevicesSection — sync failure surfacing (CLOUD_DRIVE_SYNC §9.4)', () => {
  it('surfaces a server-transport failure distinctly (server unreachable)', async () => {
    mockJoined();
    mockSyncNow.mockResolvedValue({
      success: false,
      error: 'Sync cycle failed: IO operation failed: sync status request failed: timed out',
      error_code: 'SYNC_SERVER_UNREACHABLE',
    });
    render(<SyncDevicesSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('sync-now-button'));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        i18n.t('settings.syncDevices.serverUnreachable'),
      );
    });
    // 不走通用「同步失败」兜底
    expect(mockToastError).not.toHaveBeenCalledWith(
      i18n.t('settings.syncDevices.syncFailed'),
    );
  });

  it('surfaces a cloud-folder failure distinctly (cloud folder unavailable)', async () => {
    mockJoined();
    mockSyncNow.mockResolvedValue({
      success: false,
      error: 'Sync session failed: IO operation failed: create cloud drive dir failed: ENOENT',
      error_code: 'SYNC_CLOUD_FOLDER_UNAVAILABLE',
    });
    render(<SyncDevicesSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('sync-now-button'));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        i18n.t('settings.syncDevices.cloudFolderUnavailable'),
      );
    });
  });

  it('falls back to the raw error message for failures without a sync code', async () => {
    mockJoined();
    const raw = 'Vault is locked: unlock to sync';
    mockSyncNow.mockResolvedValue({ success: false, error: raw });
    render(<SyncDevicesSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('sync-now-button'));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(raw);
    });
  });
});
