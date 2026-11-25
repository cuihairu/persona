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
    // Used by SyncConflictsModal (a child component of this section)
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

/** Joined state: the status row and the sync-now button are visible */
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
    // Does not fall back to the generic "sync failed" toast
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
