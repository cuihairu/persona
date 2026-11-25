import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SyncMethodsSection from './SyncMethodsSection';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getWorkspaceSettings: jest.fn(),
    syncGroupStatus: jest.fn(),
    syncDeviceStatus: jest.fn(),
    setSyncMethods: jest.fn(),
  },
}));

const mockSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockGroup = personaAPI.syncGroupStatus as jest.Mock;
const mockDevice = personaAPI.syncDeviceStatus as jest.Mock;
const mockSet = personaAPI.setSyncMethods as jest.Mock;

const SERVER_TRUTH = {
  success: true,
  data: { sync_methods: { cross_device_sync: true, account_sync: false } },
};

function mockReady(): void {
  mockSettings.mockResolvedValue(SERVER_TRUTH);
  // Derived states: cross-device joined, account not joined
  mockGroup.mockResolvedValue({ success: true, data: true });
  mockDevice.mockResolvedValue({ success: true, data: { joined: false } });
  mockSet.mockResolvedValue(SERVER_TRUTH);
}

/** Toggles are disabled while preferences haven't loaded; wait for them to become available (never click a dead button). */
async function waitForCrossToggle(): Promise<void> {
  await waitFor(() => {
    expect(screen.getByTestId('sync-method-cross-device-toggle')).toHaveAttribute(
      'aria-checked',
      'true',
    );
  });
}

beforeEach(() => {
  jest.clearAllMocks();
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('components/settings/SyncMethodsSection', () => {
  it('renders both toggles from server truth plus the derived keyring states', async () => {
    mockReady();
    render(<SyncMethodsSection />);

    await waitForCrossToggle();
    const cross = screen.getByTestId('sync-method-cross-device-toggle');
    const account = screen.getByTestId('sync-method-account-toggle');
    expect(cross).toHaveAttribute('aria-checked', 'true');
    expect(account).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('sync-method-cross-device-state')).toHaveTextContent('已加入');
    expect(screen.getByTestId('sync-method-account-state')).toHaveTextContent('未加入');
  });

  it('asks for confirmation when disabling cross-device sync while still joined', async () => {
    mockReady();
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    render(<SyncMethodsSection />);
    await waitForCrossToggle();

    fireEvent.click(screen.getByTestId('sync-method-cross-device-toggle'));

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(mockSet).not.toHaveBeenCalled();
    // Cancel: no optimistic flip, the toggle stays on (server truth unchanged)
    expect(screen.getByTestId('sync-method-cross-device-toggle')).toHaveAttribute(
      'aria-checked',
      'true',
    );
    confirmSpy.mockRestore();
  });

  it('writes the preference pair and backfills the server truth on a confirmed disable', async () => {
    mockReady();
    mockSet.mockResolvedValue({
      success: true,
      data: { sync_methods: { cross_device_sync: false, account_sync: false } },
    });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    render(<SyncMethodsSection />);
    await waitForCrossToggle();

    fireEvent.click(screen.getByTestId('sync-method-cross-device-toggle'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(false, false);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-method-cross-device-toggle')).toHaveAttribute(
        'aria-checked',
        'false',
      );
    });
    confirmSpy.mockRestore();
  });

  it('toggles account sync without confirmation and leaves cross-device untouched', async () => {
    mockReady();
    // Backfill with server truth (the save response echoes the new preferences back verbatim)
    mockSet.mockResolvedValue({
      success: true,
      data: { sync_methods: { cross_device_sync: true, account_sync: true } },
    });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    render(<SyncMethodsSection />);
    await waitForCrossToggle();

    fireEvent.click(screen.getByTestId('sync-method-account-toggle'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(true, true);
    });
    expect(screen.getByTestId('sync-method-account-toggle')).toHaveAttribute('aria-checked', 'true');
    // The cross-device toggle's semantics are not coupled to the account toggle
    expect(screen.getByTestId('sync-method-cross-device-toggle')).toHaveAttribute(
      'aria-checked',
      'true',
    );
    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });
});
