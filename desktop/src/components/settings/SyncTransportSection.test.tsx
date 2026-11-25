import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SyncTransportSection from './SyncTransportSection';
import { personaAPI } from '@/utils/api';
import { open as openDialog } from '@tauri-apps/plugin-dialog';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getWorkspaceSettings: jest.fn(),
    setSyncTransport: jest.fn(),
  },
}));

jest.mock('@tauri-apps/plugin-dialog', () => ({ open: jest.fn() }));

const mockSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockSet = personaAPI.setSyncTransport as jest.Mock;
const mockOpen = openDialog as jest.Mock;

function mockServer(dir: string | null = null): void {
  mockSettings.mockResolvedValue({
    success: true,
    data: { sync: { enabled: true, server_url: 'https://s.example', server_token: '', sync_transport: 'server', cloud_drive_dir: dir } },
  });
}

function mockCloud(dir = '/Cloud/Dropbox'): void {
  mockSettings.mockResolvedValue({
    success: true,
    data: { sync: { enabled: true, server_url: 'https://s.example', server_token: '', sync_transport: 'cloud', cloud_drive_dir: dir } },
  });
}

function mockSetOk(transport: string, dir: string | null): void {
  mockSet.mockResolvedValue({
    success: true,
    data: { sync: { enabled: true, server_url: 'https://s.example', server_token: '', sync_transport: transport, cloud_drive_dir: dir } },
  });
}

beforeEach(() => {
  jest.clearAllMocks();
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('components/settings/SyncTransportSection', () => {
  it('renders both transports and marks the server active from server truth', async () => {
    mockServer();
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'false');
    // server active → no cloud folder row
    expect(screen.queryByTestId('sync-cloud-dir-input')).not.toBeInTheDocument();
  });

  it('defaults to server and hides the folder row when the vault has no sync config', async () => {
    mockSettings.mockResolvedValue({ success: true, data: { sync: null } });
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.queryByTestId('sync-cloud-dir-input')).not.toBeInTheDocument();
  });

  it('shows the cloud folder row when cloud transport is active with a dir', async () => {
    mockCloud();
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('sync-cloud-dir-input')).toHaveValue('/Cloud/Dropbox');
    expect(screen.getByTestId('sync-cloud-pick-dir')).toBeInTheDocument();
  });

  it('switches to server, preserving the existing cloud dir, and backfills truth', async () => {
    mockCloud();
    mockSetOk('server', '/Cloud/Dropbox');
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'true');
    });

    fireEvent.click(screen.getByTestId('sync-transport-server'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith('server', '/Cloud/Dropbox');
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'false');
    // folder row hidden once back on server
    await waitFor(() => {
      expect(screen.queryByTestId('sync-cloud-dir-input')).not.toBeInTheDocument();
    });
  });

  it('opens the folder picker when switching to cloud without a dir, then saves', async () => {
    mockServer(null);
    mockOpen.mockResolvedValue('/Cloud/iCloud');
    mockSetOk('cloud', '/Cloud/iCloud');
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'true');
    });

    fireEvent.click(screen.getByTestId('sync-transport-cloud'));

    await waitFor(() => {
      expect(mockOpen).toHaveBeenCalledWith({ directory: true, multiple: false });
    });
    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith('cloud', '/Cloud/iCloud');
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('sync-cloud-dir-input')).toHaveValue('/Cloud/iCloud');
  });

  it('does not save when the folder picker is cancelled', async () => {
    mockServer(null);
    mockOpen.mockResolvedValue(null);
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'true');
    });

    fireEvent.click(screen.getByTestId('sync-transport-cloud'));

    await waitFor(() => {
      expect(mockOpen).toHaveBeenCalled();
    });
    // Cancel: no config write, no flip (still server)
    expect(mockSet).not.toHaveBeenCalled();
    expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'false');
  });

  it('keeps the real state (no optimistic flip) when the write fails', async () => {
    mockCloud();
    mockSet.mockResolvedValue({ success: false, error: 'boom' });
    render(<SyncTransportSection />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'true');
    });

    // Switch to server: write fails → server truth unchanged, UI keeps cloud (no optimistic flip)
    fireEvent.click(screen.getByTestId('sync-transport-server'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith('server', '/Cloud/Dropbox');
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-transport-cloud')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('sync-transport-server')).toHaveAttribute('aria-checked', 'false');
  });
});
