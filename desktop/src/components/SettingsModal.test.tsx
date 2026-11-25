import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import SettingsModal from './SettingsModal';
import i18n from '@/i18n';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import toast from 'react-hot-toast';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    setFeatureFlags: jest.fn(),
    getWorkspaceSettings: jest.fn(),
    setSyncConfig: jest.fn(),
    syncTokenPresent: jest.fn(),
    setPasswordExpiry: jest.fn(),
    changeMasterPassword: jest.fn(),
    biometricStatus: jest.fn(),
    biometricEnable: jest.fn(),
    biometricDisable: jest.fn(),
    getTravelStatus: jest.fn(),
    setTravelMarked: jest.fn(),
    enterTravelMode: jest.fn(),
    exitTravelMode: jest.fn(),
    reauthVerify: jest.fn(),
    // The Connect local-automation section (the section after SecurityPane)
    connectServerStatus: jest.fn(),
    connectServerStart: jest.fn(),
    connectServerStop: jest.fn(),
    connectTokenList: jest.fn(),
    connectTokenCreate: jest.fn(),
    connectTokenRevoke: jest.fn(),
    getIdentities: jest.fn(),
    // E2EE sync device management
    syncDeviceStatus: jest.fn(),
    syncJoin: jest.fn(),
    syncLeave: jest.fn(),
    syncListDevices: jest.fn(),
    syncSetDeviceRemark: jest.fn(),
    syncAuthorize: jest.fn(),
    syncRevoke: jest.fn(),
    syncNow: jest.fn(),
    syncStatus: jest.fn(),
    syncRotate: jest.fn(),
    syncConflictsList: jest.fn(),
    syncConflictResolve: jest.fn(),
    // SSH goes through the persona agent (the IdentityAgent anchor block in ~/.ssh/config)
    sshAgentIntegrationStatus: jest.fn(),
    sshAgentIntegrationEnable: jest.fn(),
    sshAgentIntegrationDisable: jest.fn(),
    // Locale switching (GeneralPane's locale-select) and the tray-copy push that follows
    setLocale: jest.fn(),
    setTrayLocale: jest.fn().mockResolvedValue({ success: true, data: true }),
  },
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const mockSetFlags = personaAPI.setFeatureFlags as jest.Mock;
const mockSetLocale = personaAPI.setLocale as jest.Mock;
const mockSetTrayLocale = personaAPI.setTrayLocale as jest.Mock;
const mockGetSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockSetSync = personaAPI.setSyncConfig as jest.Mock;
const mockTokenPresent = personaAPI.syncTokenPresent as jest.Mock;
const mockSetExpiry = personaAPI.setPasswordExpiry as jest.Mock;
const mockChangePw = personaAPI.changeMasterPassword as jest.Mock;
const mockBiometricStatus = personaAPI.biometricStatus as jest.Mock;
const mockBiometricEnable = personaAPI.biometricEnable as jest.Mock;
const mockBiometricDisable = personaAPI.biometricDisable as jest.Mock;
const mockGetTravelStatus = personaAPI.getTravelStatus as jest.Mock;
const mockSetTravelMarked = personaAPI.setTravelMarked as jest.Mock;
const mockEnterTravel = personaAPI.enterTravelMode as jest.Mock;
const mockExitTravel = personaAPI.exitTravelMode as jest.Mock;
const mockReauthVerify = personaAPI.reauthVerify as jest.Mock;
const mockConnectStatus = personaAPI.connectServerStatus as jest.Mock;
const mockConnectList = personaAPI.connectTokenList as jest.Mock;
const mockGetIdentities = personaAPI.getIdentities as jest.Mock;
const mockSyncStatus = personaAPI.syncDeviceStatus as jest.Mock;
const mockSyncJoin = personaAPI.syncJoin as jest.Mock;
const mockSyncLeave = personaAPI.syncLeave as jest.Mock;
const mockSyncList = personaAPI.syncListDevices as jest.Mock;
const mockSyncSetRemark = personaAPI.syncSetDeviceRemark as jest.Mock;
const mockSyncAuthorize = personaAPI.syncAuthorize as jest.Mock;
const mockSyncRevoke = personaAPI.syncRevoke as jest.Mock;
const mockSyncNow = personaAPI.syncNow as jest.Mock;
const mockSyncStatusReport = personaAPI.syncStatus as jest.Mock;
const mockSyncRotate = personaAPI.syncRotate as jest.Mock;
const mockSyncConflictsList = personaAPI.syncConflictsList as jest.Mock;

const inactiveTravel = {
  success: true,
  data: { active: false, entered_at: null, sidecar_exists: false, inconsistent: false },
};

/** Empty settings response (SyncServerPane's initial load) */
const emptySettings = { success: true, data: null };

/** General is visible by default; identity-management cases must first switch to the Identities tab */
const openIdentitiesTab = () => {
  fireEvent.click(screen.getByRole('tab', { name: '身份' }));
};

/** Helper for typing into the travel-passphrase modal */
const typeTravel = (value: string) =>
  fireEvent.change(screen.getByTestId('travel-passphrase-input'), { target: { value } });
const typeTravelConfirm = (value: string) =>
  fireEvent.change(screen.getByTestId('travel-passphrase-confirm-input'), {
    target: { value },
  });

describe('components/SettingsModal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // theme survives across cases in the store; reset it per case
    useAppStore.setState({ theme: 'system', featureFlags: { ...DEFAULT_FEATURE_FLAGS } });
    mockGetSettings.mockResolvedValue(emptySettings);
    // The keyring has no token by default (placeholder = 'API token')
    mockTokenPresent.mockResolvedValue({ success: true, data: false });
    // Biometrics are unavailable by default on this system (toggle disabled + unavailable hint)
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: false, enabled: false, platform: 'linux-polkit' },
    });
    // Travel mode is off by default
    mockGetTravelStatus.mockResolvedValue(inactiveTravel);
    // The Connect listener is off by default, with no token and no identity
    mockConnectStatus.mockResolvedValue({ success: true, data: { running: false, port: null } });
    mockConnectList.mockResolvedValue({ success: true, data: [] });
    mockGetIdentities.mockResolvedValue({ success: true, data: [] });
    // Not joined to E2EE sync by default (the join form is visible and no device list is fetched)
    mockSyncStatus.mockResolvedValue({
      success: true,
      data: { joined: false, corrupted: false, device_id: null, device_name: null },
    });
    // The watermark query returns no data by default (row hidden; cases override it with a concrete snapshot)
    mockSyncStatusReport.mockResolvedValue({ success: true, data: null });
    // The SSH integration section is not enabled by default (the section renders its steady-state badge from data)
    (personaAPI.sshAgentIntegrationStatus as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        enabled: false,
        anomaly: null,
        manualEntry: false,
        configPath: '/home/user/.ssh/config',
        socketPath: '/run/user/1000/persona/ssh-agent.sock',
        identityAgent: null,
        sshVersion: null,
      },
    });
    (personaAPI.sshAgentIntegrationEnable as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        enabled: true,
        anomaly: null,
        manualEntry: false,
        configPath: '/home/user/.ssh/config',
        socketPath: '/run/user/1000/persona/ssh-agent.sock',
        identityAgent: '/run/user/1000/persona/ssh-agent.sock',
        sshVersion: null,
      },
    });
    (personaAPI.sshAgentIntegrationDisable as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        enabled: false,
        anomaly: null,
        manualEntry: false,
        configPath: '/home/user/.ssh/config',
        socketPath: '/run/user/1000/persona/ssh-agent.sock',
        identityAgent: null,
        sshVersion: null,
      },
    });
  });

  it('renders nothing when closed', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    const { container } = render(<SettingsModal isOpen={false} onClose={() => {}} />);
    expect(container.firstChild).toBeNull();
  });

  it('shows the general pane with feature-flag switches by default', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    // Default tab: the four General toggles (all off out of the box), identity section not visible
    expect(screen.getByRole('tab', { name: '通用' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('switch', { name: 'SSH Agent' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByRole('switch', { name: '钱包' })).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByRole('switch', { name: '通行密钥' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByTestId('feature-toggle-passkeys').closest('div')).toHaveTextContent(
      '下次解锁时生效',
    );
    expect(screen.getByRole('switch', { name: '站点图标' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByTestId('feature-toggle-fetch_favicons').closest('div')).toHaveTextContent(
      '默认关闭——未开启前不会有任何网络请求',
    );
    expect(screen.queryByText('还没有身份。')).not.toBeInTheDocument();
  });

  it('renders the theme picker with the current preference checked', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    useAppStore.setState({ theme: 'dark' });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    expect(screen.getByRole('radiogroup', { name: '外观' })).toBeInTheDocument();
    expect(screen.getByTestId('theme-option-system')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('theme-option-light')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('theme-option-dark')).toHaveAttribute('aria-checked', 'true');
  });

  it('writes the theme preference to the store without touching feature flags', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('theme-option-dark'));
    expect(useAppStore.getState().theme).toBe('dark');

    fireEvent.click(screen.getByTestId('theme-option-light'));
    expect(useAppStore.getState().theme).toBe('light');

    // Theme and the feature toggles are independent (the component only writes the store; the html class is applied by useTheme at the App layer)
    expect(mockSetFlags).not.toHaveBeenCalled();
  });

  it('pushes new-language tray labels to the backend right after a locale switch', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetLocale.mockResolvedValue({ success: true, data: {} });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    // Starts at zh-CN: after selecting en, the tray copy must be the real English values --
    // the component-level t is a getFixedT snapshot of the old language, and misusing it here would push the Chinese labels back
    fireEvent.change(screen.getByTestId('locale-select'), { target: { value: 'en' } });

    await waitFor(() => {
      expect(mockSetLocale).toHaveBeenCalledWith('en');
      expect(mockSetTrayLocale).toHaveBeenCalledWith({
        open: 'Open Persona',
        quickAccess: 'Quick Access',
        generator: 'Password Generator',
        lock: 'Lock',
        quit: 'Quit',
      });
    });
    expect(mockSetTrayLocale).toHaveBeenCalledTimes(1);

    // The real i18n singleton is shared across cases: switch back to zh-CN to reset (setupTests' base locale)
    await act(async () => {
      await i18n.changeLanguage('zh-CN');
    });
  });

  it('rolls back the locale switch and skips the tray push when persistence fails', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetLocale.mockResolvedValue({ success: false, error: 'Service is locked' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.change(screen.getByTestId('locale-select'), { target: { value: 'en' } });

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Service is locked');
    });
    expect(mockSetTrayLocale).not.toHaveBeenCalled();
    expect(screen.getByTestId('locale-select')).toHaveValue('zh-CN');

    await act(async () => {
      await i18n.changeLanguage('zh-CN');
    });
  });

  // Deep-review Major regression (2026-11-13): locale-change writes are serialized -- while the first
  // write is in flight the second must queue, and a late failure rolls back only itself, never the later success.
  it('serializes stacked locale switches so a late failure cannot roll back a newer one', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    let rejectFirst!: (e: Error) => void;
    mockSetLocale
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            rejectFirst = reject;
          }),
      )
      .mockResolvedValueOnce({ success: true, data: {} });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.change(screen.getByTestId('locale-select'), { target: { value: 'en' } });
    // Flush the head microtask of the chain: the first write has been issued (optimistic + IPC call, still in flight)
    await act(async () => {});
    // First write in flight: the second must queue and never run concurrently carrying a stale baseline
    fireEvent.change(screen.getByTestId('locale-select'), { target: { value: 'zh-CN' } });
    expect(mockSetLocale).toHaveBeenCalledTimes(1);

    await act(async () => {
      rejectFirst(new Error('first failed'));
    });

    await waitFor(() => {
      expect(mockSetLocale).toHaveBeenCalledTimes(2);
    });
    expect(mockSetLocale).toHaveBeenLastCalledWith('zh-CN');
    // It finally rests at the second write's target locale; the first write's late failure only toasts
    expect(screen.getByTestId('locale-select')).toHaveValue('zh-CN');
    expect(toast.error).toHaveBeenCalledWith('first failed');

    await act(async () => {
      await i18n.changeLanguage('zh-CN');
    });
  });

  it('toggles a flag optimistically and adopts the server truth', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    // The server confirms all three bits together (e.g. because of a change elsewhere): the return value wins
    mockSetFlags.mockResolvedValueOnce({
      success: true,
      data: {
        encryption_enabled: true,
        auto_backup_hours: 24,
        backup_retention_count: 7,
        session_timeout_seconds: 3600,
        require_confirmation: true,
        default_identity_type: 'personal',
        features: { ssh_agent: true, wallet: true, passkeys: true, fetch_favicons: true },
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('feature-toggle-ssh_agent'));

    await waitFor(() => {
      expect(mockSetFlags).toHaveBeenCalledWith({
        ssh_agent: true,
        wallet: false,
        passkeys: false,
        fetch_favicons: false,
      });
    });
    await waitFor(() => {
      // Server truth (all on) overrides the optimistic value
      expect(useAppStore.getState().featureFlags).toEqual({
        ssh_agent: true,
        wallet: true,
        passkeys: true,
        fetch_favicons: true,
      });
    });
    expect(screen.getByRole('switch', { name: 'SSH Agent' })).toHaveAttribute(
      'aria-checked',
      'true',
    );
    expect(toast.error).not.toHaveBeenCalled();
  });

  it('rolls back the optimistic toggle and toasts when the save fails', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetFlags.mockRejectedValueOnce(new Error('ipc down'));

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('feature-toggle-wallet'));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc down');
    });
    // Rolls back to the factory all-off state
    expect(useAppStore.getState().featureFlags).toEqual({
      ssh_agent: false,
      wallet: false,
      passkeys: false,
      fetch_favicons: false,
    });
    expect(screen.getByRole('switch', { name: '钱包' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
  });

  // Deep-review Major regression (2026-11-13): feature-flag writes are serialized -- a slow first-write
  // failure must not roll back the second write's success; the second write's baseline is the latest truth after the first rollback.
  it('serializes stacked feature toggles so a late failure cannot roll back a newer save', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    let rejectFirst!: (e: Error) => void;
    mockSetFlags
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            rejectFirst = reject;
          }),
      )
      .mockResolvedValueOnce({
        success: true,
        data: {
          features: { ssh_agent: false, wallet: true, passkeys: false, fetch_favicons: false },
        },
      });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('feature-toggle-ssh_agent'));
    // Flush the head microtask of the chain: the first write has been issued (optimistic + IPC call, still in flight)
    await act(async () => {});
    // First write in flight: the second must queue
    fireEvent.click(screen.getByTestId('feature-toggle-wallet'));
    expect(mockSetFlags).toHaveBeenCalledTimes(1);

    await act(async () => {
      rejectFirst(new Error('first failed'));
    });

    // The second write baselines on the post-rollback truth: wallet is on by itself
    await waitFor(() => {
      expect(mockSetFlags).toHaveBeenLastCalledWith({
        ssh_agent: false,
        wallet: true,
        passkeys: false,
        fetch_favicons: false,
      });
    });
    await waitFor(() => {
      expect(useAppStore.getState().featureFlags).toEqual({
        ssh_agent: false,
        wallet: true,
        passkeys: false,
        fetch_favicons: false,
      });
    });
    expect(toast.error).toHaveBeenCalledWith('first failed');
    expect(screen.getByRole('switch', { name: '钱包' })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('switch', { name: 'SSH Agent' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
  });

  it('rolls back with the backend error message when the save is refused', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetFlags.mockResolvedValueOnce({ success: false, error: 'Service is locked' });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('feature-toggle-passkeys'));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Service is locked');
    });
    expect(useAppStore.getState().featureFlags.passkeys).toBe(false);
  });

  it('shows empty state when no identities', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();
    expect(screen.getByText('还没有身份。')).toBeInTheDocument();
  });

  it('edits and saves identity', async () => {
    const updateIdentity = jest.fn().mockResolvedValue({ id: '1' });
    const identity = {
      id: '1',
      name: 'Old',
      identity_type: 'Personal',
      description: '',
      email: '',
      phone: '',
      tags: ['a', 'b'],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
    } as any;

    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: identity,
      updateIdentity,
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();

    fireEvent.click(screen.getByTitle('编辑'));

    const inputs = () => document.querySelectorAll('input.input');
    // order: name, email, phone, tags
    fireEvent.change(inputs()[0], { target: { value: ' New Name ' } });
    fireEvent.change(inputs()[3], { target: { value: 'a, b, c, c' } });

    fireEvent.click(screen.getByText('保存'));

    await act(async () => {});

    expect(updateIdentity).toHaveBeenCalledWith(
      expect.objectContaining({
        id: '1',
        name: 'New Name',
        tags: expect.arrayContaining(['a', 'b', 'c']),
      }),
    );
  });

  it('deletes identity after confirm', async () => {
    const deleteIdentity = jest.fn().mockResolvedValue(true);
    const identity = { id: '1', name: 'ToDelete', identity_type: 'Personal', tags: [] } as any;

    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity,
      isLoading: false,
    });

    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();
    fireEvent.click(screen.getByTitle('删除'));

    await act(async () => {});

    expect(deleteIdentity).toHaveBeenCalledWith('1');
    confirmSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // Sync-server section
  // -------------------------------------------------------------------------

  const mockIdentityHook = () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
  };

  it('loads the saved sync config and keeps the stored token masked', async () => {
    mockIdentityHook();
    // The backend's sync.server_token always returns an empty string (the real value lives in the OS keyring);
    // the placeholder is driven by the sync_token_present existence query
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://sync.example.com', server_token: '' },
      },
    });
    mockTokenPresent.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('sync-url-input')).toHaveValue('https://sync.example.com');
    });
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    // The token is never written back into the input (keeps it out of long-lived frontend memory); the placeholder signals one is stored
    const tokenInput = screen.getByTestId('sync-token-input') as HTMLInputElement;
    expect(tokenInput.type).toBe('password');
    expect(tokenInput.value).toBe('');
    await waitFor(() => {
      expect(tokenInput.placeholder).toContain('留空表示保持不变');
    });
  });

  it('saves sync config, adopts server truth and clears the token field', async () => {
    mockIdentityHook();
    // After saving the placeholder re-queries keyring existence (the new token is stored)
    mockTokenPresent.mockResolvedValue({ success: true, data: true });
    mockSetSync.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://s.example.com', server_token: '' },
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    // Enabling the toggle first raises the data-scope disclosure: before confirmation the form never appears and nothing is persisted
    fireEvent.click(screen.getByTestId('sync-toggle'));
    expect(mockSetSync).not.toHaveBeenCalled();
    expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument();
    expect(screen.queryByTestId('sync-url-input')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();

    fireEvent.change(screen.getByTestId('sync-url-input'), {
      target: { value: 'https://s.example.com' },
    });
    fireEvent.change(screen.getByTestId('sync-token-input'), { target: { value: 'fresh-tok' } });
    // The whole save() async chain (IPC mock resolve -> setState -> placeholder re-query) flushes inside act
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-save'));
    });

    await waitFor(() => {
      expect(mockSetSync).toHaveBeenCalledWith({
        enabled: true,
        server_url: 'https://s.example.com',
        server_token: 'fresh-tok',
      });
    });
    // Server truth is written back; the token input clears (empty string = the backend keeps the old value);
    // the placeholder re-queries keyring existence and every microtask flushes inside act
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith('同步设置已保存');
    });
    await act(async () => {});
    await waitFor(() => {
      expect((screen.getByTestId('sync-token-input') as HTMLInputElement).value).toBe('');
    });
    expect(screen.getByTestId('sync-url-input')).toHaveValue('https://s.example.com');
    expect(toast.error).not.toHaveBeenCalled();
  });

  it('refuses to save an enabled config without a server url', async () => {
    mockIdentityHook();

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    fireEvent.click(screen.getByTestId('sync-toggle'));
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    fireEvent.click(screen.getByTestId('sync-save'));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('启用同步时必须填写服务器 URL');
    });
    expect(mockSetSync).not.toHaveBeenCalled();
  });

  it('saves immediately when switching an enabled sync off', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://s.example.com', server_token: '' },
      },
    });
    mockSetSync.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: false, server_url: 'https://s.example.com', server_token: '' },
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    });

    // Toggle-off saves immediately: the save() async chain flushes inside act (as in the previous case)
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-toggle'));
    });

    await waitFor(() => {
      expect(mockSetSync).toHaveBeenCalledWith(
        expect.objectContaining({ enabled: false, server_url: 'https://s.example.com' }),
      );
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'false');
    });
  });

  // Deep-review Major regression (2026-11-13): a failed sync disable must not optimistically flip -- the state
  // is written back from server truth only after a successful save; on failure it stays at the real (on) state.
  it('keeps the sync toggle on when switching off fails server-side', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://s.example.com', server_token: '' },
      },
    });
    mockSetSync.mockRejectedValueOnce(new Error('sync down'));

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-toggle'));
    });

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('sync down');
    });
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByTestId('sync-url-input')).toBeInTheDocument();
    expect(mockSetSync).toHaveBeenCalledWith(
      expect.objectContaining({ enabled: false, server_url: 'https://s.example.com' }),
    );
  });

  // -------------------------------------------------------------------------
  // Privacy red line (2026-10 scoping upgrade directive 5): sync is off by default, enabled explicitly, and the
  // data scope is disclosed at enable time; dismissing the disclosure never lets it through (nothing persisted, no join)
  // -------------------------------------------------------------------------

  it('defaults sync off and gates enabling behind the data-scope disclosure', async () => {
    mockIdentityHook();

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    // A fresh workspace (no sync section) -> the toggle defaults to off
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'false');

    // Toggling on = disclosure first: nothing persisted and the config form stays collapsed
    fireEvent.click(screen.getByTestId('sync-toggle'));
    expect(screen.getByTestId('data-scope-modal')).toHaveAttribute('data-scope', 'audit');
    expect(screen.queryByTestId('sync-url-input')).not.toBeInTheDocument();
    expect(mockSetSync).not.toHaveBeenCalled();

    // Cancel = stays off
    fireEvent.click(screen.getByTestId('data-scope-cancel'));
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'false');
    expect(mockSetSync).not.toHaveBeenCalled();

    // Toggle on again + confirm = expand the form (only saving persists; confirming alone persists nothing)
    fireEvent.click(screen.getByTestId('sync-toggle'));
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();
    expect(screen.getByTestId('sync-url-input')).toBeInTheDocument();
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    expect(mockSetSync).not.toHaveBeenCalled();
  });

  it('skips joining E2EE sync when the disclosure is cancelled and joins after confirming', async () => {
    mockIdentityHook();
    mockSyncJoin.mockResolvedValue({
      success: true,
      data: { device_id: 'dev-new', device_name: '我的笔记本', pending: true },
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-device-name-input')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('sync-device-name-input'), {
      target: { value: '我的笔记本' },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });

    // The disclosure is open and the backend was never called
    expect(screen.getByTestId('data-scope-modal')).toHaveAttribute('data-scope', 'e2ee');
    expect(mockSyncJoin).not.toHaveBeenCalled();

    // Cancel = no join and the disclosure closes
    fireEvent.click(screen.getByTestId('data-scope-cancel'));
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();
    expect(mockSyncJoin).not.toHaveBeenCalled();

    // Only reopening and confirming actually calls the backend
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() => {
      expect(mockSyncJoin).toHaveBeenCalledWith('我的笔记本');
    });
  });

  // -------------------------------------------------------------------------
  // Password-security section (expiry policy + manual password change)
  // -------------------------------------------------------------------------

  it('renders the expiry selector with the persisted policy value', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        password_expiry_days: 90,
        sync: null,
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('90');
    });
    expect(screen.getByTestId('change-password-button')).toBeEnabled();
  });

  it('defaults the expiry selector to Never and writes a numeric policy', async () => {
    mockIdentityHook();
    mockSetExpiry.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        password_expiry_days: 180,
        sync: null,
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    // Defaults to Never until server truth is written back (the same shape when an older JSON omits the key)
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('');
    });

    fireEvent.change(screen.getByTestId('password-expiry-select'), {
      target: { value: '180' },
    });

    await waitFor(() => {
      expect(mockSetExpiry).toHaveBeenCalledWith(180);
    });
    // Fills back using the server's return value as the authority
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('180');
    });
    expect(toast.success).toHaveBeenCalledWith('密码策略已保存');
  });

  it('writes null when the policy is switched back to Never', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        password_expiry_days: 365,
        sync: null,
      },
    });
    mockSetExpiry.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        password_expiry_days: null,
        sync: null,
      },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('365');
    });

    fireEvent.change(screen.getByTestId('password-expiry-select'), { target: { value: '' } });

    await waitFor(() => {
      expect(mockSetExpiry).toHaveBeenCalledWith(null);
    });
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('');
    });
  });

  it('toasts the backend error and keeps the selector value when the save fails', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        password_expiry_days: 90,
        sync: null,
      },
    });
    mockSetExpiry.mockResolvedValueOnce({ success: false, error: 'Service is locked' });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('90');
    });

    fireEvent.change(screen.getByTestId('password-expiry-select'), {
      target: { value: '365' },
    });

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Service is locked');
    });
    expect(mockSetExpiry).toHaveBeenCalledWith(365);
  });

  it('opens the change-password dialog and locks the service after rotation', async () => {
    const lockService = jest.fn().mockResolvedValue(undefined);
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
      lockService,
    });
    mockSetExpiry.mockResolvedValue({
      success: true,
      data: { features: { ...DEFAULT_FEATURE_FLAGS }, password_expiry_days: null, sync: null },
    });
    mockChangePw.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    // The manual password change uses the non-forced modal: cancellable, and the old password is not prefilled
    fireEvent.click(screen.getByTestId('change-password-button'));
    expect(screen.getByTestId('change-password-modal')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '取消' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('当前密码'), {
      target: { value: 'old-pw' },
    });
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'new-pw' } });
    fireEvent.change(screen.getByLabelText('确认新密码'), {
      target: { value: 'new-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '修改密码' }));
    });

    await waitFor(() => {
      expect(mockChangePw).toHaveBeenCalledWith('old-pw', 'new-pw', undefined);
    });
    // A successful password change -> back to the lock screen (the old session key in state.service is already invalidated)
    await waitFor(() => {
      expect(lockService).toHaveBeenCalledTimes(1);
    });
    expect(toast.success).toHaveBeenCalledWith('主密码已修改——请重新登录');
    expect(screen.queryByTestId('change-password-modal')).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Biometric unlock section (on = ReauthModal verifies the password; off = disables directly)
  // -------------------------------------------------------------------------

  it('disables the biometric switch with an unavailable hint when the OS lacks support', async () => {
    mockIdentityHook();

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    const toggle = await screen.findByTestId('biometric-toggle');
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    // After the status is written back it switches to the unavailable hint (while loading it shows the plain hint)
    await waitFor(() => {
      expect(toggle.closest('div')).toHaveTextContent('当前系统不支持或未配置生物识别');
    });
  });

  it('enables biometric through the reauth modal and adopts the returned status', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: false, platform: 'linux-polkit' },
    });
    mockBiometricEnable.mockResolvedValue({
      success: true,
      data: { available: true, enabled: true, platform: 'linux-polkit' },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);

    // Enabling first verifies the master password (ReauthModal); it does not call enable directly
    const modal = screen.getByTestId('reauth-modal');
    expect(mockBiometricEnable).not.toHaveBeenCalled();
    fireEvent.change(modal.querySelector('input') as HTMLInputElement, {
      target: { value: 'master-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });

    await waitFor(() => {
      expect(mockBiometricEnable).toHaveBeenCalledWith('master-pw');
    });
    await waitFor(() => {
      expect(screen.getByTestId('biometric-toggle')).toHaveAttribute('aria-checked', 'true');
    });
    expect(toast.success).toHaveBeenCalledWith('指纹解锁已开启');
    expect(screen.queryByTestId('reauth-modal')).not.toBeInTheDocument();
  });

  it('keeps the reauth modal open with the backend error when enable fails', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: false, platform: 'linux-polkit' },
    });
    mockBiometricEnable.mockResolvedValue({
      success: false,
      error: 'Invalid master password',
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);

    const modal = screen.getByTestId('reauth-modal');
    fireEvent.change(modal.querySelector('input') as HTMLInputElement, {
      target: { value: 'wrong-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });

    // Wrong password: the error stays inside the modal for an in-place retry and the toggle does not flip
    await waitFor(() => {
      expect(screen.getByTestId('reauth-error')).toHaveTextContent('Invalid master password');
    });
    expect(screen.getByTestId('biometric-toggle')).toHaveAttribute('aria-checked', 'false');
  });

  it('shows the hardware-bound tier line after enabling on a hardware platform', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: false, platform: 'touch-id', wrap_tier: 'hardware-bound' },
    });
    mockBiometricEnable.mockResolvedValue({
      success: true,
      data: { available: true, enabled: true, platform: 'touch-id', wrap_tier: 'hardware-bound' },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);

    const modal = screen.getByTestId('reauth-modal');
    fireEvent.change(modal.querySelector('input') as HTMLInputElement, {
      target: { value: 'master-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });

    // Once enabled it shows the hardware-bound tier row (the key is wrapped by hardware, not password-escrowed)
    await waitFor(() => {
      expect(screen.getByTestId('biometric-tier')).toHaveTextContent('硬件绑定');
    });
  });

  it('shows the os-gate tier line on platforms without hardware wrapping', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: true, platform: 'linux-polkit', wrap_tier: 'os-gate' },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('biometric-tier')).toHaveTextContent('仅系统门禁');
    });
  });

  it('disables biometric without a password prompt', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: true, platform: 'linux-polkit' },
    });
    mockBiometricDisable.mockResolvedValue({
      success: true,
      data: { available: true, enabled: false, platform: 'linux-polkit' },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'));
    // The tightening operation has no password gate: one click deletes the keyring entry outright
    await act(async () => {
      fireEvent.click(toggle);
    });

    await waitFor(() => {
      expect(mockBiometricDisable).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTestId('reauth-modal')).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByTestId('biometric-toggle')).toHaveAttribute('aria-checked', 'false');
    });
    expect(toast.success).toHaveBeenCalledWith('指纹解锁已关闭');
  });

  // -------------------------------------------------------------------------
  // Travel mode section (SecurityPane status row + passphrase modal + REAUTH retry)
  // -------------------------------------------------------------------------

  /** Hook mock for the travel cases: carries loadIdentities (reloads the list after a successful enter/exit) */
  const travelHook = () => {
    const loadIdentities = jest.fn().mockResolvedValue(undefined);
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
      lockService: jest.fn(),
      loadIdentities,
    });
    return loadIdentities;
  };

  it('renders the travel enter button while inactive and exit while active', async () => {
    travelHook();

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('travel-exit-button')).not.toBeInTheDocument();

    // In the active state it shows the exit button instead
    mockGetTravelStatus.mockResolvedValue({
      success: true,
      data: {
        active: true,
        entered_at: '2026-09-22T08:00:00Z',
        sidecar_exists: true,
        inconsistent: false,
      },
    });
    await act(async () => {});
    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-exit-button')).toBeInTheDocument();
    });
  });

  it('shows the inconsistent warning when the sidecar is gone', async () => {
    travelHook();
    mockGetTravelStatus.mockResolvedValue({
      success: true,
      data: { active: true, entered_at: null, sidecar_exists: false, inconsistent: true },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('travel-inconsistent-warning')).toHaveTextContent('sidecar');
    });
  });

  it('enters travel mode with a matched passphrase and reloads identities', async () => {
    const loadIdentities = travelHook();
    mockEnterTravel.mockResolvedValue({
      success: true,
      data: { identities: 2, credentials: 5, attachments: 0, passkeys: 0, wallets: 0, history_rows: 0, files: 0 },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));

    // Passphrase modal mode=set: typed twice
    expect(screen.getByTestId('travel-passphrase-modal')).toBeInTheDocument();
    expect(mockEnterTravel).not.toHaveBeenCalled();

    typeTravel('travel-pw');
    typeTravelConfirm('different');
    fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    await act(async () => {});
    expect(mockEnterTravel).not.toHaveBeenCalled();
    expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent('两次输入的口令不一致');

    typeTravelConfirm('travel-pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });

    await waitFor(() => {
      expect(mockEnterTravel).toHaveBeenCalledWith('travel-pw');
    });
    await waitFor(() => {
      expect(loadIdentities).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith('旅行模式已开启——2 个身份已移出本设备');
    });
    expect(screen.queryByTestId('travel-passphrase-modal')).not.toBeInTheDocument();
  });

  it('exits travel mode; a wrong passphrase stays in the modal for retry', async () => {
    travelHook();
    mockGetTravelStatus.mockResolvedValue({
      success: true,
      data: { active: true, entered_at: null, sidecar_exists: true, inconsistent: false },
    });
    mockExitTravel.mockResolvedValueOnce({ success: false, error: 'passphrase is wrong' });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-exit-button')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('travel-exit-button'));

    // mode=enter: typed once
    expect(screen.queryByTestId('travel-passphrase-confirm-input')).not.toBeInTheDocument();
    typeTravel('wrong-pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });

    await waitFor(() => {
      expect(mockExitTravel).toHaveBeenCalledWith('wrong-pw');
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent(
        'passphrase is wrong',
      );
    });
    expect(screen.getByTestId('travel-passphrase-modal')).toBeInTheDocument();

    // Retrying in place with the corrected passphrase succeeds
    mockExitTravel.mockResolvedValueOnce({
      success: true,
      data: { identities: 1, credentials: 0, attachments: 0, passkeys: 0, wallets: 0, history_rows: 0, files: 0 },
    });
    typeTravel('right-pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });
    await waitFor(() => {
      expect(screen.queryByTestId('travel-passphrase-modal')).not.toBeInTheDocument();
    });
  });

  it('interrupts enter with REAUTH_REQUIRED, verifies, and reopens the passphrase modal', async () => {
    travelHook();
    mockEnterTravel.mockResolvedValueOnce({
      success: false,
      error_code: 'REAUTH_REQUIRED',
      error: 'Re-authentication required',
    });
    mockReauthVerify.mockResolvedValueOnce({ success: true, data: true });
    mockEnterTravel.mockResolvedValueOnce({
      success: true,
      data: { identities: 1, credentials: 0, attachments: 0, passkeys: 0, wallets: 0, history_rows: 0, files: 0 },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));
    typeTravel('travel-pw');
    typeTravelConfirm('travel-pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });

    // Sensitive-operation gate: the passphrase modal collapses and the master-password re-verification is raised
    await waitFor(() => {
      expect(screen.getByTestId('reauth-modal')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('travel-passphrase-modal')).not.toBeInTheDocument();

    fireEvent.change(screen.getByTestId('reauth-modal').querySelector('input') as HTMLInputElement, {
      target: { value: 'master-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });

    // Verification passes -> the passphrase modal reopens for the original intent (enter) and the travel passphrase must be re-entered
    await waitFor(() => {
      expect(mockReauthVerify).toHaveBeenCalledWith('master-pw');
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-passphrase-modal')).toBeInTheDocument();
    });
    expect((screen.getByTestId('travel-passphrase-input') as HTMLInputElement).value).toBe('');
    expect(mockEnterTravel).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // The travel-marker toggle in the identity edit form (applies immediately)
  // -------------------------------------------------------------------------

  it('toggles the identity travel mark immediately and reloads', async () => {
    const identity = {
      id: 'id-1',
      name: 'Work',
      identity_type: 'Work',
      description: '',
      email: '',
      phone: '',
      tags: [],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      is_active: true,
      travel_marked: false,
    } as any;
    const loadIdentities = jest.fn().mockResolvedValue(undefined);
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
      lockService: jest.fn(),
      loadIdentities,
    });
    mockSetTravelMarked.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();
    fireEvent.click(screen.getByTitle('编辑'));

    const toggle = await screen.findByTestId('travel-mark-toggle-id-1');
    expect(toggle).toHaveAttribute('aria-checked', 'false');

    await act(async () => {
      fireEvent.click(toggle);
    });

    await waitFor(() => {
      expect(mockSetTravelMarked).toHaveBeenCalledWith('id-1', true);
    });
    await waitFor(() => {
      expect(loadIdentities).toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // E2EE sync device section (SyncDevicesSection)
  // -------------------------------------------------------------------------

  /** Default response for the joined state (the local machine is named laptop) */
  const joinedStatus = {
    success: true,
    data: { joined: true, corrupted: false, device_id: 'dev-self', device_name: 'laptop' },
  };

  /** Two devices in the sync group: the local machine authorized + phone awaiting authorization */
  const twoDevices = {
    success: true,
    data: [
      { id: 'dev-self', device_name: 'laptop', created_at: '2026-09-23T00:00:00Z', remark: '', authorized: true, this_device: true },
      { id: 'dev-phone', device_name: 'phone', created_at: '2026-09-23T01:00:00Z', remark: '备用机', authorized: false, this_device: false },
    ],
  };

  it('shows the join form while not joined and skips the device list', async () => {
    mockIdentityHook();
    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-device-name-input')).toBeInTheDocument();
    expect(mockSyncList).not.toHaveBeenCalled();
  });

  it('rejects an empty device name without touching the backend', async () => {
    mockIdentityHook();
    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });

    expect(mockSyncJoin).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalledWith('请填写设备名称');
  });

  it('joins with the trimmed name and toasts the pending hint', async () => {
    mockIdentityHook();
    mockSyncJoin.mockResolvedValue({
      success: true,
      data: { device_id: 'dev-new', device_name: '我的笔记本', pending: true },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-device-name-input')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('sync-device-name-input'), {
      target: { value: '  我的笔记本  ' },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });

    // Before joining it first raises the E2EE data-scope disclosure; only confirmation calls the backend
    expect(screen.getByTestId('data-scope-modal')).toHaveAttribute('data-scope', 'e2ee');
    expect(mockSyncJoin).not.toHaveBeenCalled();
    await act(async () => {
      fireEvent.click(screen.getByTestId('data-scope-confirm'));
    });

    await waitFor(() => {
      expect(mockSyncJoin).toHaveBeenCalledWith('我的笔记本');
    });
    expect(toast.success).toHaveBeenCalledWith('已登记——请在另一台已授权设备上授权本机');
  });

  it('renders the joined state with this-device and pending badges', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-joined')).toBeInTheDocument();
    });
    expect(screen.getByText('已加入：laptop')).toBeInTheDocument();
    // The device list is fetched asynchronously in the follow-up effect triggered by status.joined
    await waitFor(() => {
      expect(screen.getByTestId('sync-device-this-badge')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-device-pending-badge')).toBeInTheDocument();
    expect(mockSyncList).toHaveBeenCalled();

    // The local row has no authorize/revoke buttons; the phone row awaiting authorization has an authorize button
    expect(screen.getByTestId('sync-authorize-dev-phone')).toBeInTheDocument();
    expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    expect(screen.queryByTestId('sync-authorize-dev-self')).not.toBeInTheDocument();
    expect(screen.queryByTestId('sync-revoke-dev-self')).not.toBeInTheDocument();

    // The leave entry
    expect(screen.getByTestId('sync-leave-button')).toBeInTheDocument();
  });

  it('edits this-device remark inline and backfills the normalized value', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncSetRemark.mockResolvedValue({ success: true, data: '书房的主力机' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-remark-edit')).toBeInTheDocument();
    });

    // An empty note shows placeholder copy; other people's devices are read-only (S4: only the owner may write a note)
    expect(screen.getByText('暂无备注')).toBeInTheDocument();
    expect(screen.getByText('备用机')).toBeInTheDocument();
    expect(screen.getAllByTestId('sync-remark-edit')).toHaveLength(1);

    fireEvent.click(screen.getByTestId('sync-remark-edit'));
    const input = screen.getByTestId('sync-remark-input') as HTMLInputElement;
    expect(input.value).toBe('');
    fireEvent.change(input, { target: { value: '  书房的主力机  ' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-remark-save'));
    });

    expect(mockSyncSetRemark).toHaveBeenCalledWith('  书房的主力机  ');
    // The server's normalized value (post-trim) is written back inline and the edit state exits
    await waitFor(() => {
      expect(screen.getByText('书房的主力机')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('sync-remark-input')).not.toBeInTheDocument();
    expect(toast.success).toHaveBeenCalledWith('备注已更新');
  });

  it('toasts on remark failure and Escape abandons the edit', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncSetRemark.mockResolvedValue({ success: false, error: 'remark too long' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-remark-edit')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('sync-remark-edit'));
    fireEvent.change(screen.getByTestId('sync-remark-input'), {
      target: { value: '过长备注' },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-remark-save'));
    });
    expect(toast.error).toHaveBeenCalledWith('remark too long');
    // A failure does not exit the edit state; fix and retry, or abandon with Escape
    expect(screen.getByTestId('sync-remark-input')).toBeInTheDocument();
    fireEvent.keyDown(screen.getByTestId('sync-remark-input'), { key: 'Escape' });
    expect(screen.queryByTestId('sync-remark-input')).not.toBeInTheDocument();
  });

  it('shows the sync status row: up-to-date, behind and hidden-when-unavailable', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    // Up to date: group version + green verdict + last sync time
    mockSyncStatusReport.mockResolvedValue({
      success: true,
      data: {
        headSeq: 42,
        localWatermark: 42,
        behind: 0,
        pendingPush: 0,
        lastSyncAt: '2026-10-05T10:00:00Z',
      },
    });
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-status-row')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-status-head')).toHaveTextContent('组版本号 #42');
    expect(screen.getByTestId('sync-status-uptodate')).toHaveTextContent('已最新');
    expect(screen.queryByTestId('sync-status-behind')).not.toBeInTheDocument();
    expect(screen.getByTestId('sync-status-last-sync')).toHaveTextContent('最近同步');

    // Five behind: the yellow bar replaces the green verdict (a fresh snapshot on remount)
    cleanup();
    mockSyncStatusReport.mockResolvedValue({
      success: true,
      data: { headSeq: 47, localWatermark: 42, behind: 5, pendingPush: 3, lastSyncAt: null },
    });
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-status-behind')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-status-behind')).toHaveTextContent('落后 5 条指令');
    expect(screen.queryByTestId('sync-status-uptodate')).not.toBeInTheDocument();
    expect(screen.getByTestId('sync-status-last-sync')).toHaveTextContent('从未同步');
  });

  it('hides the sync status row when the snapshot query fails', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    // Server unreachable: a query failure must keep the row hidden (no lying "up to date")
    mockSyncStatusReport.mockResolvedValue({ success: false, data: null });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-joined')).toBeInTheDocument();
    });
    await act(async () => {}); // flush the watermark effect's rejected promise
    expect(screen.queryByTestId('sync-status-row')).not.toBeInTheDocument();
  });

  it('revokes a device after confirm and refreshes the list', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncRevoke.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-revoke-dev-phone'));
    });

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      expect(mockSyncRevoke).toHaveBeenCalledWith('dev-phone');
    });
    expect(toast.success).toHaveBeenCalledWith('设备已吊销');
    confirmSpy.mockRestore();
  });

  it('keeps the device when the revoke confirm is dismissed', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-revoke-dev-phone'));
    });

    expect(mockSyncRevoke).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // Rotation entry (phase 3d): after confirmation it calls sync_rotate and reports the count; cancelling never calls it.
  // The full rotation semantics are covered by the core runtime plus the real-TCP server tests.
  it('rotates the group key after confirm and reports the counts', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncRotate.mockResolvedValue({
      success: true,
      data: { rewrapped: 2, skipped: 0, pushed: 4 },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-rotate-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      expect(mockSyncRotate).toHaveBeenCalled();
    });
    expect(toast.success).toHaveBeenCalledWith('轮换完成——重包 2 条，跳过 0 条，推送 4 条');
    confirmSpy.mockRestore();
  });

  it('skips rotation when the confirm is dismissed', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-rotate-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });

    expect(mockSyncRotate).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // Concurrent rotation mutual exclusion (epoch optimistic lock): the later arrival gets the CONCURRENT_CONFLICT code
  // and a targeted retry hint rather than a generic "rotation failed".
  it('shows a retry hint when rotation hits a concurrent conflict', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncRotate.mockResolvedValue({
      success: false,
      error: 'Group key rotation failed: Concurrent operation conflict: ...',
      error_code: 'CONCURRENT_CONFLICT',
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-rotate-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });

    await waitFor(() => {
      expect(mockSyncRotate).toHaveBeenCalled();
    });
    expect(toast.error).toHaveBeenCalledWith(
      '另一台设备刚刚完成了组密钥轮换——你的数据未受影响，请重试轮换。',
    );
    confirmSpy.mockRestore();
  });

  it('authorizes a pending device through the authorize button', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncAuthorize.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-authorize-dev-phone')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-authorize-dev-phone'));
    });

    await waitFor(() => {
      expect(mockSyncAuthorize).toHaveBeenCalledWith('dev-phone');
    });
    expect(toast.success).toHaveBeenCalledWith('已授权「phone」');
  });

  it('surfaces the corrupted warning and keeps the join form for re-join', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue({
      success: true,
      data: { joined: false, corrupted: true, device_id: null, device_name: null },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-corrupted')).toBeInTheDocument();
    });
    // A corrupted state can still re-join (the leave-clears-residue-then-join path)
    expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Conflict arbitration entry (phase 3c: syncNow -> conflicts>0 -> banner + arbitration modal)
  // -------------------------------------------------------------------------

  /** SyncConflictsModal.test.tsx fully covers the arbitration modal's data surface; this only verifies
   *  the SettingsModal-side wiring: when syncNow reports conflicts>0 the banner lights up and the modal
   *  opens automatically; no entry appears at conflicts=0. */
  const conflictedList = {
    success: true,
    data: [
      {
        item_id: 'item-1',
        primary: {
          op_id: 'op-p',
          device_id: 'dev-a',
          lamport: 5,
          timestamp: null,
          deleted: false,
          snapshot: {
            identity_id: 'id-1',
            name: 'GitHub',
            credential_type: 'Password',
            security_level: 'High',
            url: null,
            username: null,
            notes: null,
            tags: [],
            metadata: {},
            is_favorite: false,
            is_active: true,
            data: { credential_type: 'Password', data: { password: 'a' } },
          },
        },
        copies: [
          {
            op_id: 'op-c',
            device_id: 'dev-b',
            lamport: 5,
            timestamp: null,
            deleted: false,
            snapshot: null,
          },
        ],
      },
    ],
  };

  it('syncs now, shows the conflict banner and auto-opens the resolution modal', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue({ success: true, data: [] });
    mockSyncNow.mockResolvedValue({
      success: true,
      data: { pulled: 2, materialized: 1, conflicts: 1, pending_identity: 0, pushed: 1, backfilled: 0 },
    });
    mockSyncConflictsList.mockResolvedValue(conflictedList);

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });

    await waitFor(() => {
      expect(mockSyncNow).toHaveBeenCalled();
    });
    // conflicts>0: the banner lights up and the arbitration modal opens automatically
    await waitFor(() => {
      expect(screen.getByTestId('sync-conflicts-banner')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-conflicts-banner')).toHaveTextContent(
      '1 个条目存在并发修改的冲突版本',
    );
    await waitFor(() => {
      expect(screen.getByTestId('sync-conflicts-modal')).toBeInTheDocument();
    });
  });

  it('hides the conflict entry point when the report has no conflicts', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue({ success: true, data: [] });
    mockSyncNow.mockResolvedValue({
      success: true,
      data: { pulled: 1, materialized: 1, conflicts: 0, pending_identity: 0, pushed: 0, backfilled: 0 },
    });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });

    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith(
        '同步完成——拉取 1 条，推送 0 条',
      );
    });
    expect(screen.queryByTestId('sync-conflicts-banner')).not.toBeInTheDocument();
    expect(screen.queryByTestId('sync-conflicts-modal')).not.toBeInTheDocument();
  });

  it('leaves sync after confirm and falls back to the join form', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncLeave.mockResolvedValue({ success: true, data: true });

    // On mount the four panes start their first async fetch: async act flushes the setState of the already-resolved
    // promises, otherwise the update lands outside act and logs a "not wrapped in act" warning
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-leave-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-leave-button'));
    });

    await waitFor(() => {
      expect(mockSyncLeave).toHaveBeenCalled();
    });
    expect(toast.success).toHaveBeenCalledWith('已离开同步');
    // The state switches back to the join form
    await waitFor(() => {
      expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
    });
    confirmSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // Failure and exception branch coverage: every async action's catch and failure response must give the user
  // feedback -- errors must not be swallowed silently, and the UI must not be left in a false-success state.
  // -------------------------------------------------------------------------

  /** Opens the sync config form (toggle -> data-scope disclosure -> confirm) and returns the token input */
  const openSyncConfigForm = async () => {
    fireEvent.click(screen.getByTestId('sync-toggle'));
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() => {
      expect(screen.getByTestId('sync-token-input')).toBeInTheDocument();
    });
    fireEvent.change(screen.getByTestId('sync-url-input'), {
      target: { value: 'https://s.example.com' },
    });
    fireEvent.change(screen.getByTestId('sync-token-input'), { target: { value: 'fresh-tok' } });
  };

  it('surfaces sync config save failures and recovers the token placeholder', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({ success: true, data: null });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await openSyncConfigForm();

    // Failure response: the toast shows the backend error (144)
    mockSetSync.mockResolvedValueOnce({ success: false, error: 'server said no' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-save'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('server said no');
    });

    // IPC exception: the toast shows the exception message (147)
    mockSetSync.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-save'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });

    // The keyring existence query fails after a successful save: the placeholder falls back to placeholder copy instead of freezing (99)
    mockSetSync.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://s.example.com', server_token: '' },
      },
    });
    mockTokenPresent.mockRejectedValueOnce(new Error('keyring unavailable'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-save'));
    });
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith('同步设置已保存');
    });
    expect(screen.getByTestId('sync-token-input')).toHaveAttribute('placeholder', 'API 令牌');
  });

  it('shows the sync status load failure message', async () => {
    mockIdentityHook();

    // Failure-response branch (279). syncDeviceStatus is now consumed by two sections (the sync-methods section
    // also reads the derived state to display "not joined"), so a persistent mock is used instead of mockResolvedValueOnce --
    // otherwise the Once value is taken by the sync-methods section, which mounts first, and this section never sees the failure (deliverable 4
    // introduced the second consumer and the test adapted to the new fact; the assertion's intent is unchanged).
    mockSyncStatus.mockResolvedValue({ success: false, error: 'locked' });
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-error')).toHaveTextContent('同步状态加载失败');
    });

    // IPC exception branch (280-281)
    cleanup();
    mockSyncStatus.mockRejectedValue(new Error('backend gone'));
    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-error')).toHaveTextContent('同步状态加载失败');
    });
  });

  it('reports join failures and keeps the form for retry', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue({
      success: true,
      data: { joined: false, corrupted: false, device_id: null, device_name: null },
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
    });
    fireEvent.change(screen.getByTestId('sync-device-name-input'), {
      target: { value: 'laptop' },
    });

    // Failure response
    mockSyncJoin.mockResolvedValueOnce({ success: false, error: 'denied' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('data-scope-confirm'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('denied');
    });
    expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();

    // IPC exception
    mockSyncJoin.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('data-scope-confirm'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
  });

  it('reports sync-now failures and clears busy state', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue({ success: true, data: [] });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    mockSyncNow.mockResolvedValueOnce({ success: false, error: 'offline' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('offline');
    });

    mockSyncNow.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
    // busy has reset and the button is clickable again
    expect(screen.getByTestId('sync-now-button')).toBeEnabled();
  });

  it('reports a generic rotation failure without a concurrent-conflict hint', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-rotate-button')).toBeInTheDocument();
    });

    mockSyncRotate.mockResolvedValueOnce({ success: false, error: 'boom' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('boom');
    });

    mockSyncRotate.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
    confirmSpy.mockRestore();
  });

  it('reports leave failures and keeps the joined state', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-leave-button')).toBeInTheDocument();
    });

    mockSyncLeave.mockResolvedValueOnce({ success: false, error: 'locked' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-leave-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('locked');
    });
    // Still in the joined state (does not wrongly clear the device list)
    expect(screen.getByTestId('sync-leave-button')).toBeInTheDocument();

    mockSyncLeave.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-leave-button'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
    confirmSpy.mockRestore();
  });

  it('reports authorize failures without dropping the pending device', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-authorize-dev-phone')).toBeInTheDocument();
    });

    mockSyncAuthorize.mockResolvedValueOnce({ success: false, error: 'not allowed' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-authorize-dev-phone'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('not allowed');
    });
    // The device is still on the awaiting-authorization list (not lost to a refresh)
    expect(screen.getByTestId('sync-authorize-dev-phone')).toBeInTheDocument();

    // IPC exception branch (439)
    mockSyncAuthorize.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-authorize-dev-phone'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
  });

  it('reports revoke failures and keeps the device row', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    });

    mockSyncRevoke.mockResolvedValueOnce({ success: false, error: 'still primary' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-revoke-dev-phone'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('still primary');
    });
    expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();

    // IPC exception branch (458)
    mockSyncRevoke.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-revoke-dev-phone'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
    confirmSpy.mockRestore();
  });

  it('abandons a remark edit through the cancel button and reports save rejection', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-remark-edit')).toBeInTheDocument();
    });

    // The cancel button exits the edit state (640) and does not hit the backend
    fireEvent.click(screen.getByTestId('sync-remark-edit'));
    expect(screen.getByTestId('sync-remark-input')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('sync-remark-cancel'));
    expect(screen.queryByTestId('sync-remark-input')).not.toBeInTheDocument();
    expect(mockSyncSetRemark).not.toHaveBeenCalled();

    // The save is rejected by IPC: the catch branch toasts (478 catch arm)
    fireEvent.click(screen.getByTestId('sync-remark-edit'));
    fireEvent.change(screen.getByTestId('sync-remark-input'), {
      target: { value: '新备注' },
    });
    mockSyncSetRemark.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-remark-save'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
  });

  it('reopens the conflict modal from the banner button and closes it via keep-current', async () => {
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue({ success: true, data: [] });
    mockSyncNow.mockResolvedValue({
      success: true,
      data: { pulled: 2, materialized: 1, conflicts: 1, pending_identity: 0, pushed: 1, backfilled: 0 },
    });
    mockSyncConflictsList.mockResolvedValue(conflictedList);

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });
    await waitFor(() => {
      expect(screen.getByTestId('sync-conflicts-modal')).toBeInTheDocument();
    });

    // Closing the modal (747): not handled yet
    fireEvent.click(within(screen.getByTestId('sync-conflicts-modal')).getByText('暂不处理'));
    await waitFor(() => {
      expect(screen.queryByTestId('sync-conflicts-modal')).not.toBeInTheDocument();
    });

    // Reopens from the banner button (597)
    fireEvent.click(screen.getByTestId('sync-view-conflicts-button'));
    expect(screen.getByTestId('sync-conflicts-modal')).toBeInTheDocument();
  });

  it('reports password-expiry policy save failures', async () => {
    mockIdentityHook();
    mockSetExpiry.mockResolvedValue({ success: false, error: 'locked' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.change(screen.getByTestId('password-expiry-select'), { target: { value: '30' } });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('locked');
    });

    // IPC exception branch (896)
    mockSetExpiry.mockRejectedValueOnce(new Error('ipc gone'));
    fireEvent.change(screen.getByTestId('password-expiry-select'), { target: { value: '60' } });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
  });

  it('reports biometric disable failures', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: true, platform: 'linux-polkit' },
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'));

    mockBiometricDisable.mockResolvedValueOnce({ success: false, error: 'hw error' });
    await act(async () => {
      fireEvent.click(toggle);
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('hw error');
    });

    mockBiometricDisable.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('biometric-toggle'));
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
  });

  it('surfaces the enable failure inside the reauth modal and closes it', async () => {
    mockIdentityHook();
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: true, enabled: false, platform: 'linux-polkit' },
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'false'));
    fireEvent.click(toggle);

    const reauth = await screen.findByTestId('reauth-modal');
    fireEvent.change(reauth.querySelector('input') as HTMLInputElement, {
      target: { value: 'master-pw' },
    });
    mockBiometricEnable.mockResolvedValueOnce({ success: false, error: 'nope' });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });
    await waitFor(() => {
      expect(within(reauth).getByTestId('reauth-error')).toHaveTextContent('nope');
    });

    // IPC exception branch (952)
    fireEvent.change(reauth.querySelector('input') as HTMLInputElement, {
      target: { value: 'again' },
    });
    mockBiometricEnable.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });
    await waitFor(() => {
      expect(within(reauth).getByTestId('reauth-error')).toHaveTextContent('指纹解锁设置失败');
    });

    // Closes the re-verification window (1132): usability restored
    fireEvent.click(within(reauth).getByText('取消'));
    await waitFor(() => {
      expect(screen.queryByTestId('reauth-modal')).not.toBeInTheDocument();
    });
  });

  it('keeps the travel modal open on a non-reauth failure and closes it', async () => {
    travelHook();
    // mockReset clears the mockResolvedValueOnce queue left over from earlier cases
    // (clearAllMocks does not clear the once queue; the REAUTH case's "success" once would drift here)
    mockEnterTravel.mockReset();
    mockEnterTravel.mockResolvedValueOnce({ success: false, error: 'denied' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));
    typeTravel('pw');
    typeTravelConfirm('pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent('denied');
    });
    // The modal stays open for a retry; closing exits the edit state
    expect(screen.getByTestId('travel-passphrase-modal')).toBeInTheDocument();

    // IPC exception branch (991)
    mockEnterTravel.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent('旅行模式操作失败');
    });

    fireEvent.click(within(screen.getByTestId('travel-passphrase-modal')).getByText('取消'));
    expect(screen.queryByTestId('travel-passphrase-modal')).not.toBeInTheDocument();
  });

  it('reports reauth verification failures inside the reauth modal', async () => {
    travelHook();
    mockEnterTravel.mockReset();
    mockReauthVerify.mockReset();
    mockEnterTravel.mockResolvedValueOnce({
      success: false,
      error_code: 'REAUTH_REQUIRED',
      error: 'Re-authentication required',
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));
    typeTravel('pw');
    typeTravelConfirm('pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });
    await waitFor(() => {
      expect(screen.getByTestId('reauth-modal')).toBeInTheDocument();
    });

    const reauth = screen.getByTestId('reauth-modal');
    fireEvent.change(reauth.querySelector('input') as HTMLInputElement, {
      target: { value: 'bad-pw' },
    });
    mockReauthVerify.mockResolvedValueOnce({ success: false, error: 'bad passphrase' });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });
    await waitFor(() => {
      expect(within(reauth).getByTestId('reauth-error')).toHaveTextContent('bad passphrase');
    });
    // Re-verification failed: the passphrase modal does not reopen (stay in reauth)
    expect(screen.queryByTestId('travel-passphrase-modal')).not.toBeInTheDocument();

    // IPC exception -> the generic operation-failed copy
    fireEvent.change(reauth.querySelector('input') as HTMLInputElement, {
      target: { value: 'again' },
    });
    mockReauthVerify.mockRejectedValueOnce(new Error('net'));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });
    await waitFor(() => {
      expect(within(reauth).getByTestId('reauth-error')).toHaveTextContent('旅行模式操作失败');
    });

    // Closes the re-verification window (1162-1163)
    fireEvent.click(within(reauth).getByText('取消'));
    await waitFor(() => {
      expect(screen.queryByTestId('reauth-modal')).not.toBeInTheDocument();
    });
  });

  it('cancels the change-master-password modal without rotating', async () => {
    mockIdentityHook();
    mockGetSettings.mockResolvedValue({ success: true, data: null });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.click(screen.getByTestId('change-password-button'));
    const modal = await screen.findByTestId('change-password-modal');
    expect(mockChangePw).not.toHaveBeenCalled();
    fireEvent.click(within(modal).getByText('取消'));
    await waitFor(() => {
      expect(screen.queryByTestId('change-password-modal')).not.toBeInTheDocument();
    });
  });

  it('rolls back the locale switch when the IPC call rejects', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetLocale.mockRejectedValueOnce(new Error('ipc gone'));

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });

    fireEvent.change(screen.getByTestId('locale-select'), { target: { value: 'en' } });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc gone');
    });
    expect(mockSetTrayLocale).not.toHaveBeenCalled();
    expect(screen.getByTestId('locale-select')).toHaveValue('zh-CN');

    await act(async () => {
      await i18n.changeLanguage('zh-CN');
    });
  });

  it('reports travel-mark failures and keeps the editor open', async () => {
    const identity = {
      id: 'id-1',
      name: 'Work',
      identity_type: 'Work',
      description: '',
      email: '',
      phone: '',
      tags: [],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      is_active: true,
      travel_marked: false,
    } as any;
    const loadIdentities = jest.fn().mockResolvedValue(undefined);
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
      lockService: jest.fn(),
      loadIdentities,
    });
    mockSetTravelMarked.mockResolvedValueOnce({ success: false, error: 'locked' });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();
    fireEvent.click(screen.getByTitle('编辑'));
    const toggle = await screen.findByTestId('travel-mark-toggle-id-1');

    await act(async () => {
      fireEvent.click(toggle);
    });
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('locked');
    });
    expect(loadIdentities).not.toHaveBeenCalled();

    mockSetTravelMarked.mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-mark-toggle-id-1'));
    });
    await waitFor(() => {
      // The catch branch uses the i18n copy rather than err.message (same user-facing policy as the failure response)
      expect(toast.error).toHaveBeenCalledWith('旅行标记保存失败');
    });
  });

  it('closes the modal when the backdrop is clicked outside the panel', () => {
    mockIdentityHook();
    const onClose = jest.fn();
    const { container } = render(<SettingsModal isOpen={true} onClose={onClose} />);
    // The outer backdrop is itself the event target (target === currentTarget) -> onClose
    fireEvent.mouseDown(container.firstChild as Element);
    expect(onClose).toHaveBeenCalled();
  });

  it('edits every identity draft field and saves the merged changes', async () => {
    const identity = {
      id: 'id-1',
      name: 'Work',
      identity_type: 'Work',
      description: '',
      email: '',
      phone: '',
      tags: [],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
      is_active: true,
      travel_marked: false,
    } as any;
    const updateIdentity = jest.fn().mockResolvedValue(true);
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: null,
      updateIdentity,
      deleteIdentity: jest.fn(),
      isLoading: false,
      lockService: jest.fn(),
      loadIdentities: jest.fn().mockResolvedValue(undefined),
    });

    await act(async () => {
      render(<SettingsModal isOpen={true} onClose={() => {}} />);
    });
    openIdentitiesTab();
    fireEvent.click(screen.getByTitle('编辑'));

    // Type dropdown (1536): both the name input and the dropdown may show Work, so take the select inside it
    const typeSelect = screen
      .getAllByDisplayValue('Work')
      .find((el) => el.tagName === 'SELECT') as HTMLSelectElement;
    fireEvent.change(typeSelect, { target: { value: 'Personal' } });
    // Email/phone/description inputs (1554/1562/1573)
    const field = (label: string) =>
      screen.getByText(label, { selector: 'label' }).parentElement as HTMLElement;
    fireEvent.change(field('邮箱').querySelector('input') as HTMLInputElement, {
      target: { value: 'work@example.com' },
    });
    fireEvent.change(field('电话').querySelector('input') as HTMLInputElement, {
      target: { value: '13800000000' },
    });
    fireEvent.change(field('描述').querySelector('textarea') as HTMLTextAreaElement, {
      target: { value: '主要工作身份' },
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
    });
    await waitFor(() => {
      expect(updateIdentity).toHaveBeenCalledWith(
        expect.objectContaining({
          identity_type: 'Personal',
          email: 'work@example.com',
          phone: '13800000000',
          description: '主要工作身份',
        }),
      );
    });
  });
});
