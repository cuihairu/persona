import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import toast from 'react-hot-toast';
import { useAppStore } from '@/stores/appStore';

// -- hooks: mutable return values, reset by beforeEach -----------------------------------
let serviceState: any;
let pendingSeconds: number | null = null;
let sshPending: any = null;
let passkeyPending: any = null;

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: () => serviceState,
}));
jest.mock('@/hooks/useAutoLockEvents', () => ({
  useAutoLockEvents: () => ({ pendingSeconds }),
}));
jest.mock('@/hooks/useSshApprovals', () => ({
  useSshApprovals: () => ({
    pending: sshPending,
    pendingCount: sshPending ? 2 : 0,
    respond: jest.fn(),
  }),
}));
jest.mock('@/hooks/usePasskeyApprovals', () => ({
  usePasskeyApprovals: () => ({
    pending: passkeyPending,
    pendingCount: passkeyPending ? 1 : 0,
    respond: jest.fn(),
  }),
}));

// -- Child components: dummy rendering, hooks exposed via props -------------------------------------
jest.mock('@/components/UnlockScreen', () => ({
  __esModule: true,
  default: () => <div data-testid="unlock-screen" />,
}));
jest.mock('@/components/IdentitySwitcher', () => ({
  IdentitySwitcher: (props: any) => (
    <div data-testid="identity-switcher" onClick={props.onCreateIdentity} />
  ),
  CreateIdentityModal: (props: any) =>
    props.isOpen ? <div data-testid="create-identity-modal" /> : null,
}));
jest.mock('@/components/CredentialList', () => ({
  __esModule: true,
  default: (props: any) => (
    <div data-testid="credential-list" onClick={props.onCreateCredential} />
  ),
}));
// Detail-panel composition tests: dummy-render the reveal chain (same stub style as CredentialList.test)
jest.mock('@/components/RevealSecretButton', () => ({
  __esModule: true,
  default: ({ field, label }: any) => (
    <button data-testid={`reveal-${field}`}>{label}</button>
  ),
}));
jest.mock('@/components/CreateCredentialModal', () => ({
  __esModule: true,
  default: (props: any) =>
    props.isOpen ? <div data-testid="create-credential-modal" /> : null,
}));
// Note: mock components cannot use the Fragment shorthand <>…</> (under
// jsx-runtime interop Fragment resolves to undefined → "Element type is
// invalid"), so wrap in a div instead.
jest.mock('@/components/ErrorHandling', () => ({
  ErrorBoundary: ({ children }: any) => <div>{children}</div>,
  ErrorDisplay: (props: any) => (
    <div data-testid="error-display" onClick={props.onDismiss}>
      {props.error}
    </div>
  ),
  LoadingSpinner: ({ message }: any) => <div data-testid="loading-spinner">{message}</div>,
}));
jest.mock('@/components/SshApprovalModal', () => ({
  __esModule: true,
  default: (props: any) =>
    props.request ? (
      <div data-testid="ssh-approval-modal" data-count={props.pendingCount} />
    ) : null,
}));
jest.mock('@/components/PasskeyApprovalModal', () => ({
  __esModule: true,
  default: (props: any) =>
    props.request ? (
      <div data-testid="passkey-approval-modal" data-count={props.pendingCount} />
    ) : null,
}));
jest.mock('@/components/SshAgentPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="ssh-agent-panel" />,
}));
jest.mock('@/components/WalletPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="wallet-panel" />,
}));
jest.mock('@/components/WatchtowerPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="watchtower-panel" />,
}));
jest.mock('@/components/PasskeyPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="passkey-panel" />,
}));
jest.mock('@/components/SettingsModal', () => ({
  __esModule: true,
  default: (props: any) =>
    props.isOpen ? <div data-testid="settings-modal" /> : null,
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  // Callable (update-hint toast(...)) while keeping success/error (existing assertions)
  default: Object.assign(jest.fn(), { success: jest.fn(), error: jest.fn() }),
  Toaster: () => null,
}));

// Update check off by default (no test triggers network); individual tests flip it on as needed below
jest.mock('@/utils/updateCheck', () => ({
  isUpdateCheckEnabled: jest.fn(() => false),
  checkForUpdate: jest.fn().mockResolvedValue({ status: 'none' }),
}));

jest.mock('@/utils/clipboard', () => ({
  __esModule: true,
  copyToClipboardWithToast: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    startAutoLockMonitoring: jest.fn().mockResolvedValue(undefined),
    stopAutoLockMonitoring: jest.fn().mockResolvedValue(undefined),
    getStatistics: jest.fn(),
    // All flags on by default: most existing tests assume all six views are reachable; the "all off by default" semantics is covered separately
    getWorkspaceSettings: jest.fn().mockResolvedValue({
      success: true,
      data: { features: { ssh_agent: true, wallet: true, passkeys: true, fetch_favicons: true } },
    }),
    // Tray right-click menu label push (restoring the language at startup / when switching languages)
    setTrayLocale: jest.fn().mockResolvedValue({ success: true, data: true }),
  },
}));


describe('App', () => {
  const lockService = jest.fn();
  const loadCredentialsForIdentity = jest.fn();
  const clearError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    pendingSeconds = null;
    sshPending = null;
    passkeyPending = null;
    // The real zustand store is shared across tests: reset to the factory all-off state; individual tests drive it via fetches / setState
    useAppStore.setState({
      featureFlags: { ssh_agent: false, wallet: false, passkeys: false, fetch_favicons: false },
      sidebarFilter: { kind: 'all' },
      credentials: [],
      selectedCredentialId: null,
      currentIdentity: null,
    });
    serviceState = {
      isUnlocked: false,
      currentIdentity: null,
      error: null,
      isLoading: false,
      lockService,
      loadCredentialsForIdentity,
      clearError,
      // Toolbar QuickSearch (closed state issues no request, kept as a defensive reference)
      searchCredentials: jest.fn().mockResolvedValue([]),
      switchIdentity: jest.fn(),
      // Detail-panel defensive stubs: any test writing selectedCredentialId into the store mounts the panel,
      // whose mount fetches attachment/detail data — a dangling promise produces no setState, avoiding act warnings
      getCredentialData: jest.fn(() => new Promise(() => {})),
      listAttachments: jest.fn(() => new Promise(() => {})),
      getCredentialCustomFields: jest.fn(() => new Promise(() => {})),
      toggleCredentialFavorite: jest.fn(),
      getTotpCode: jest.fn(),
      getCredentialHistory: jest.fn().mockResolvedValue([]),
      attachFileToCredential: jest.fn(),
      saveAttachmentToFile: jest.fn().mockResolvedValue(true),
      deleteAttachment: jest.fn().mockResolvedValue(true),
    };
  });

  it('shows the spinner while initializing', () => {
    serviceState.isLoading = true;
    render(<App />);
    expect(screen.getByTestId('loading-spinner')).toHaveTextContent('正在初始化 Persona…');
  });

  it('shows the unlock screen with a dismissible error when locked', () => {
    serviceState.error = 'bridge down';
    render(<App />);

    expect(screen.getByTestId('unlock-screen')).toBeInTheDocument();
    expect(screen.getByTestId('error-display')).toHaveTextContent('bridge down');

    fireEvent.click(screen.getByTestId('error-display'));
    expect(clearError).toHaveBeenCalledTimes(1);
  });

  it('starts auto-lock monitoring when unlocked and stops on lock', async () => {
    const { rerender } = render(<App />);
    expect(personaAPI.stopAutoLockMonitoring).toHaveBeenCalled();

    serviceState.isUnlocked = true;
    rerender(<App />);
    expect(personaAPI.startAutoLockMonitoring).toHaveBeenCalled();

    // flush the flags fetch triggered by the unlock, to avoid a setState warning after the test ends
    await act(async () => {});
  });

  it('renders the full workspace for an unlocked session', () => {
    serviceState.isUnlocked = true;
    serviceState.currentIdentity = { id: 'id-1', name: 'Personal' };
    render(<App />);

    expect(screen.getByTestId('credential-list')).toBeInTheDocument();
    expect(screen.getByTestId('app-sidebar')).toBeInTheDocument();
    expect(screen.getByTestId('quick-search-trigger')).toBeInTheDocument();
    expect(screen.queryByTestId('auto-lock-banner')).not.toBeInTheDocument();

    // Credentials are fetched when the identity changes
    expect(loadCredentialsForIdentity).toHaveBeenCalledWith('id-1');
  });

  it('shows the auto-lock countdown banner while a lock is pending', () => {
    serviceState.isUnlocked = true;
    pendingSeconds = 25;
    render(<App />);
    expect(screen.getByTestId('auto-lock-banner').textContent).toContain('25 秒');
  });

  it('switches between all six views', async () => {
    serviceState.isUnlocked = true;
    render(<App />);

    // After the workspace settings fetch takes effect, the advanced entries appear (the mock is all-on by default)
    await screen.findByRole('button', { name: 'SSH Agent' });

    const nav = (label: string) => fireEvent.click(screen.getByRole('button', { name: label }));

    nav('统计');
    expect(screen.getByTestId('view-title')).toHaveTextContent('统计');
    nav('SSH Agent');
    expect(screen.getByTestId('ssh-agent-panel')).toBeInTheDocument();
    nav('钱包');
    expect(screen.getByTestId('wallet-panel')).toBeInTheDocument();
    nav('安全瞭望');
    expect(screen.getByTestId('watchtower-panel')).toBeInTheDocument();
    nav('通行密钥');
    expect(screen.getByTestId('passkey-panel')).toBeInTheDocument();
    nav('全部条目');
    expect(screen.getByTestId('credential-list')).toBeInTheDocument();
  });

  it('hides advanced nav entries while their workspace flags are off', async () => {
    // Once: falls back to the top-level all-on implementation after consumption, so it does not leak into later tests
    (personaAPI.getWorkspaceSettings as jest.Mock).mockResolvedValueOnce({
      success: true,
      data: { features: { ssh_agent: false, wallet: false, passkeys: false, fetch_favicons: false } },
    });
    serviceState.isUnlocked = true;
    render(<App />);

    await waitFor(() => {
      expect(personaAPI.getWorkspaceSettings).toHaveBeenCalled();
    });

    // The core path is always visible; advanced features are hidden by default
    expect(screen.getByRole('button', { name: '全部条目' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '统计' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '安全瞭望' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'SSH Agent' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '钱包' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '通行密钥' })).not.toBeInTheDocument();
  });

  it('keeps the default flags when the settings read fails', async () => {
    (personaAPI.getWorkspaceSettings as jest.Mock).mockRejectedValueOnce(new Error('no settings'));
    serviceState.isUnlocked = true;
    render(<App />);

    await waitFor(() => {
      expect(personaAPI.getWorkspaceSettings).toHaveBeenCalled();
    });

    // A failed read silently keeps the defaults (all off); the core path is unaffected and nothing crashes
    expect(screen.getByRole('button', { name: '全部条目' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '钱包' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-panel')).not.toBeInTheDocument();
  });

  it('falls back to credentials when the current view is disabled at runtime', async () => {
    serviceState.isUnlocked = true;
    render(<App />);

    // The mock is all-on by default: switch to Wallets
    await screen.findByRole('button', { name: '钱包' });
    fireEvent.click(screen.getByRole('button', { name: '钱包' }));
    expect(screen.getByTestId('wallet-panel')).toBeInTheDocument();

    // Turning the wallet switch off at runtime: the button disappears and the view falls back automatically
    act(() => {
      useAppStore.setState({
        featureFlags: { ssh_agent: true, wallet: false, passkeys: true, fetch_favicons: true },
      });
    });

    expect(screen.queryByTestId('wallet-panel')).not.toBeInTheDocument();
    expect(screen.getByTestId('credential-list')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '钱包' })).not.toBeInTheDocument();
  });

  it('resets the sidebar filter when the identity changes', () => {
    serviceState.isUnlocked = true;
    serviceState.currentIdentity = { id: 'id-1', name: 'A' };
    useAppStore.setState({ sidebarFilter: { kind: 'category', value: 'api_keys' } });
    const { rerender } = render(<App />);

    serviceState.currentIdentity = { id: 'id-2', name: 'B' };
    rerender(<App />);

    // Switching identity discards the previous category-tree selection (the new identity may not have that type/tag)
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
  });

  it('locks the session and opens settings from the sidebar footer', () => {
    serviceState.isUnlocked = true;
    render(<App />);

    // Sidebar footer action area: look up by accessible name (no longer relying on button order)
    fireEvent.click(screen.getByRole('button', { name: '设置' }));
    expect(screen.getByTestId('settings-modal')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '锁定会话' }));
    expect(lockService).toHaveBeenCalledTimes(1);
  });

  it('locks via cmd+L and closes any open modals', () => {
    serviceState.isUnlocked = true;
    const { rerender } = render(<App />);

    // Open settings first: ⌘L resets the modal, and it does not reopen by itself after unlocking
    fireEvent.click(screen.getByRole('button', { name: '设置' }));
    expect(screen.getByTestId('settings-modal')).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'l', metaKey: true });
    expect(lockService).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('settings-modal')).not.toBeInTheDocument();

    // Pressing ⌘L again on the lock screen has no listener, so it is not triggered twice
    serviceState.isUnlocked = false;
    rerender(<App />);
    fireEvent.keyDown(window, { key: 'l', metaKey: true });
    expect(lockService).toHaveBeenCalledTimes(1);
  });

  it('copies the selected credential\'s username with cmd+E', () => {
    serviceState.isUnlocked = true;
    useAppStore.setState({
      credentials: [{ id: 'c1', identity_id: 'i1', username: 'alice', tags: [] } as any],
      selectedCredentialId: 'c1',
      currentIdentity: { id: 'i1', name: 'Me' } as any,
    });
    render(<App />);

    fireEvent.keyDown(window, { key: 'e', metaKey: true });
    expect(copyToClipboardWithToast).toHaveBeenCalledWith('alice', '用户名');
  });

  it('prompts to select an entry on cmd+E without a selection', () => {
    serviceState.isUnlocked = true;
    render(<App />);

    fireEvent.keyDown(window, { key: 'e', ctrlKey: true });
    expect(toast.error).toHaveBeenCalledWith('请先选中一个条目');
    expect(copyToClipboardWithToast).not.toHaveBeenCalled();
  });

  it('reports entries without a username on cmd+E', () => {
    serviceState.isUnlocked = true;
    useAppStore.setState({
      credentials: [{ id: 'c1', identity_id: 'i1', username: null, tags: [] } as any],
      selectedCredentialId: 'c1',
      currentIdentity: { id: 'i1', name: 'Me' } as any,
    });
    render(<App />);

    fireEvent.keyDown(window, { key: 'e', metaKey: true });
    expect(toast.error).toHaveBeenCalledWith('该条目没有用户名');
    expect(copyToClipboardWithToast).not.toHaveBeenCalled();
  });

  it('ignores a stale selection from another identity on cmd+E', () => {
    serviceState.isUnlocked = true;
    useAppStore.setState({
      credentials: [{ id: 'c1', identity_id: 'other', username: 'bob', tags: [] } as any],
      selectedCredentialId: 'c1',
      currentIdentity: { id: 'i1', name: 'Me' } as any,
    });
    render(<App />);

    fireEvent.keyDown(window, { key: 'e', metaKey: true });
    expect(toast.error).toHaveBeenCalledWith('请先选中一个条目');
    expect(copyToClipboardWithToast).not.toHaveBeenCalled();
  });

  it('toggles the settings modal with cmd+comma', () => {
    serviceState.isUnlocked = true;
    render(<App />);

    expect(screen.queryByTestId('settings-modal')).not.toBeInTheDocument();
    fireEvent.keyDown(window, { key: ',', metaKey: true });
    expect(screen.getByTestId('settings-modal')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: ',', metaKey: true });
    expect(screen.queryByTestId('settings-modal')).not.toBeInTheDocument();
  });

  it('opens the create-identity and create-credential modals from their triggers', () => {
    serviceState.isUnlocked = true;
    render(<App />);

    fireEvent.click(screen.getByTestId('identity-switcher'));
    expect(screen.getByTestId('create-identity-modal')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('credential-list'));
    expect(screen.getByTestId('create-credential-modal')).toBeInTheDocument();
  });

  it('renders ssh and passkey approval modals only with pending requests', () => {
    serviceState.isUnlocked = true;
    sshPending = { request_id: 'r1' };
    passkeyPending = { request_id: 'r2' };
    render(<App />);

    expect(screen.getByTestId('ssh-approval-modal').getAttribute('data-count')).toBe('2');
    expect(screen.getByTestId('passkey-approval-modal').getAttribute('data-count')).toBe('1');
  });

  it('statistics view loads data and renders the cards, or survives failure', async () => {
    serviceState.isUnlocked = true;
    (personaAPI.getStatistics as jest.Mock).mockResolvedValueOnce({
      success: true,
      data: {
        total_identities: 3,
        total_credentials: 11,
        active_credentials: 7,
        favorite_credentials: 2,
        credential_types: { Login: 6, ApiKey: 5 },
        security_levels: { High: 9 },
      },
    });

    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: '统计' }));

    await waitFor(() => {
      expect(screen.getByText('身份总数')).toBeInTheDocument();
    });
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.getByText('高')).toBeInTheDocument();

    // Failure branch: the console.error is silenced and the loading state is kept
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
    (personaAPI.getStatistics as jest.Mock).mockRejectedValueOnce(new Error('x'));
    fireEvent.click(screen.getByRole('button', { name: '全部条目' }));
    fireEvent.click(screen.getByRole('button', { name: '统计' }));
    await act(async () => {});
    consoleError.mockRestore();
  });

  // -- Detail pane composition (the pane hangs in the main area's detail column; the full selection/data/close/delete chain) --------

  const setupDetail = (serviceOver: Record<string, any> = {}) => {
    serviceState.isUnlocked = true;
    serviceState.currentIdentity = { id: 'id-1', name: 'Personal' };
    // The pane pulls attachments while mounting (a dangling promise produces no setState); every other service surface is a defensive stub
    serviceState.getCredentialData = jest.fn().mockResolvedValue(null);
    serviceState.listAttachments = jest.fn(() => new Promise(() => {}));
    serviceState.getCredentialCustomFields = jest.fn(() => new Promise(() => {}));
    serviceState.toggleCredentialFavorite = jest.fn();
    serviceState.getTotpCode = jest.fn();
    serviceState.getCredentialHistory = jest.fn().mockResolvedValue([]);
    serviceState.attachFileToCredential = jest.fn();
    serviceState.saveAttachmentToFile = jest.fn().mockResolvedValue(true);
    serviceState.deleteAttachment = jest.fn().mockResolvedValue(true);
    Object.assign(serviceState, serviceOver);
    useAppStore.setState({
      credentials: [
        {
          id: 'c1',
          identity_id: 'id-1',
          name: 'Example',
          credential_type: 'Password',
          security_level: 'High',
          tags: [],
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
          is_active: true,
          is_favorite: false,
        },
      ],
      selectedCredentialId: 'c1',
    });
  };

  it('shows the detail placeholder when nothing is selected', () => {
    serviceState.isUnlocked = true;
    serviceState.currentIdentity = { id: 'id-1', name: 'Personal' };
    render(<App />);

    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
    expect(screen.getByText('选择一个条目查看详情')).toBeInTheDocument();
    expect(screen.queryByTestId('detail-pane')).not.toBeInTheDocument();
  });

  it('loads credential data and renders the pane for the store selection', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: { email: 'a@b.com' },
    });
    setupDetail({ getCredentialData });
    render(<App />);

    await screen.findByTestId('detail-pane');
    expect(getCredentialData).toHaveBeenCalledWith('c1');
    // The pane renders in a loading state first; field values appear only once App's async load finishes
    await screen.findByText('a@b.com');
  });

  it('shows a loading state while credential data is in flight', async () => {
    let resolveData: (v: any) => void = () => {};
    const getCredentialData = jest.fn(
      () => new Promise((resolve) => { resolveData = resolve; }),
    );
    setupDetail({ getCredentialData });
    render(<App />);

    expect(await screen.findByTestId('detail-loading')).toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();

    await act(async () => {
      resolveData({ credential_type: 'Password', data: { email: 'a@b.com' } });
    });
    expect(screen.getByText('a@b.com')).toBeInTheDocument();
    expect(screen.queryByTestId('detail-loading')).not.toBeInTheDocument();
  });

  it('closing the pane clears the store selection', async () => {
    setupDetail({
      getCredentialData: jest.fn().mockResolvedValue({ credential_type: 'Password', data: {} }),
    });
    render(<App />);

    await screen.findByTestId('detail-pane');
    fireEvent.click(screen.getByTitle('关闭'));
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
  });

  it('deleting the selected credential clears the pane', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    const deleteCredential = jest.fn().mockResolvedValue(true);
    setupDetail({
      getCredentialData: jest.fn().mockResolvedValue({ credential_type: 'Password', data: {} }),
      deleteCredential,
    });
    render(<App />);

    await screen.findByTestId('detail-pane');
    fireEvent.click(screen.getByTitle('删除'));
    await act(async () => {});
    expect(deleteCredential).toHaveBeenCalledWith('c1');
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it('unlock gate resolves immediately when already on the unlock screen', async () => {
    serviceState.isUnlocked = false;
    render(<App />);
    const resolve = jest.fn();
    window.dispatchEvent(new CustomEvent('persona:need-unlock', { detail: { resolve } }));
    expect(resolve).toHaveBeenCalledWith(false);
    expect(screen.queryByTestId('unlock-gate-modal')).not.toBeInTheDocument();
  });

  it('unlock gate opens and resolves through the modal cancel', async () => {
    serviceState.isUnlocked = true;
    // The event handler reads the store's unlocked state (not serviceState)
    useAppStore.setState({ isUnlocked: true });
    render(<App />);
    const resolve = jest.fn();
    window.dispatchEvent(new CustomEvent('persona:need-unlock', { detail: { resolve } }));
    await screen.findByTestId('unlock-gate-modal');
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(resolve).toHaveBeenCalledWith(false);
    expect(screen.queryByTestId('unlock-gate-modal')).not.toBeInTheDocument();
  });

  it('clicking a vault in the sidebar switches to that identity', async () => {
    serviceState.isUnlocked = true;
    useAppStore.setState({
      identities: [{ id: 'vault-1', name: 'Work', identity_type: 'Work' } as any],
      currentIdentity: null,
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'Work' }));
    expect(serviceState.switchIdentity).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'vault-1' }),
    );
  });

  it('toasts when an update is available', async () => {
    const uc = jest.requireMock('@/utils/updateCheck') as {
      isUpdateCheckEnabled: jest.Mock;
      checkForUpdate: jest.Mock;
    };
    uc.isUpdateCheckEnabled.mockReturnValue(true);
    uc.checkForUpdate.mockResolvedValue({
      status: 'update-available',
      latestVersion: '2.0.0',
    });
    serviceState.isUnlocked = false;
    render(<App />);
    await waitFor(() => expect(toast).toHaveBeenCalled());
  });
});
