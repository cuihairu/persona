import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';

// -- hooks：可变返回值，由 beforeEach 重置 -----------------------------------
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

// -- 子组件：哑渲染，暴露 props 驱动钩子 -------------------------------------
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
jest.mock('@/components/CreateCredentialModal', () => ({
  __esModule: true,
  default: (props: any) =>
    props.isOpen ? <div data-testid="create-credential-modal" /> : null,
}));
// 注意：mock 组件里不能用 Fragment 简写 <>…</>（jsx-runtime 互操作下
// Fragment 会解析成 undefined → "Element type is invalid"），用 div 包裹。
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
  default: { success: jest.fn(), error: jest.fn() },
  Toaster: () => null,
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    startAutoLockMonitoring: jest.fn().mockResolvedValue(undefined),
    stopAutoLockMonitoring: jest.fn().mockResolvedValue(undefined),
    getStatistics: jest.fn(),
    // 默认返回全开：多数既有用例假设六个视图都可达；"默认全关"语义单独覆盖
    getWorkspaceSettings: jest.fn().mockResolvedValue({
      success: true,
      data: { features: { ssh_agent: true, wallet: true, passkeys: true, fetch_favicons: true } },
    }),
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
    // 真实 zustand store 跨用例共享：复位为出厂全关，由各用例经拉取/ setState 驱动
    useAppStore.setState({
      featureFlags: { ssh_agent: false, wallet: false, passkeys: false, fetch_favicons: false },
      sidebarFilter: { kind: 'all' },
    });
    serviceState = {
      isUnlocked: false,
      currentIdentity: null,
      error: null,
      isLoading: false,
      lockService,
      loadCredentialsForIdentity,
      clearError,
      // 工具栏 QuickSearch（closed 态不发请求，仅防御引用）
      searchCredentials: jest.fn().mockResolvedValue([]),
      switchIdentity: jest.fn(),
    };
  });

  it('shows the spinner while initializing', () => {
    serviceState.isLoading = true;
    render(<App />);
    expect(screen.getByTestId('loading-spinner')).toHaveTextContent('Initializing Persona...');
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

    // flush 解锁后触发的 flags 拉取，避免测试结束后 setState 警告
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

    // 身份变化时拉取凭据
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

    // workspace settings 拉取生效后高级入口出现（默认 mock 全开）
    await screen.findByRole('button', { name: 'SSH Agent' });

    const nav = (label: string) => fireEvent.click(screen.getByRole('button', { name: label }));

    nav('Statistics');
    expect(screen.getByTestId('view-title')).toHaveTextContent('Statistics');
    nav('SSH Agent');
    expect(screen.getByTestId('ssh-agent-panel')).toBeInTheDocument();
    nav('Wallets');
    expect(screen.getByTestId('wallet-panel')).toBeInTheDocument();
    nav('Watchtower');
    expect(screen.getByTestId('watchtower-panel')).toBeInTheDocument();
    nav('Passkeys');
    expect(screen.getByTestId('passkey-panel')).toBeInTheDocument();
    nav('Credentials');
    expect(screen.getByTestId('credential-list')).toBeInTheDocument();
  });

  it('hides advanced nav entries while their workspace flags are off', async () => {
    // Once：消费后回退到顶层的全开实现，不泄漏到后续用例
    (personaAPI.getWorkspaceSettings as jest.Mock).mockResolvedValueOnce({
      success: true,
      data: { features: { ssh_agent: false, wallet: false, passkeys: false, fetch_favicons: false } },
    });
    serviceState.isUnlocked = true;
    render(<App />);

    await waitFor(() => {
      expect(personaAPI.getWorkspaceSettings).toHaveBeenCalled();
    });

    // 主航道恒可见，高级功能默认隐藏
    expect(screen.getByRole('button', { name: 'Credentials' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Statistics' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Watchtower' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'SSH Agent' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wallets' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Passkeys' })).not.toBeInTheDocument();
  });

  it('keeps the default flags when the settings read fails', async () => {
    (personaAPI.getWorkspaceSettings as jest.Mock).mockRejectedValueOnce(new Error('no settings'));
    serviceState.isUnlocked = true;
    render(<App />);

    await waitFor(() => {
      expect(personaAPI.getWorkspaceSettings).toHaveBeenCalled();
    });

    // 读取失败静默保持默认（全关），主航道不受影响、不崩
    expect(screen.getByRole('button', { name: 'Credentials' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wallets' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-panel')).not.toBeInTheDocument();
  });

  it('falls back to credentials when the current view is disabled at runtime', async () => {
    serviceState.isUnlocked = true;
    render(<App />);

    // 默认 mock 全开：切到 Wallets
    await screen.findByRole('button', { name: 'Wallets' });
    fireEvent.click(screen.getByRole('button', { name: 'Wallets' }));
    expect(screen.getByTestId('wallet-panel')).toBeInTheDocument();

    // 运行中关闭 wallet 开关：按钮消失、视图自动回退
    act(() => {
      useAppStore.setState({
        featureFlags: { ssh_agent: true, wallet: false, passkeys: true, fetch_favicons: true },
      });
    });

    expect(screen.queryByTestId('wallet-panel')).not.toBeInTheDocument();
    expect(screen.getByTestId('credential-list')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wallets' })).not.toBeInTheDocument();
  });

  it('resets the sidebar filter when the identity changes', () => {
    serviceState.isUnlocked = true;
    serviceState.currentIdentity = { id: 'id-1', name: 'A' };
    useAppStore.setState({ sidebarFilter: { kind: 'type', value: 'ApiKey' } });
    const { rerender } = render(<App />);

    serviceState.currentIdentity = { id: 'id-2', name: 'B' };
    rerender(<App />);

    // 换身份丢弃旧分类树选中（新身份未必还有该类型/标签）
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
  });

  it('locks the session and opens settings from the sidebar footer', () => {
    serviceState.isUnlocked = true;
    render(<App />);

    // 侧栏底部操作区：按可访问名取（不再依赖按钮顺序）
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByTestId('settings-modal')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Lock session' }));
    expect(lockService).toHaveBeenCalledTimes(1);
  });

  it('locks via cmd+L and closes any open modals', () => {
    serviceState.isUnlocked = true;
    const { rerender } = render(<App />);

    // 先开设置：⌘L 后 modal 复位，解锁后不会自动重开
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    expect(screen.getByTestId('settings-modal')).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'l', metaKey: true });
    expect(lockService).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('settings-modal')).not.toBeInTheDocument();

    // 锁定屏上再按 ⌘L 无监听，不重复触发
    serviceState.isUnlocked = false;
    rerender(<App />);
    fireEvent.keyDown(window, { key: 'l', metaKey: true });
    expect(lockService).toHaveBeenCalledTimes(1);
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
    fireEvent.click(screen.getByRole('button', { name: 'Statistics' }));

    await waitFor(() => {
      expect(screen.getByText('Total Identities')).toBeInTheDocument();
    });
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();

    // 失败分支：静默 console.error，保持加载态
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
    (personaAPI.getStatistics as jest.Mock).mockRejectedValueOnce(new Error('x'));
    fireEvent.click(screen.getByRole('button', { name: 'Credentials' }));
    fireEvent.click(screen.getByRole('button', { name: 'Statistics' }));
    await act(async () => {});
    consoleError.mockRestore();
  });
});
