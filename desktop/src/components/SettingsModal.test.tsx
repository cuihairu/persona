import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import SettingsModal from './SettingsModal';
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
    // Connect 本机自动化区块（SecurityPane 后的 section）
    connectServerStatus: jest.fn(),
    connectServerStart: jest.fn(),
    connectServerStop: jest.fn(),
    connectTokenList: jest.fn(),
    connectTokenCreate: jest.fn(),
    connectTokenRevoke: jest.fn(),
    getIdentities: jest.fn(),
    // E2EE sync 设备管理
    syncDeviceStatus: jest.fn(),
    syncJoin: jest.fn(),
    syncLeave: jest.fn(),
    syncListDevices: jest.fn(),
    syncAuthorize: jest.fn(),
    syncRevoke: jest.fn(),
    syncNow: jest.fn(),
    syncRotate: jest.fn(),
    syncConflictsList: jest.fn(),
    syncConflictResolve: jest.fn(),
  },
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const mockSetFlags = personaAPI.setFeatureFlags as jest.Mock;
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
const mockSyncAuthorize = personaAPI.syncAuthorize as jest.Mock;
const mockSyncRevoke = personaAPI.syncRevoke as jest.Mock;
const mockSyncNow = personaAPI.syncNow as jest.Mock;
const mockSyncRotate = personaAPI.syncRotate as jest.Mock;
const mockSyncConflictsList = personaAPI.syncConflictsList as jest.Mock;

const inactiveTravel = {
  success: true,
  data: { active: false, entered_at: null, sidecar_exists: false, inconsistent: false },
};

/** 空设置响应（SyncServerPane 的初始加载） */
const emptySettings = { success: true, data: null };

/** General 默认可见；身份管理用例需先切到 Identities tab */
const openIdentitiesTab = () => {
  fireEvent.click(screen.getByRole('tab', { name: '身份' }));
};

/** 旅行口令弹窗输入辅助 */
const typeTravel = (value: string) =>
  fireEvent.change(screen.getByTestId('travel-passphrase-input'), { target: { value } });
const typeTravelConfirm = (value: string) =>
  fireEvent.change(screen.getByTestId('travel-passphrase-confirm-input'), {
    target: { value },
  });

describe('components/SettingsModal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // theme 在 store 里跨用例存活，逐用例复位
    useAppStore.setState({ theme: 'system', featureFlags: { ...DEFAULT_FEATURE_FLAGS } });
    mockGetSettings.mockResolvedValue(emptySettings);
    // 默认 keyring 无 token（placeholder = 'API token'）
    mockTokenPresent.mockResolvedValue({ success: true, data: false });
    // 默认系统不可用 biometric（开关禁用 + 不可用提示）
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: false, enabled: false, platform: 'linux-polkit' },
    });
    // 默认旅行模式关闭
    mockGetTravelStatus.mockResolvedValue(inactiveTravel);
    // 默认 Connect listener 关闭、无 token、无身份
    mockConnectStatus.mockResolvedValue({ success: true, data: { running: false, port: null } });
    mockConnectList.mockResolvedValue({ success: true, data: [] });
    mockGetIdentities.mockResolvedValue({ success: true, data: [] });
    // 默认未加入 E2EE sync（join 表单可见，不拉设备列表）
    mockSyncStatus.mockResolvedValue({
      success: true,
      data: { joined: false, corrupted: false, device_id: null, device_name: null },
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

  it('shows the general pane with feature-flag switches by default', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    // 默认 tab：General 四开关（出厂全关），身份区块不可见
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

  it('renders the theme picker with the current preference checked', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    useAppStore.setState({ theme: 'dark' });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    expect(screen.getByRole('radiogroup', { name: '外观' })).toBeInTheDocument();
    expect(screen.getByTestId('theme-option-system')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('theme-option-light')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('theme-option-dark')).toHaveAttribute('aria-checked', 'true');
  });

  it('writes the theme preference to the store without touching feature flags', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    fireEvent.click(screen.getByTestId('theme-option-dark'));
    expect(useAppStore.getState().theme).toBe('dark');

    fireEvent.click(screen.getByTestId('theme-option-light'));
    expect(useAppStore.getState().theme).toBe('light');

    // Theme 与功能开关互不相干（组件只写 store，html class 由 App 层 useTheme 应用）
    expect(mockSetFlags).not.toHaveBeenCalled();
  });

  it('toggles a flag optimistically and adopts the server truth', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    // 服务端把三个位一起确认（比如另一处改动）：以返回值为准
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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
      // 服务端真相（全开）覆盖 optimistic 值
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    fireEvent.click(screen.getByTestId('feature-toggle-wallet'));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('ipc down');
    });
    // 回滚到出厂全关
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

  it('rolls back with the backend error message when the save is refused', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });
    mockSetFlags.mockResolvedValueOnce({ success: false, error: 'Service is locked' });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    fireEvent.click(screen.getByTestId('feature-toggle-passkeys'));

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Service is locked');
    });
    expect(useAppStore.getState().featureFlags.passkeys).toBe(false);
  });

  it('shows empty state when no identities', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    openIdentitiesTab();
    fireEvent.click(screen.getByTitle('删除'));

    await act(async () => {});

    expect(deleteIdentity).toHaveBeenCalledWith('1');
    confirmSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 同步服务器区块
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
    // 后端 sync.server_token 恒回空串（真值在 OS keyring）；
    // placeholder 由 sync_token_present 的存在性查询驱动
    mockGetSettings.mockResolvedValue({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://sync.example.com', server_token: '' },
      },
    });
    mockTokenPresent.mockResolvedValue({ success: true, data: true });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByTestId('sync-url-input')).toHaveValue('https://sync.example.com');
    });
    expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    // token 永不回填输入框（避免令牌常驻前端内存）；placeholder 提示已有保存
    const tokenInput = screen.getByTestId('sync-token-input') as HTMLInputElement;
    expect(tokenInput.type).toBe('password');
    expect(tokenInput.value).toBe('');
    await waitFor(() => {
      expect(tokenInput.placeholder).toContain('留空表示保持不变');
    });
  });

  it('saves sync config, adopts server truth and clears the token field', async () => {
    mockIdentityHook();
    // 保存后 placeholder 重查 keyring 存在性（新 token 已入库）
    mockTokenPresent.mockResolvedValue({ success: true, data: true });
    mockSetSync.mockResolvedValueOnce({
      success: true,
      data: {
        features: { ...DEFAULT_FEATURE_FLAGS },
        sync: { enabled: true, server_url: 'https://s.example.com', server_token: '' },
      },
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    // 打开开关仅展开表单，不立即保存
    fireEvent.click(screen.getByTestId('sync-toggle'));
    expect(mockSetSync).not.toHaveBeenCalled();

    fireEvent.change(screen.getByTestId('sync-url-input'), {
      target: { value: 'https://s.example.com' },
    });
    fireEvent.change(screen.getByTestId('sync-token-input'), { target: { value: 'fresh-tok' } });
    // save() 异步链（IPC mock resolve → setState → placeholder 重查）整体在 act 内 flush
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
    // 服务端真相回填；token 输入框清空（空串 = 后端保留旧值）；
    // placeholder 重查 keyring 存在性，全部微任务在 act 内 flush
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    fireEvent.click(screen.getByTestId('sync-toggle'));
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-toggle')).toHaveAttribute('aria-checked', 'true');
    });

    // toggle-off 立即保存：save() 异步链在 act 内 flush（同上一用例）
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

  // -------------------------------------------------------------------------
  // 密码安全区块（过期策略 + 手动改密）
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    // 服务端真相未回填前默认 Never（旧 JSON 缺键同型）
    await waitFor(() => {
      expect(screen.getByTestId('password-expiry-select')).toHaveValue('');
    });

    fireEvent.change(screen.getByTestId('password-expiry-select'), {
      target: { value: '180' },
    });

    await waitFor(() => {
      expect(mockSetExpiry).toHaveBeenCalledWith(180);
    });
    // 以服务端返回为准回填
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    // 手动改密走非 forced 弹窗：可取消，旧密码不预填
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
    // 改密成功 → 回锁屏（state.service 旧会话密钥已作废）
    await waitFor(() => {
      expect(lockService).toHaveBeenCalledTimes(1);
    });
    expect(toast.success).toHaveBeenCalledWith('主密码已修改——请重新登录');
    expect(screen.queryByTestId('change-password-modal')).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // biometric 解锁区块（开 = ReauthModal 验密；关 = 直接禁用）
  // -------------------------------------------------------------------------

  it('disables the biometric switch with an unavailable hint when the OS lacks support', async () => {
    mockIdentityHook();

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    const toggle = await screen.findByTestId('biometric-toggle');
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    // status 回填后切换到不可用提示（加载中显示的是普通 hint）
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);

    // 开启先验主密码（ReauthModal），不直接调 enable
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    // 密码不对：错误留在弹窗内原地重试，开关不翻
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    // 启用后显示硬件绑定档位行（密钥被硬件包裹，非密码托管）
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    const toggle = await screen.findByTestId('biometric-toggle');
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'));
    // 收紧操作不设密码门禁：一键直删 keyring 条目
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
  // 旅行模式区块（SecurityPane 状态行 + 口令弹窗 + REAUTH 重试）
  // -------------------------------------------------------------------------

  /** travel 用例的 hook mock：带 loadIdentities（enter/exit 成功后重载列表） */
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('travel-exit-button')).not.toBeInTheDocument();

    // 活动态换显 exit 按钮
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
    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));

    // 口令窗 mode=set：双录
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('travel-exit-button')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('travel-exit-button'));

    // mode=enter：单录
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

    // 改对口令原地重试成功
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('travel-enter-button')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('travel-enter-button'));
    typeTravel('travel-pw');
    typeTravelConfirm('travel-pw');
    await act(async () => {
      fireEvent.click(screen.getByTestId('travel-passphrase-submit'));
    });

    // 敏感操作门禁：口令窗收起、弹主密码重验
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

    // 验证通过 → 按原意图（enter）重开口令窗，travel 口令需重输
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
  // 身份编辑表单的 travel 标记开关（即时生效）
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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
  // E2EE sync 设备区块（SyncDevicesSection）
  // -------------------------------------------------------------------------

  /** joined 状态的默认响应（本机名为 laptop） */
  const joinedStatus = {
    success: true,
    data: { joined: true, corrupted: false, device_id: 'dev-self', device_name: 'laptop' },
  };

  /** 同步组两台设备：本机已授权 + phone 待授权 */
  const twoDevices = {
    success: true,
    data: [
      { id: 'dev-self', device_name: 'laptop', created_at: '2026-09-23T00:00:00Z', authorized: true, this_device: true },
      { id: 'dev-phone', device_name: 'phone', created_at: '2026-09-23T01:00:00Z', authorized: false, this_device: false },
    ],
  };

  it('shows the join form while not joined and skips the device list', async () => {
    mockIdentityHook();
    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-device-name-input')).toBeInTheDocument();
    expect(mockSyncList).not.toHaveBeenCalled();
  });

  it('rejects an empty device name without touching the backend', async () => {
    mockIdentityHook();
    render(<SettingsModal isOpen={true} onClose={() => {}} />);

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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-device-name-input')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('sync-device-name-input'), {
      target: { value: '  我的笔记本  ' },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-join-button'));
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-joined')).toBeInTheDocument();
    });
    expect(screen.getByText('已加入：laptop')).toBeInTheDocument();
    // 设备列表在 status.joined 触发的二次 effect 里异步拉取
    await waitFor(() => {
      expect(screen.getByTestId('sync-device-this-badge')).toBeInTheDocument();
    });
    expect(screen.getByTestId('sync-device-pending-badge')).toBeInTheDocument();
    expect(mockSyncList).toHaveBeenCalled();

    // 本机行无授权/吊销按钮；待授权的 phone 行有授权按钮
    expect(screen.getByTestId('sync-authorize-dev-phone')).toBeInTheDocument();
    expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    expect(screen.queryByTestId('sync-authorize-dev-self')).not.toBeInTheDocument();
    expect(screen.queryByTestId('sync-revoke-dev-self')).not.toBeInTheDocument();

    // leave 入口
    expect(screen.getByTestId('sync-leave-button')).toBeInTheDocument();
  });

  it('revokes a device after confirm and refreshes the list', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncRevoke.mockResolvedValue({ success: true, data: true });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-revoke-dev-phone')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-revoke-dev-phone'));
    });

    expect(mockSyncRevoke).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // 轮换入口（阶段 3d）：确认后调 sync_rotate 并汇报计数；取消不调用。
  // 完整轮换语义在 core runtime + server 真 TCP 测试覆盖。
  it('rotates the group key after confirm and reports the counts', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockIdentityHook();
    mockSyncStatus.mockResolvedValue(joinedStatus);
    mockSyncList.mockResolvedValue(twoDevices);
    mockSyncRotate.mockResolvedValue({
      success: true,
      data: { rewrapped: 2, skipped: 0, pushed: 4 },
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-rotate-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-rotate-button'));
    });

    expect(mockSyncRotate).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // 并发轮换互斥（epoch 乐观锁）：后到者拿 CONCURRENT_CONFLICT 码，
  // 显示针对性重试提示而非笼统「轮换失败」。
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByTestId('sync-devices-corrupted')).toBeInTheDocument();
    });
    // 损坏状态仍可重新 join（leave 清残留后再加入的路径）
    expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // 冲突裁决入口（阶段 3c：syncNow → conflicts>0 → banner + 裁决弹窗）
  // -------------------------------------------------------------------------

  /** 冲突裁决弹窗的数据面由 SyncConflictsModal.test.tsx 全覆盖；这里只验
   *  SettingsModal 侧的接线：syncNow 报告 conflicts>0 时亮 banner 并自动
   *  开窗，conflicts=0 时不出入口。 */
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.getByTestId('sync-now-button')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('sync-now-button'));
    });

    await waitFor(() => {
      expect(mockSyncNow).toHaveBeenCalled();
    });
    // conflicts>0：banner 亮起 + 裁决弹窗自动打开
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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

    render(<SettingsModal isOpen={true} onClose={() => {}} />);
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
    // 状态切回 join 表单
    await waitFor(() => {
      expect(screen.getByTestId('sync-join-button')).toBeInTheDocument();
    });
    confirmSpy.mockRestore();
  });
});
