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

/** 空设置响应（SyncServerPane 的初始加载） */
const emptySettings = { success: true, data: null };

/** General 默认可见；身份管理用例需先切到 Identities tab */
const openIdentitiesTab = () => {
  fireEvent.click(screen.getByRole('tab', { name: 'Identities' }));
};

describe('components/SettingsModal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // theme 在 store 里跨用例存活，逐用例复位
    useAppStore.setState({ theme: 'system', featureFlags: { ...DEFAULT_FEATURE_FLAGS } });
    mockGetSettings.mockResolvedValue(emptySettings);
    // 默认 keyring 无 token（placeholder = 'API token'）
    mockTokenPresent.mockResolvedValue({ success: true, data: false });
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
    expect(screen.getByRole('tab', { name: 'General' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('switch', { name: 'SSH Agent' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByRole('switch', { name: 'Wallets' })).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByRole('switch', { name: 'Passkeys' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByTestId('feature-toggle-passkeys').closest('div')).toHaveTextContent(
      'Takes effect the next time you unlock',
    );
    expect(screen.getByRole('switch', { name: 'Website icons' })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByTestId('feature-toggle-fetch_favicons').closest('div')).toHaveTextContent(
      'Off by default — no network requests until you opt in',
    );
    expect(screen.queryByText('No identities yet.')).not.toBeInTheDocument();
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

    expect(screen.getByRole('radiogroup', { name: 'Theme' })).toBeInTheDocument();
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
    expect(screen.getByRole('switch', { name: 'Wallets' })).toHaveAttribute(
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
    expect(screen.getByText('No identities yet.')).toBeInTheDocument();
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

    fireEvent.click(screen.getByTitle('Edit'));

    const inputs = () => document.querySelectorAll('input.input');
    // order: name, email, phone, tags
    fireEvent.change(inputs()[0], { target: { value: ' New Name ' } });
    fireEvent.change(inputs()[3], { target: { value: 'a, b, c, c' } });

    fireEvent.click(screen.getByText('Save'));

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
    fireEvent.click(screen.getByTitle('Delete'));

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
      expect(tokenInput.placeholder).toContain('leave blank to keep');
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
      expect(toast.success).toHaveBeenCalledWith('Sync settings saved');
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
      expect(toast.error).toHaveBeenCalledWith('Server URL is required when sync is enabled');
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
});
