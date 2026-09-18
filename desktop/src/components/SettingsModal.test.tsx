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
  },
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const mockSetFlags = personaAPI.setFeatureFlags as jest.Mock;

/** General 默认可见；身份管理用例需先切到 Identities tab */
const openIdentitiesTab = () => {
  fireEvent.click(screen.getByRole('tab', { name: 'Identities' }));
};

describe('components/SettingsModal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // theme 在 store 里跨用例存活，逐用例复位
    useAppStore.setState({ theme: 'system', featureFlags: { ...DEFAULT_FEATURE_FLAGS } });
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

    // 默认 tab：General 三开关（出厂全关），身份区块不可见
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
        features: { ssh_agent: true, wallet: true, passkeys: true },
      },
    });

    render(<SettingsModal isOpen={true} onClose={() => {}} />);

    fireEvent.click(screen.getByTestId('feature-toggle-ssh_agent'));

    await waitFor(() => {
      expect(mockSetFlags).toHaveBeenCalledWith({
        ssh_agent: true,
        wallet: false,
        passkeys: false,
      });
    });
    await waitFor(() => {
      // 服务端真相（全开）覆盖 optimistic 值
      expect(useAppStore.getState().featureFlags).toEqual({
        ssh_agent: true,
        wallet: true,
        passkeys: true,
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
});
