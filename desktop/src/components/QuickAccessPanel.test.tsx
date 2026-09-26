import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import QuickAccessPanel from './QuickAccessPanel';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import type { Credential, Identity } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    revealCredentialSecret: jest.fn(),
    getTotpCode: jest.fn(),
    quickAccessOpenCredential: jest.fn(),
    focusMainWindow: jest.fn(),
  },
}));

jest.mock('@/utils/clipboard', () => ({
  copyToClipboardWithToast: jest.fn(),
}));

jest.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({ hide: jest.fn().mockResolvedValue(undefined) }),
}));

jest.mock('@tauri-apps/api/event', () => ({
  listen: jest.fn().mockResolvedValue(() => {}),
}));

jest.mock('@/hooks/usePersonaService');
jest.mock('@/components/ReauthModal', () => () => null);
jest.mock('@/components/FaviconImg', () => () => null);

const mockService = usePersonaService as jest.Mock;
const mockCopy = jest.requireMock('@/utils/clipboard').copyToClipboardWithToast as jest.Mock;
const mockReveal = personaAPI.revealCredentialSecret as jest.Mock;
const mockTotp = personaAPI.getTotpCode as jest.Mock;
const mockOpenCred = personaAPI.quickAccessOpenCredential as jest.Mock;
const mockFocusMain = personaAPI.focusMainWindow as jest.Mock;

const identity = (id: string, name: string): Identity =>
  ({
    id,
    name,
    identity_type: 'Personal',
    description: null,
    email: null,
    phone: null,
    tags: [],
    is_active: true,
    travel_marked: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }) as unknown as Identity;

const credential = (overrides: Partial<Credential>): Credential =>
  ({
    id: 'c1',
    identity_id: 'i1',
    name: 'GitHub',
    username: 'octocat',
    url: 'https://github.com',
    credential_type: 'Password',
    ...overrides,
  }) as Credential;

/** 默认：已解锁 + 一个身份 + 搜索返回两条 */
const setup = (results: Credential[] = [credential({}), credential({ id: 'c2', name: 'GitLab' })]) => {
  mockService.mockReturnValue({
    isUnlocked: true,
    searchCredentials: jest.fn().mockResolvedValue(results),
    checkServiceStatus: jest.fn(),
  });
  useAppStore.setState({ identities: [identity('i1', 'Personal')] });
};

beforeAll(() => {
  // react-hot-toast 的 Toaster 挂载即读 matchMedia（prefers-reduced-motion），
  // jsdom 没实现——不补这个桩，渲染路径随用例顺序随机炸
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

beforeEach(() => {
  jest.clearAllMocks();
  mockService.mockReset();
  useAppStore.setState({ identities: [] });
});

describe('components/QuickAccessPanel', () => {
  it('prompts to unlock in the main window when the vault is locked', () => {
    setup([]);
    mockService.mockReturnValue({
      isUnlocked: false,
      searchCredentials: jest.fn(),
      checkServiceStatus: jest.fn(),
    });

    render(<QuickAccessPanel />);

    expect(screen.getByTestId('quick-access-locked')).toBeInTheDocument();
    expect(screen.queryByTestId('quick-access-input')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('quick-access-unlock-button'));
    expect(mockFocusMain).toHaveBeenCalledTimes(1);
  });

  it('searches after the debounce and groups results by identity', async () => {
    setup();
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });

    await waitFor(() => {
      expect(screen.getAllByTestId('quick-access-item')).toHaveLength(2);
    });
    const search = mockService().searchCredentials as jest.Mock;
    expect(search).toHaveBeenCalledWith('git');
    expect(screen.getByText('Personal')).toBeInTheDocument();
  });

  it('does not search while the query is empty', async () => {
    setup();
    render(<QuickAccessPanel />);

    await waitFor(() => {
      expect(screen.getByTestId('quick-access-results')).toHaveTextContent('输入');
    });
    const search = mockService().searchCredentials as jest.Mock;
    expect(search).not.toHaveBeenCalled();
  });

  it('Enter copies the primary secret field of the active row', async () => {
    setup([credential({})]);
    mockReveal.mockResolvedValue({ success: true, data: { field: 'password', value: 's3cret' } });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => {
      expect(mockReveal).toHaveBeenCalledWith('c1', 'password');
    });
    expect(mockCopy).toHaveBeenCalledWith('s3cret', '密码');
  });

  it('Enter falls back to the username for types with no revealable secret', async () => {
    setup([credential({ credential_type: 'BankCard' })]);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => {
      expect(mockCopy).toHaveBeenCalledWith('octocat', '用户名');
    });
    expect(mockReveal).not.toHaveBeenCalled();
  });

  it('arrow keys move the active row and ⌘O opens it in the main window', async () => {
    setup();
    mockOpenCred.mockResolvedValue({ success: true, data: true });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(2));

    const panel = screen.getByTestId('quick-access-panel');
    fireEvent.keyDown(panel, { key: 'ArrowDown' });
    expect(screen.getAllByTestId('quick-access-item')[1]).toHaveAttribute('data-active', 'true');

    fireEvent.keyDown(panel, { key: 'o', metaKey: true });
    await waitFor(() => {
      expect(mockOpenCred).toHaveBeenCalledWith('i1', 'c2');
    });
  });

  it('⌘T copies the TOTP code of the active row', async () => {
    setup([credential({})]);
    mockTotp.mockResolvedValue({
      success: true,
      data: { code: '123456', remaining_seconds: 20, period: 30, digits: 6, algorithm: 'SHA1', issuer: 'GitHub', account_name: 'octocat' },
    });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 't', ctrlKey: true });

    await waitFor(() => {
      expect(mockCopy).toHaveBeenCalledWith('123456', 'TOTP 验证码');
    });
  });

  it('surfaces a failed reveal instead of copying', async () => {
    setup([credential({})]);
    mockReveal.mockResolvedValue({ success: false, error: 'Service is locked' });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => expect(mockReveal).toHaveBeenCalled());
    expect(mockCopy).not.toHaveBeenCalled();
  });

  it('shows the no-results state for a query with no hits', async () => {
    setup([]);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'zzz' } });

    await waitFor(() => {
      expect(screen.getByTestId('quick-access-results')).toHaveTextContent('zzz');
    });
  });
});
