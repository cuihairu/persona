import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
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

// hide/listen 用具名 mock：用例要直接驱动事件回调与断言 hide 调用
const mockHide = jest.fn().mockResolvedValue(undefined);
const mockListen = jest.fn().mockResolvedValue(() => {});

jest.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({ hide: () => mockHide() }),
}));

jest.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: (payload?: unknown) => void) => mockListen(event, handler),
}));

jest.mock('@/hooks/usePersonaService');
// useReauth 一并接管：真实 hook 的 requestReauth 只有 ReauthModal 提交/取消才
// resolve，而弹框在本文件被 mock 成 null——不接管 REAUTH 用例会挂死
const mockRequestReauth = jest.fn();
jest.mock('@/hooks/useReauth', () => ({
  useReauth: () => ({
    isOpen: false,
    error: null,
    isVerifying: false,
    requestReauth: mockRequestReauth,
    submit: () => {},
    cancel: () => {},
  }),
}));
jest.mock('@/components/ReauthModal', () => () => null);
jest.mock('@/components/FaviconImg', () => () => null);

const mockService = usePersonaService as jest.Mock;
const mockCopy = jest.requireMock('@/utils/clipboard').copyToClipboardWithToast as jest.Mock;
const mockReveal = personaAPI.revealCredentialSecret as jest.Mock;
const mockTotp = personaAPI.getTotpCode as jest.Mock;
const mockOpenCred = personaAPI.quickAccessOpenCredential as jest.Mock;
const mockFocusMain = personaAPI.focusMainWindow as jest.Mock;

/** 取组件挂载时注册的指定事件回调（mockListen.mock.calls 由 beforeEach 清空） */
const listenerFor = (event: string): (() => void) => {
  const call = mockListen.mock.calls.find(([name]) => name === event);
  if (!call) throw new Error(`listener not registered: ${event}`);
  return call[1] as () => void;
};

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

  it('Escape hides the floating window', () => {
    setup();
    render(<QuickAccessPanel />);

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Escape' });

    expect(mockHide).toHaveBeenCalledTimes(1);
  });

  it('auto-lock event hides the window immediately', async () => {
    setup();
    render(<QuickAccessPanel />);

    act(() => {
      listenerFor('persona://auto-lock')();
    });

    await waitFor(() => expect(mockHide).toHaveBeenCalledTimes(1));
  });

  it('opened event clears the query and re-checks the unlock state', async () => {
    setup();
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(2));

    const check = mockService().checkServiceStatus as jest.Mock;
    act(() => {
      listenerFor('persona://quick-access-opened')();
    });

    expect(screen.getByTestId('quick-access-input')).toHaveValue('');
    expect(check).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('quick-access-item')).not.toBeInTheDocument();
  });

  it('⌘U copies the username of the active row', async () => {
    setup([credential({})]);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'u', metaKey: true });

    await waitFor(() => expect(mockCopy).toHaveBeenCalledWith('octocat', '用户名'));
  });

  it('Enter with neither a secret field nor a username surfaces an error instead of copying', async () => {
    setup([credential({ credential_type: 'SecureNote', username: undefined })]);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    expect(mockReveal).not.toHaveBeenCalled();
    expect(mockCopy).not.toHaveBeenCalled();
  });

  it('⌘T surfaces the TOTP failure instead of copying', async () => {
    setup([credential({})]);
    mockTotp.mockResolvedValue({ success: false, error: '未配置 TOTP' });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 't', ctrlKey: true });

    await waitFor(() => expect(mockTotp).toHaveBeenCalled());
    expect(mockCopy).not.toHaveBeenCalled();
  });

  it('⌘O surfaces the open failure', async () => {
    setup([credential({})]);
    mockOpenCred.mockResolvedValue({ success: false, error: '打开失败' });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'o', metaKey: true });

    await waitFor(() => expect(mockOpenCred).toHaveBeenCalled());
  });

  it('ArrowUp wraps to the last row', async () => {
    setup();
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(2));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'ArrowUp' });

    expect(screen.getAllByTestId('quick-access-item')[1]).toHaveAttribute('data-active', 'true');
  });

  it('hover and click set the active row; double-click copies its primary secret', async () => {
    setup();
    mockReveal.mockResolvedValue({ success: true, data: { field: 'password', value: 's3cret2' } });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(2));

    const items = screen.getAllByTestId('quick-access-item');
    fireEvent.mouseEnter(items[1]);
    expect(items[1]).toHaveAttribute('data-active', 'true');

    fireEvent.click(items[1]);
    fireEvent.doubleClick(items[1]);

    await waitFor(() => expect(mockReveal).toHaveBeenCalledWith('c2', 'password'));
    expect(mockCopy).toHaveBeenCalledWith('s3cret2', '密码');
  });

  it.each([
    ['ApiKey', 'api_key'],
    ['SshKey', 'ssh_private_key'],
    ['CryptoWallet', 'wallet_private_key'],
  ])('Enter copies the %s primary secret field', async (type, field) => {
    setup([credential({ credential_type: type })]);
    mockReveal.mockResolvedValue({ success: true, data: { field, value: 'topsecret' } });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => expect(mockReveal).toHaveBeenCalledWith('c1', field));
    expect(mockCopy).toHaveBeenCalledWith('topsecret', '密码');
  });

  it('REAUTH_REQUIRED re-verifies and retries the reveal', async () => {
    setup([credential({})]);
    mockReveal
      .mockResolvedValueOnce({ success: false, error_code: 'REAUTH_REQUIRED', error: '需要重新验证' })
      .mockResolvedValueOnce({ success: true, data: { field: 'password', value: 's3cret' } });
    mockRequestReauth.mockResolvedValueOnce(true);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => expect(mockReveal).toHaveBeenCalledTimes(2));
    expect(mockRequestReauth).toHaveBeenCalledTimes(1);
    expect(mockCopy).toHaveBeenCalledWith('s3cret', '密码');
  });

  it('declined re-verification leaves the secret unrevealed', async () => {
    setup([credential({})]);
    mockReveal.mockResolvedValue({ success: false, error_code: 'REAUTH_REQUIRED', error: '需要重新验证' });
    mockRequestReauth.mockResolvedValueOnce(false);
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => expect(mockRequestReauth).toHaveBeenCalledTimes(1));
    expect(mockReveal).toHaveBeenCalledTimes(1);
    expect(mockCopy).not.toHaveBeenCalled();
  });

  it('SERVICE_LOCKED surfaces the lock hint instead of copying', async () => {
    setup([credential({})]);
    mockReveal.mockResolvedValue({ success: false, error_code: 'SERVICE_LOCKED', error: '服务已锁定' });
    render(<QuickAccessPanel />);

    fireEvent.change(screen.getByTestId('quick-access-input'), { target: { value: 'git' } });
    await waitFor(() => expect(screen.getAllByTestId('quick-access-item')).toHaveLength(1));

    fireEvent.keyDown(screen.getByTestId('quick-access-panel'), { key: 'Enter' });

    await waitFor(() => expect(mockReveal).toHaveBeenCalled());
    expect(mockCopy).not.toHaveBeenCalled();
  });
});
