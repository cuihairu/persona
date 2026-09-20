import { act, fireEvent, render, screen } from '@testing-library/react';
import QuickSearch from './QuickSearch';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

const makeIdentity = (id: string, name: string) => ({
  id,
  name,
  identity_type: 'Personal',
  tags: [],
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  is_active: true,
});

const makeCred = (over: Record<string, any> = {}) => ({
  id: 'c1',
  identity_id: 'i1',
  name: 'GitHub',
  credential_type: 'Password',
  security_level: 'High',
  username: 'alice',
  tags: [],
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  is_active: true,
  is_favorite: false,
  ...over,
});

const IDENTITIES = [makeIdentity('i1', 'Personal'), makeIdentity('i2', 'Work')];

const setup = (serviceOver: Record<string, any> = {}) => {
  const searchCredentials = jest.fn().mockResolvedValue([]);
  const switchIdentity = jest.fn();
  (usePersonaService as jest.Mock).mockReturnValue({
    searchCredentials,
    switchIdentity,
    currentIdentity: { id: 'i1', name: 'Personal', identity_type: 'Personal' },
    ...serviceOver,
  });
  render(<QuickSearch />);
  return { searchCredentials, switchIdentity };
};

/** 打开 overlay 并让 debounce 后的搜索落地 */
const searchFor = async (searchCredentials: jest.Mock, results: any[], term = 'git') => {
  searchCredentials.mockResolvedValueOnce(results);
  fireEvent.change(screen.getByTestId('quick-search-input'), { target: { value: term } });
  await act(async () => {
    jest.advanceTimersByTime(250);
  });
};

describe('components/QuickSearch', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    useAppStore.setState({
      identities: IDENTITIES,
      pendingCredentialSelection: null,
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      faviconCache: {},
      faviconMisses: {},
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('renders only the toolbar trigger while closed', () => {
    setup();

    expect(screen.getByTestId('quick-search-trigger')).toBeInTheDocument();
    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
  });

  it('opens the overlay with a focused input from the trigger button', () => {
    setup();

    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    expect(screen.getByTestId('quick-search-overlay')).toBeInTheDocument();
    expect(screen.getByTestId('quick-search-input')).toHaveFocus();
    expect(screen.getByText('Type to search across all identities')).toBeInTheDocument();
  });

  it('closes on Escape and resets the query', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred()], 'git');

    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'Escape' });

    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
    // 重新打开应是干净的空态（查询与结果都复位）
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    expect(screen.getByTestId('quick-search-input')).toHaveValue('');
    expect(screen.getByText('Type to search across all identities')).toBeInTheDocument();
  });

  it('opens via ctrl+K and cmd+K global shortcuts', () => {
    setup();

    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.getByTestId('quick-search-overlay')).toBeInTheDocument();

    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'Escape' });
    fireEvent.keyDown(window, { key: 'K', metaKey: true });
    expect(screen.getByTestId('quick-search-overlay')).toBeInTheDocument();
  });

  it('does not hit the backend while the query is empty', () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    fireEvent.change(screen.getByTestId('quick-search-input'), { target: { value: '   ' } });
    act(() => {
      jest.advanceTimersByTime(400);
    });

    expect(searchCredentials).not.toHaveBeenCalled();
  });

  it('searches debounced and groups results under identity headings', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    await searchFor(searchCredentials, [
      makeCred({ id: 'c1', identity_id: 'i1', name: 'GitHub', credential_type: 'Password', username: 'alice' }),
      makeCred({ id: 'c2', identity_id: 'i2', name: 'Gitea', credential_type: 'ServerConfig', username: 'bob' }),
      makeCred({ id: 'c3', identity_id: 'i1', name: 'GitHub PAT', credential_type: 'ApiKey', username: null }),
    ]);

    expect(searchCredentials).toHaveBeenCalledWith('git');
    // 身份组头，按 store 中的身份顺序
    expect(screen.getByText('Personal')).toBeInTheDocument();
    expect(screen.getByText('Work')).toBeInTheDocument();
    // 组内条目：名称 + 类型徽章 + 用户名
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('GitHub PAT')).toBeInTheDocument();
    expect(screen.getByText('Gitea')).toBeInTheDocument();
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.getAllByTestId('quick-search-item')).toHaveLength(3);
  });

  it('shows the no-results hint when nothing matches', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    await searchFor(searchCredentials, []);

    expect(screen.getByText('No results for "git"')).toBeInTheDocument();
    expect(screen.queryByTestId('quick-search-item')).not.toBeInTheDocument();
  });

  it('selecting a result in the current identity only queues the pending selection', async () => {
    const { searchCredentials, switchIdentity } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred({ id: 'c1', identity_id: 'i1' })]);

    fireEvent.click(screen.getByTestId('quick-search-item'));

    expect(switchIdentity).not.toHaveBeenCalled();
    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'i1',
      credentialId: 'c1',
    });
    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
  });

  it('selecting a result from another identity switches identity first', async () => {
    const { searchCredentials, switchIdentity } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [
      makeCred({ id: 'c9', identity_id: 'i2', name: 'Gitea' }),
    ]);

    fireEvent.click(screen.getByTestId('quick-search-item'));

    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'i2',
      credentialId: 'c9',
    });
    expect(switchIdentity).toHaveBeenCalledWith(IDENTITIES[1], { silent: true });
    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
  });

  it('navigates results with arrow keys and opens with Enter', async () => {
    const { searchCredentials, switchIdentity } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [
      makeCred({ id: 'c1', identity_id: 'i1', name: 'One' }),
      makeCred({ id: 'c2', identity_id: 'i1', name: 'Two' }),
    ]);

    const items = () => screen.getAllByTestId('quick-search-item');
    expect(items()[0].getAttribute('data-active')).toBe('true');

    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'ArrowDown' });
    expect(items()[0].getAttribute('data-active')).toBe('false');
    expect(items()[1].getAttribute('data-active')).toBe('true');

    // ArrowUp 回退到首项，再回一次则从首项回绕到末项
    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'ArrowUp' });
    expect(items()[0].getAttribute('data-active')).toBe('true');
    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'ArrowUp' });
    expect(items()[1].getAttribute('data-active')).toBe('true');

    // Enter 选中当前高亮项（同身份：不切身份）
    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'Enter' });
    expect(switchIdentity).not.toHaveBeenCalled();
    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'i1',
      credentialId: 'c2',
    });
  });

  it('closes on backdrop mousedown but not on card mousedown', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred({ id: 'c1' })]);

    // 卡片内按下鼠标（比如准备选中文字）不关闭
    fireEvent.mouseDown(screen.getByTestId('quick-search-input'));
    expect(screen.getByTestId('quick-search-overlay')).toBeInTheDocument();

    // 遮罩（overlay 自身）按下即关闭
    fireEvent.mouseDown(screen.getByTestId('quick-search-overlay'));
    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
  });

  it('moves the highlight on mouse enter', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [
      makeCred({ id: 'c1', identity_id: 'i1', name: 'One' }),
      makeCred({ id: 'c2', identity_id: 'i1', name: 'Two' }),
    ]);

    const items = () => screen.getAllByTestId('quick-search-item');
    fireEvent.mouseEnter(items()[1]);
    expect(items()[0].getAttribute('data-active')).toBe('false');
    expect(items()[1].getAttribute('data-active')).toBe('true');
  });

  it('drops results whose identity no longer exists from the grouping', async () => {
    const { searchCredentials, switchIdentity } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [
      makeCred({ id: 'c9', identity_id: 'ghost', name: 'Orphan' }),
    ]);

    // 未知身份的结果不渲染任何行（分组阶段即被过滤）
    expect(screen.getByText('No results for "git"')).toBeInTheDocument();
    expect(screen.queryByTestId('quick-search-item')).not.toBeInTheDocument();
    expect(switchIdentity).not.toHaveBeenCalled();
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('renders cached favicons in results when the flag is on', async () => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
      // 预置缓存 → useFavicons 的批量读无 pending，不发 IPC
      faviconCache: { 'github.com': { mime_type: 'image/png', data: 'AAA' } },
    });
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred({ url: 'https://github.com/x' })]);

    const img = screen.getByTestId('favicon-img');
    expect(img).toHaveAttribute('src', 'data:image/png;base64,AAA');
  });
});
