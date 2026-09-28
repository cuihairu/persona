import { act, fireEvent, render, screen } from '@testing-library/react';
import Sidebar from './Sidebar';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import type { Credential } from '@/types';

jest.mock('@/components/IdentitySwitcher', () => ({
  __esModule: true,
  IdentitySwitcher: (props: { onCreateIdentity: () => void }) => (
    <div data-testid="identity-switcher" onClick={props.onCreateIdentity} />
  ),
}));

// 返回类型注解让 tsc 守住 fixture 与 Credential 的形状一致；
// 可选字段（url/username/notes/last_accessed）缺省即可，无需显式 null
const makeCred = (over: Record<string, any> = {}): Credential => ({
  id: 'c1',
  identity_id: 'i1',
  name: 'Example',
  credential_type: 'Password',
  security_level: 'High',
  tags: [] as string[],
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  last_accessed: '2023-01-01T00:00:00Z',
  is_active: true,
  is_favorite: false,
  ...over,
});

const makeIdentity = (over: Record<string, any> = {}) => ({
  id: 'i1',
  name: 'Example',
  identity_type: 'Personal',
  description: undefined,
  email: undefined,
  phone: undefined,
  tags: [] as string[],
  attributes: {},
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  is_active: true,
  travel_marked: false,
  ...over,
});

const ALL_FLAGS_ON = { ssh_agent: true, wallet: true, passkeys: true, fetch_favicons: true };

type SidebarProps = Parameters<typeof Sidebar>[0];

const renderSidebar = (overrides: Partial<SidebarProps> = {}) => {
  const props: SidebarProps = {
    onNavigate: jest.fn(),
    onOpenSettings: jest.fn(),
    onLock: jest.fn(),
    ...overrides,
  };
  render(<Sidebar {...props} />);
  return props;
};

describe('components/Sidebar', () => {
  beforeEach(() => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      credentials: [],
      identities: [],
      sidebarFilter: { kind: 'all' },
      credentialSearchQuery: '',
    });
  });

  it('renders search bar at top', () => {
    renderSidebar();

    expect(screen.getByPlaceholderText('搜索条目…')).toBeInTheDocument();
  });

  it('renders category navigation items (all, favorites, recent)', () => {
    renderSidebar();

    expect(screen.getByRole('button', { name: '全部条目' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '收藏' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '最近使用' })).toBeInTheDocument();
  });

  it('renders category navigation items for credential categories', () => {
    renderSidebar();

    expect(screen.getByRole('button', { name: '密码' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '安全备忘录' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'API 密钥' })).toBeInTheDocument();
  });

  it('shows gated category items once their flags are on', () => {
    useAppStore.setState({ featureFlags: ALL_FLAGS_ON });
    renderSidebar();

    expect(screen.getByRole('button', { name: '通行密钥' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'SSH 密钥' })).toBeInTheDocument();
  });

  it('renders special views section (Tools) when flags are on', () => {
    useAppStore.setState({ featureFlags: ALL_FLAGS_ON });
    renderSidebar();

    expect(screen.getByRole('button', { name: '统计' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '钱包' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '安全瞭望' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '生成器' })).toBeInTheDocument();
  });

  it('marks the active category and reports navigation clicks', () => {
    const { onNavigate } = renderSidebar();

    // all items should be active by default (sidebarFilter is { kind: 'all' })
    expect(screen.getByTestId('nav-all')).toHaveAttribute('aria-current', 'page');

    fireEvent.click(screen.getByRole('button', { name: '收藏' }));
    expect(onNavigate).toHaveBeenCalledWith({ kind: 'favorites' });
  });

  it('renders identity groups (vaults) when identities exist', () => {
    act(() => {
      useAppStore.setState({
        identities: [
          makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
          makeIdentity({ id: 'i2', name: 'Work', identity_type: 'Work' }),
        ],
        credentials: [
          makeCred({ id: 'c1', identity_id: 'i1' }),
          makeCred({ id: 'c2', identity_id: 'i1' }),
          makeCred({ id: 'c3', identity_id: 'i2' }),
        ],
        currentIdentity: makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
      });
    });

    renderSidebar();

    expect(screen.getByRole('button', { name: 'Personal' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Work' })).toBeInTheDocument();
    expect(screen.getByTestId('nav-identity-i1')).toHaveTextContent('2');
    expect(screen.getByTestId('nav-identity-i2')).toHaveTextContent('1');
  });

  it('clicking identity group navigates to identity filter', () => {
    act(() => {
      useAppStore.setState({
        identities: [
          makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
        ],
        credentials: [makeCred({ id: 'c1', identity_id: 'i1' })],
        currentIdentity: makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
      });
    });
    const { onNavigate } = renderSidebar();

    fireEvent.click(screen.getByRole('button', { name: 'Personal' }));
    expect(onNavigate).toHaveBeenCalledWith({ kind: 'identity', value: 'i1' });
  });

  it('renders tags section when current identity has tags', () => {
    act(() => {
      useAppStore.setState({
        identities: [
          makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
        ],
        credentials: [makeCred({ id: 'c1', identity_id: 'i1', tags: ['dev', 'prod'] })],
        currentIdentity: makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
      });
    });
    renderSidebar();

    expect(screen.getByRole('button', { name: '#dev' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '#prod' })).toBeInTheDocument();
  });

  it('clicking tag navigates to tag filter', () => {
    act(() => {
      useAppStore.setState({
        identities: [
          makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
        ],
        credentials: [makeCred({ id: 'c1', identity_id: 'i1', tags: ['dev'] })],
        currentIdentity: makeIdentity({ id: 'i1', name: 'Personal', identity_type: 'Personal' }),
      });
    });
    const { onNavigate } = renderSidebar();

    fireEvent.click(screen.getByRole('button', { name: '#dev' }));
    expect(onNavigate).toHaveBeenCalledWith({ kind: 'tag', value: 'dev' });
  });

  it('calls settings and lock from the footer', () => {
    const { onOpenSettings, onLock } = renderSidebar();

    const settings = screen.getByRole('button', { name: '设置' });
    fireEvent.click(settings);
    const lock = screen.getByRole('button', { name: '锁定会话' });
    fireEvent.click(lock);
    expect(onOpenSettings).toHaveBeenCalledTimes(1);
    expect(onLock).toHaveBeenCalledTimes(1);

    // 快捷键提示（title 不影响可访问名）
    expect(settings).toHaveAttribute('title', '设置 (⌘,)');
    expect(lock).toHaveAttribute('title', '锁定 (⌘L)');
  });

  it('renders per-node counts for categories', () => {
    act(() => {
      useAppStore.setState({
        credentials: [
          makeCred({ id: '1', credential_type: 'ApiKey', tags: ['dev'], is_favorite: true }),
          makeCred({ id: '2', credential_type: 'ApiKey', tags: ['dev'] }),
          makeCred({ id: '3', credential_type: 'Password' }),
        ],
      });
    });
    renderSidebar();

    expect(screen.getByTestId('nav-all')).toHaveTextContent('3');
    expect(screen.getByTestId('nav-favorites')).toHaveTextContent('1');
    expect(screen.getByTestId('nav-category-passwords')).toHaveTextContent('1');
    expect(screen.getByTestId('nav-category-api_keys')).toHaveTextContent('2');
  });

  it('maps the favorites node to the favorites-only filter', () => {
    renderSidebar();

    fireEvent.click(screen.getByRole('button', { name: '收藏' }));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'favorites' });
  });

  it('maps the category node to the category filter', () => {
    act(() => {
      useAppStore.setState({
        credentials: [makeCred({ id: '1', credential_type: 'ApiKey', tags: ['dev'] })],
      });
    });
    renderSidebar();

    fireEvent.click(screen.getByRole('button', { name: 'API 密钥' }));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'category', value: 'api_keys' });
  });
});