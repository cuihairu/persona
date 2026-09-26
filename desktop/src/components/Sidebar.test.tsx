import { act, fireEvent, render, screen } from '@testing-library/react';
import Sidebar from './Sidebar';
import { useAppStore, DEFAULT_FEATURE_FLAGS, DEFAULT_SIDEBAR_FILTER } from '@/stores/appStore';
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
  is_active: true,
  is_favorite: false,
  ...over,
});

const ALL_FLAGS_ON = { ssh_agent: true, wallet: true, passkeys: true, fetch_favicons: true };

type SidebarProps = Parameters<typeof Sidebar>[0];

const renderSidebar = (overrides: Partial<SidebarProps> = {}) => {
  const props: SidebarProps = {
    currentView: 'credentials',
    onNavigate: jest.fn(),
    onCreateIdentity: jest.fn(),
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
      sidebarFilter: DEFAULT_SIDEBAR_FILTER,
    });
  });

  it('renders always-on nav entries and hides flag-gated ones while flags are off', () => {
    renderSidebar();

    expect(screen.getByRole('button', { name: '凭据' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '统计' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '安全瞭望' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '生成器' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'SSH Agent' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '钱包' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '通行密钥' })).not.toBeInTheDocument();
  });

  it('shows gated nav entries once their flags are on', () => {
    useAppStore.setState({ featureFlags: ALL_FLAGS_ON });
    renderSidebar();

    expect(screen.getByTestId('nav-credentials')).toBeInTheDocument();
    expect(screen.getByTestId('nav-statistics')).toBeInTheDocument();
    expect(screen.getByTestId('nav-sshAgent')).toBeInTheDocument();
    expect(screen.getByTestId('nav-wallets')).toBeInTheDocument();
    expect(screen.getByTestId('nav-watchtower')).toBeInTheDocument();
    expect(screen.getByTestId('nav-passkeys')).toBeInTheDocument();
    expect(screen.getByTestId('nav-generator')).toBeInTheDocument();
  });

  it('marks the active view and reports navigation clicks', () => {
    const { onNavigate } = renderSidebar({ currentView: 'credentials' });

    expect(screen.getByTestId('nav-credentials')).toHaveAttribute('aria-current', 'page');
    expect(screen.getByTestId('nav-statistics')).not.toHaveAttribute('aria-current');

    fireEvent.click(screen.getByRole('button', { name: '统计' }));
    expect(onNavigate).toHaveBeenCalledWith('statistics');
  });

  it('wires the identity switcher create action', () => {
    const { onCreateIdentity } = renderSidebar();

    fireEvent.click(screen.getByTestId('identity-switcher'));
    expect(onCreateIdentity).toHaveBeenCalledTimes(1);
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

  it('renders all/favorites nodes always and type/tag groups only when present', () => {
    renderSidebar();

    expect(screen.getByTestId('filter-all')).toBeInTheDocument();
    expect(screen.getByTestId('filter-favorites')).toBeInTheDocument();
    expect(screen.queryByTestId('filter-type-ApiKey')).not.toBeInTheDocument();
    expect(screen.queryByTestId('filter-tag-dev')).not.toBeInTheDocument();

    act(() => {
      useAppStore.setState({
        credentials: [makeCred({ id: '1', credential_type: 'ApiKey', tags: ['dev'] })],
      });
    });
    expect(screen.getByTestId('filter-type-ApiKey')).toBeInTheDocument();
    expect(screen.getByTestId('filter-tag-dev')).toBeInTheDocument();
  });

  it('selecting a tree node replaces the store filter (single-select)', () => {
    useAppStore.setState({
      credentials: [makeCred({ id: '1', credential_type: 'ApiKey', tags: ['dev'] })],
    });
    renderSidebar();

    fireEvent.click(screen.getByTestId('filter-type-ApiKey'));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'type', value: 'ApiKey' });

    fireEvent.click(screen.getByTestId('filter-tag-dev'));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'tag', value: 'dev' });

    fireEvent.click(screen.getByTestId('filter-all'));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
  });

  it('maps the favorites node to the favorites-only filter', () => {
    renderSidebar();

    fireEvent.click(screen.getByTestId('filter-favorites'));
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'favorites' });
  });

  it('renders per-node counts', () => {
    useAppStore.setState({
      credentials: [
        makeCred({ id: '1', credential_type: 'ApiKey', tags: ['dev'], is_favorite: true }),
        makeCred({ id: '2', credential_type: 'ApiKey', tags: ['dev'] }),
        makeCred({ id: '3', credential_type: 'Password' }),
      ],
    });
    renderSidebar();

    expect(screen.getByTestId('filter-all')).toHaveTextContent('3');
    expect(screen.getByTestId('filter-favorites')).toHaveTextContent('1');
    expect(screen.getByTestId('filter-type-ApiKey')).toHaveTextContent('2');
    expect(screen.getByTestId('filter-type-Password')).toHaveTextContent('1');
    expect(screen.getByTestId('filter-tag-dev')).toHaveTextContent('2');
  });

  it('hides the tree outside the credentials view', () => {
    renderSidebar({ currentView: 'wallets' });

    expect(screen.queryByTestId('sidebar-filters')).not.toBeInTheDocument();
  });
});
