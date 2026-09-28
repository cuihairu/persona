import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialList, { filterCredentials } from './CredentialList';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import toast from 'react-hot-toast';
import type { Credential, SidebarFilter } from '@/types';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const mockTauriWriteText = jest.fn();
const mockTauriReadText = jest.fn();

jest.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: (...args: any[]) => mockTauriWriteText(...args),
  readText: (...args: any[]) => mockTauriReadText(...args),
}));

jest.mock('@/utils/clipboard', () => ({
  __esModule: true,
  // 保留真实 copyToClipboardWithToast（行内复制与全局 ⌘E 共用，toast 文案
  // 断言才有意义）；其写入链路走上面 mock 的 tauri 插件。
  // 注意：不能在这里覆盖 copyWithAutoClear——真实函数引用的是模块内部
  // 绑定，mock 导出拦不到。
  ...jest.requireActual('@/utils/clipboard'),
}));

// 面板（CredentialDetailPane）经 transitive 生效：哑渲染避免拖入真实 reveal 链路
jest.mock('@/components/RevealSecretButton', () => ({
  __esModule: true,
  default: ({ field, label }: any) => (
    <button data-testid={`reveal-${field}`}>{label}</button>
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

const setupList = (credentials: any[], serviceOver: Record<string, any> = {}) => {
  const service = {
    credentials,
    currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
    getCredentialData: jest.fn(),
    toggleCredentialFavorite: jest.fn(),
    deleteCredential: jest.fn(),
    getTotpCode: jest.fn(),
    getCredentialHistory: jest.fn().mockResolvedValue([]),
    // 挂载期拉取不产生 setState（悬挂 promise），与 DetailPane 专测各自覆盖附件流
    listAttachments: jest.fn(() => new Promise(() => {})),
    attachFileToCredential: jest.fn(),
    saveAttachmentToFile: jest.fn().mockResolvedValue(true),
    deleteAttachment: jest.fn().mockResolvedValue(true),
    ...serviceOver,
  };
  (usePersonaService as jest.Mock).mockReturnValue(service);
  render(<CredentialList onCreateCredential={() => {}} />);
  return service;
};

describe('filterCredentials (pure)', () => {
  const creds = [
    makeCred({ id: '1', name: 'GitHub Login', credential_type: 'Password', tags: ['work'], is_favorite: true }),
    makeCred({ id: '2', name: 'Stripe Key', credential_type: 'ApiKey', tags: ['dev'] }),
  ];

  it('filters by query across name and type, case-insensitively', () => {
    expect(filterCredentials(creds, { query: 'git' }).map((c) => c.id)).toEqual(['1']);
    expect(filterCredentials(creds, { query: 'APIKEY' }).map((c) => c.id)).toEqual(['2']);
    expect(filterCredentials(creds, { query: 'nope' })).toEqual([]);
    expect(filterCredentials(creds, {})).toHaveLength(2);
  });

  it('combines type, tag and favorites dimensions with AND', () => {
    expect(filterCredentials(creds, { types: new Set(['Password']) }).map((c) => c.id)).toEqual(['1']);
    expect(filterCredentials(creds, { tags: new Set(['dev']) }).map((c) => c.id)).toEqual(['2']);
    expect(filterCredentials(creds, { favoritesOnly: true }).map((c) => c.id)).toEqual(['1']);
    // 命中 query + type 才保留
    expect(filterCredentials(creds, { query: 'git', types: new Set(['ApiKey']) })).toEqual([]);
    // 空集合 = 不过滤
    expect(filterCredentials(creds, { types: new Set(), tags: new Set() })).toHaveLength(2);
  });
});

describe('components/CredentialList', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // 真实 copyToClipboardWithToast 的写入主路（tauri 插件）默认成功
    mockTauriWriteText.mockReset().mockResolvedValue(undefined);
    mockTauriReadText.mockReset();
    // 真 store 单例跨用例存活：树筛选复位为"全部条目"，清掉残留的待注入选中
    useAppStore.setState({
      sidebarFilter: { kind: 'all' },
      pendingCredentialSelection: null,
      selectedCredentialId: null,
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      faviconCache: {},
      faviconMisses: {},
    });
  });

  it('renders placeholder when no identity selected', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: null,
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={() => {}} />);
    expect(screen.getByText('选择一个身份以查看凭据')).toBeInTheDocument();
  });

  it('shows empty state and calls onCreateCredential', () => {
    const onCreateCredential = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={onCreateCredential} />);
    fireEvent.click(screen.getByText('添加第一个凭据'));
    expect(onCreateCredential).toHaveBeenCalledTimes(1);
  });

  it('filters by search query and shows the no-results hint', () => {
    setupList([
      makeCred({ id: '1', name: 'Bank one', credential_type: 'Password' }),
      makeCred({ id: '2', name: 'Keytwo', credential_type: 'ApiKey' }),
    ]);

    const setQuery = (q: string) =>
      act(() => {
        useAppStore.setState({ credentialSearchQuery: q });
      });

    // 命中类型名（大小写不敏感）；搜索词在侧栏大搜索框，store 同字段直驱
    setQuery('api');
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Keytwo')).toBeInTheDocument();
    expect(screen.queryByText('Bank one')).not.toBeInTheDocument();

    // 无结果：提示调整搜索词，且不渲染首建按钮
    setQuery('zzz');
    expect(screen.getByText('未找到凭据')).toBeInTheDocument();
    expect(screen.getByText('试试调整搜索词')).toBeInTheDocument();
    expect(screen.queryByText('添加第一个凭据')).not.toBeInTheDocument();
  });

  it('applies the sidebar tree filter to the list (single-select)', () => {
    setupList([
      makeCred({ id: '1', name: 'Fav-one', credential_type: 'Password', tags: ['work'], is_favorite: true }),
      makeCred({ id: '2', name: 'Dev-two', credential_type: 'ApiKey', tags: ['dev'] }),
    ]);

    const setFilter = (filter: SidebarFilter) =>
      act(() => {
        useAppStore.setState({ sidebarFilter: filter });
      });

    // 仅收藏；列表头标题随筛选态（filterLabel 单一事实源）
    setFilter({ kind: 'favorites' });
    expect(screen.getByRole('heading', { name: '收藏' })).toBeInTheDocument();
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Fav-one')).toBeInTheDocument();

    // 单选：切分类即替换收藏筛选
    setFilter({ kind: 'category', value: 'api_keys' });
    expect(screen.getByRole('heading', { name: 'API 密钥' })).toBeInTheDocument();
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Dev-two')).toBeInTheDocument();
    expect(screen.queryByText('Fav-one')).not.toBeInTheDocument();

    // 切标签同样替换（不再叠加）
    setFilter({ kind: 'tag', value: 'dev' });
    expect(screen.getByText('Dev-two')).toBeInTheDocument();

    // 搜索词与树筛选 AND
    act(() => {
      useAppStore.setState({ credentialSearchQuery: 'zzz' });
    });
    expect(screen.getByText('未找到凭据')).toBeInTheDocument();

    // 回全部条目并清搜索
    setFilter({ kind: 'all' });
    act(() => {
      useAppStore.setState({ credentialSearchQuery: '' });
    });
    expect(screen.getByRole('heading', { name: '全部条目' })).toBeInTheDocument();
    expect(screen.getByText('2 条凭据')).toBeInTheDocument();
  });

  it('shows the generic empty hint when a tree filter matches nothing', () => {
    setupList([makeCred({ id: '1', name: 'Bank one', credential_type: 'Password' })]);

    act(() => {
      useAppStore.setState({ sidebarFilter: { kind: 'category', value: 'secure_notes' } });
    });

    expect(screen.getByText('未找到凭据')).toBeInTheDocument();
    expect(screen.getByText('试试侧栏的其他分类')).toBeInTheDocument();
    expect(screen.queryByText('添加第一个凭据')).not.toBeInTheDocument();
  });

  it('injects the pending selection once the target credential is present', () => {
    setupList([makeCred({ id: 'c1', name: 'Jumped' })]);

    act(() => {
      useAppStore.setState({
        pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
      });
    });

    // 消费后即清除，避免下次进列表时再次弹选中
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    // 注入同时写入 store 选中 id（详情面板与全局 ⌘E 依赖同一事实源）
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');
  });

  it('keeps the pending selection when it belongs to another identity', () => {
    setupList([makeCred({ id: 'c1', name: 'Jumped' })]);

    act(() => {
      useAppStore.setState({
        pendingCredentialSelection: { identityId: 'other', credentialId: 'c1' },
      });
    });

    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'other',
      credentialId: 'c1',
    });
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
  });

  it('injecting the pending selection clears search and sidebar filter so the target is visible', () => {
    // c1 是 Password；侧栏选中 api_keys 分类 + 搜索词都会把它挡住
    setupList([
      makeCred({ id: 'c1', name: 'JumpTarget' }),
      makeCred({ id: 'c2', name: 'Other', credential_type: 'ApiKey' }),
    ]);
    act(() => {
      useAppStore.setState({
        credentialSearchQuery: 'Other',
        sidebarFilter: { kind: 'category', value: 'api_keys' },
      });
    });
    expect(screen.queryByTestId('credential-row-c1')).not.toBeInTheDocument();

    act(() => {
      useAppStore.setState({
        pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
      });
    });

    // 注入同时清筛选：目标行可见、搜索词已清空、侧栏分类复位
    expect(screen.getByTestId('credential-row-c1')).toBeInTheDocument();
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');
    expect(useAppStore.getState().credentialSearchQuery).toBe('');
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
  });

  it('clears the pending selection when the list belongs to the identity but the target is gone', () => {
    setupList([makeCred({ id: 'c1', name: 'Present' })]);

    act(() => {
      useAppStore.setState({
        pendingCredentialSelection: { identityId: 'i1', credentialId: 'c99' },
      });
    });

    // 目标已删除：pending 作废防残留
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('keeps the pending selection while the credential list still belongs to the previous identity', () => {
    // 换身份后旧列表尚未替换的中间态（首元素身份不匹配）：不能误清 pending
    setupList([makeCred({ id: 'c1', name: 'Stale', identity_id: 'i0' })]);

    act(() => {
      useAppStore.setState({
        pendingCredentialSelection: { identityId: 'i1', credentialId: 'c99' },
      });
    });

    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'i1',
      credentialId: 'c99',
    });
  });

  it('clears the selection when a filter change hides the selected credential', () => {
    setupList([
      makeCred({ id: 'c1', name: 'Picked' }),
      makeCred({ id: 'c2', name: 'Keyed', credential_type: 'ApiKey' }),
    ]);

    fireEvent.click(screen.getByTestId('credential-row-c1'));
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');

    // 侧栏切到 api_keys 分类：c1 不在结果集里 → 选中清空（详情面板随之让位占位）
    act(() => {
      useAppStore.setState({ sidebarFilter: { kind: 'category', value: 'api_keys' } });
    });

    expect(useAppStore.getState().selectedCredentialId).toBeNull();
  });

  it('renders row variants: security colors, hostnames and favorites', () => {
    setupList([
      makeCred({ id: 'c1', name: 'N-Critical', credential_type: 'Password', security_level: 'Critical' }),
      makeCred({ id: 'c2', name: 'N-Medium', credential_type: 'CryptoWallet', security_level: 'Medium', url: 'https://wallet.example.com/x' }),
      makeCred({ id: 'c3', name: 'N-Low', credential_type: 'SshKey', security_level: 'Low' }),
      makeCred({ id: 'c4', name: 'N-Weird', credential_type: 'Certificate', security_level: 'Weird', url: 'not-a-url' }),
      makeCred({ id: 'c5', name: 'N-High', credential_type: 'BankCard', security_level: 'High', is_favorite: true, last_accessed: '2024-05-06T00:00:00Z' }),
    ]);

    // 五档安全色（含未知档走 default 灰）
    expect(document.querySelector('.bg-red-100.text-red-800')).not.toBeNull();
    expect(document.querySelector('.bg-orange-100.text-orange-800')).not.toBeNull();
    expect(document.querySelector('.bg-yellow-100.text-yellow-800')).not.toBeNull();
    expect(document.querySelector('.bg-green-100.text-green-800')).not.toBeNull();
    expect(document.querySelector('.bg-gray-100.text-gray-800')).not.toBeNull();

    // 合法 URL 取 hostname；非法 URL 原样回显（catch 分支）
    expect(screen.getByText('wallet.example.com')).toBeInTheDocument();
    expect(screen.getByText('not-a-url')).toBeInTheDocument();

    // 收藏小红心（Last used 断言已迁到 CredentialDetailPane.test.tsx）
    expect(document.querySelector('svg.text-red-500')).not.toBeNull();
  });

  it('derives the row highlight from the store id (shared with global ⌘E)', () => {
    setupList([makeCred({ id: 'c1', name: 'One' })]);
    expect(screen.getByTestId('credential-row-c1').className).not.toContain('bg-primary-50');

    // 外部（全局快捷键路径）直接写 store id → 行高亮
    act(() => {
      useAppStore.setState({ selectedCredentialId: 'c1' });
    });
    expect(screen.getByTestId('credential-row-c1')).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('credential-row-c1').className).toContain('bg-primary-50');

    // id 清空 → 高亮消失
    act(() => {
      useAppStore.setState({ selectedCredentialId: null });
    });
    expect(screen.getByTestId('credential-row-c1')).not.toHaveAttribute('aria-current');
  });

  it('selecting a row highlights it and records the store id', () => {
    setupList([makeCred({ id: 'c1', name: 'One' }), makeCred({ id: 'c2', name: 'Two' })]);

    fireEvent.click(screen.getByText('One'));
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');
    expect(screen.getByTestId('credential-row-c1').className).toContain('bg-primary-50');
    expect(screen.getByTestId('credential-row-c2').className).not.toContain('bg-primary-50');
  });

  it('activates row selection with the keyboard, but not from the inline copy button', () => {
    setupList([makeCred({ username: 'alice' })]);

    // 行上按 Enter：选中
    fireEvent.keyDown(screen.getByTestId('credential-row-c1'), { key: 'Enter' });
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');

    // 焦点在行内复制按钮上时，Enter 不触发选中切换
    act(() => {
      useAppStore.setState({ selectedCredentialId: null });
    });
    fireEvent.keyDown(screen.getAllByTitle('复制用户名')[0], { key: 'Enter' });
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
  });

  it('inline copy copies the username without selecting the row', async () => {
    setupList([
      makeCred({ id: 'c1', name: 'One', username: 'alice' }),
      makeCred({ id: 'c2', name: 'Two', username: 'bob' }),
    ]);

    fireEvent.click(screen.getAllByTitle('复制用户名')[1]);
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('用户名 已复制（30 秒后自动清除）');
    // stopPropagation 生效：未触发选中
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
  });

  it('switching selection moves the highlight with the store id', () => {
    setupList([makeCred({ id: 'c1', name: 'One' }), makeCred({ id: 'c2', name: 'Two' })]);

    fireEvent.click(screen.getByText('One'));
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');
    fireEvent.click(screen.getByText('Two'));
    expect(useAppStore.getState().selectedCredentialId).toBe('c2');
    expect(screen.getByTestId('credential-row-c2').className).toContain('bg-primary-50');
    expect(screen.getByTestId('credential-row-c1').className).not.toContain('bg-primary-50');
  });

  // 「关闭面板清空选中 / 加载态 / 删除清空面板」是 App 层组合行为（面板挂在
  // App 的详情列），覆盖迁至 App.test.tsx；「复制失败 toast」随真实剪贴板
  // 链路迁至 CredentialDetailPane.test.tsx。

  it('renders cached favicons on rows when the flag is on', () => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
      // 预置缓存 → useFavicons 的批量读无 pending，不发 IPC
      faviconCache: { 'site.com': { mime_type: 'image/png', data: 'AAA' } },
    });
    setupList([
      makeCred({ id: 'c-fav', name: 'Fav Site', url: 'https://site.com/x' }),
      makeCred({ id: 'c-plain', name: 'Plain Site' }),
    ]);

    const img = screen.getByTestId('favicon-img');
    expect(img).toHaveAttribute('src', 'data:image/png;base64,AAA');
  });
});
