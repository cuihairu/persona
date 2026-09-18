import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialList, { filterCredentials } from './CredentialList';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import { copyWithAutoClear } from '@/utils/clipboard';
import toast from 'react-hot-toast';
import type { SidebarFilter } from '@/types';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
}));

// 面板（CredentialDetailPane）经 transitive 生效：哑渲染避免拖入真实 reveal 链路
jest.mock('@/components/RevealSecretButton', () => ({
  __esModule: true,
  default: ({ field, label }: any) => (
    <button data-testid={`reveal-${field}`}>{label}</button>
  ),
}));

const makeCred = (over: Record<string, any> = {}) => ({
  id: 'c1',
  identity_id: 'i1',
  name: 'Example',
  credential_type: 'Password',
  security_level: 'High',
  url: null,
  username: null,
  notes: null,
  tags: [] as string[],
  last_accessed: null,
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
    ...serviceOver,
  };
  (usePersonaService as jest.Mock).mockReturnValue(service);
  render(<CredentialList onCreateCredential={() => {}} />);
  return service;
};

/** 点击紧挨着给定文本右侧的复制按钮（span 与按钮同处一个 flex 容器） */
const clickCopyNextTo = (text: string) => {
  const btn = screen.getByText(text).parentElement!.querySelector('button');
  fireEvent.click(btn!);
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
    (copyWithAutoClear as jest.Mock).mockResolvedValue(true);
    // 真 store 单例跨用例存活：树筛选复位为"全部条目"
    useAppStore.setState({ sidebarFilter: { kind: 'all' } });
  });

  it('renders placeholder when no identity selected', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: null,
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={() => {}} />);
    expect(screen.getByText('Select an identity to view credentials')).toBeInTheDocument();
  });

  it('shows empty state and calls onCreateCredential', () => {
    const onCreateCredential = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={onCreateCredential} />);
    fireEvent.click(screen.getByText('Add Your First Credential'));
    expect(onCreateCredential).toHaveBeenCalledTimes(1);
  });

  it('filters by search query and shows the no-results hint', () => {
    setupList([
      makeCred({ id: '1', name: 'Bank one', credential_type: 'Password' }),
      makeCred({ id: '2', name: 'Keytwo', credential_type: 'ApiKey' }),
    ]);

    // 命中类型名（大小写不敏感）
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: 'api' },
    });
    expect(screen.getByText('1 credential')).toBeInTheDocument();
    expect(screen.getByText('Keytwo')).toBeInTheDocument();
    expect(screen.queryByText('Bank one')).not.toBeInTheDocument();

    // 无结果：提示调整搜索词，且不渲染首建按钮
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: 'zzz' },
    });
    expect(screen.getByText('No credentials found')).toBeInTheDocument();
    expect(screen.getByText('Try adjusting your search terms')).toBeInTheDocument();
    expect(screen.queryByText('Add Your First Credential')).not.toBeInTheDocument();
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

    // 仅收藏
    setFilter({ kind: 'favorites' });
    expect(screen.getByText('1 credential')).toBeInTheDocument();
    expect(screen.getByText('Fav-one')).toBeInTheDocument();

    // 单选：切类型即替换收藏筛选
    setFilter({ kind: 'type', value: 'ApiKey' });
    expect(screen.getByText('1 credential')).toBeInTheDocument();
    expect(screen.getByText('Dev-two')).toBeInTheDocument();
    expect(screen.queryByText('Fav-one')).not.toBeInTheDocument();

    // 切标签同样替换（不再叠加）
    setFilter({ kind: 'tag', value: 'dev' });
    expect(screen.getByText('Dev-two')).toBeInTheDocument();

    // 搜索词与树筛选 AND
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: 'zzz' },
    });
    expect(screen.getByText('No credentials found')).toBeInTheDocument();

    // 回全部条目并清搜索
    setFilter({ kind: 'all' });
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: '' },
    });
    expect(screen.getByText('2 credentials')).toBeInTheDocument();
  });

  it('shows the generic empty hint when a tree filter matches nothing', () => {
    setupList([makeCred({ id: '1', name: 'Bank one', credential_type: 'Password' })]);

    act(() => {
      useAppStore.setState({ sidebarFilter: { kind: 'type', value: 'Nope' } });
    });

    expect(screen.getByText('No credentials found')).toBeInTheDocument();
    expect(screen.getByText('Try a different category in the sidebar')).toBeInTheDocument();
    expect(screen.queryByText('Add Your First Credential')).not.toBeInTheDocument();
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

  it('shows the placeholder panel when nothing is selected', () => {
    setupList([makeCred()]);
    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
    expect(screen.getByText('Select an item to see details')).toBeInTheDocument();
    expect(screen.queryByTestId('detail-pane')).not.toBeInTheDocument();
  });

  it('selecting a row opens the pane and highlights it', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    setupList(
      [makeCred({ id: 'c1', name: 'One' }), makeCred({ id: 'c2', name: 'Two' })],
      { getCredentialData },
    );

    fireEvent.click(screen.getByText('One'));
    await screen.findByTitle('Close');
    expect(getCredentialData).toHaveBeenCalledWith('c1');
    expect(screen.getByTestId('detail-pane')).toBeInTheDocument();
    expect(screen.getByTestId('credential-row-c1').className).toContain('bg-primary-50');
    expect(screen.getByTestId('credential-row-c2').className).not.toContain('bg-primary-50');
  });

  it('activates row selection with the keyboard, but not from the inline copy button', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    setupList([makeCred({ username: 'alice' })], { getCredentialData });

    // 行上按 Enter：选中
    fireEvent.keyDown(screen.getByTestId('credential-row-c1'), { key: 'Enter' });
    await screen.findByTitle('Close');
    expect(getCredentialData).toHaveBeenCalledWith('c1');

    // 焦点在行内复制按钮上时，Enter 不触发选中（先清掉再验证）
    fireEvent.click(screen.getByTitle('Close'));
    fireEvent.keyDown(screen.getAllByTitle('Copy username')[0], { key: 'Enter' });
    expect(getCredentialData).toHaveBeenCalledTimes(1);
  });

  it('inline copy copies the username without selecting the row', async () => {
    setupList([
      makeCred({ id: 'c1', name: 'One', username: 'alice' }),
      makeCred({ id: 'c2', name: 'Two', username: 'bob' }),
    ]);

    fireEvent.click(screen.getAllByTitle('Copy username')[1]);
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('Username copied (clears in 30s)');
    // stopPropagation 生效：未触发选中
    expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
    expect(screen.queryByTestId('detail-pane')).not.toBeInTheDocument();
  });

  it('switching selection updates the pane', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    setupList(
      [makeCred({ id: 'c1', name: 'One' }), makeCred({ id: 'c2', name: 'Two' })],
      { getCredentialData },
    );

    fireEvent.click(screen.getByText('One'));
    await screen.findByTitle('Close');
    fireEvent.click(screen.getByText('Two'));
    await screen.findByText('Two', { selector: 'h2' });
    expect(getCredentialData).toHaveBeenCalledTimes(2);
    expect(getCredentialData).toHaveBeenNthCalledWith(1, 'c1');
    expect(getCredentialData).toHaveBeenNthCalledWith(2, 'c2');
  });

  it('closing the pane clears the selection', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    setupList([makeCred()], { getCredentialData });

    fireEvent.click(screen.getByText('Example'));
    await screen.findByTitle('Close');
    fireEvent.click(screen.getByTitle('Close'));
    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
    expect(screen.queryByTestId('detail-pane')).not.toBeInTheDocument();
  });

  it('surfaces the error toast when copying fails', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    setupList([makeCred({ username: 'bob' })], { getCredentialData });

    fireEvent.click(screen.getByText('Example'));
    await screen.findByTitle('Close');

    (copyWithAutoClear as jest.Mock).mockResolvedValueOnce(false);
    clickCopyNextTo('bob');
    await act(async () => {});
    expect(toast.error).toHaveBeenCalledWith('Failed to copy to clipboard');
  });

  it('shows a loading state while credential data is in flight', async () => {
    let resolveData: (v: any) => void = () => {};
    const getCredentialData = jest.fn(
      () => new Promise((resolve) => { resolveData = resolve; }),
    );
    setupList([makeCred()], { getCredentialData });

    fireEvent.click(screen.getByText('Example'));
    expect(await screen.findByTestId('detail-loading')).toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();

    await act(async () => {
      resolveData({ credential_type: 'Password', data: { email: 'a@b.com' } });
    });
    expect(screen.getByText('a@b.com')).toBeInTheDocument();
    expect(screen.queryByTestId('detail-loading')).not.toBeInTheDocument();
  });

  it('deleting the selected credential clears the pane', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: {},
    });
    const deleteCredential = jest.fn().mockResolvedValue(true);
    setupList([makeCred()], { getCredentialData, deleteCredential });

    fireEvent.click(screen.getByText('Example'));
    await screen.findByTitle('Close');
    fireEvent.click(screen.getByTitle('Delete'));
    await act(async () => {});
    expect(deleteCredential).toHaveBeenCalledWith('c1');
    // 列表数组是静态 mock：只断言面板回占位，不断言行消失
    expect(screen.getByTestId('detail-placeholder')).toBeInTheDocument();
    confirmSpy.mockRestore();
  });
});
