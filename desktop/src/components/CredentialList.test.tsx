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
  // Keep the real copyToClipboardWithToast (shared by inline copy and global ⌘E,
  // so toast copy assertions are meaningful); its write path uses the Tauri plugin
  // mock above.
  // Note: do not override copyWithAutoClear here—the real function refers to a
  // module-internal binding, so mocking the export cannot intercept it.
  ...jest.requireActual('@/utils/clipboard'),
}));

// The pane (CredentialDetailPane) takes effect transitively: dummy render avoids pulling in the real reveal chain
jest.mock('@/components/RevealSecretButton', () => ({
  __esModule: true,
  default: ({ field, label }: any) => (
    <button data-testid={`reveal-${field}`}>{label}</button>
  ),
}));

// The return-type annotation lets tsc keep the fixture shape aligned with Credential;
// optional fields (url/username/notes/last_accessed) may be omitted—explicit null is unnecessary
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
    // Mount-time fetch does not produce setState (dangling promise); DetailPane-specific tests cover attachment flows
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
    // Kept only when query + type match
    expect(filterCredentials(creds, { query: 'git', types: new Set(['ApiKey']) })).toEqual([]);
    // Empty sets = no filtering
    expect(filterCredentials(creds, { types: new Set(), tags: new Set() })).toHaveLength(2);
  });
});

describe('components/CredentialList', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // The real copyToClipboardWithToast's primary write path (Tauri plugin) succeeds by default
    mockTauriWriteText.mockReset().mockResolvedValue(undefined);
    mockTauriReadText.mockReset();
    // The real store singleton survives across cases: reset the tree filter to "All Items" and clear leftover pending selection
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

    // Match the type name case-insensitively; the search term comes from the large sidebar search box and drives the same store field
    setQuery('api');
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Keytwo')).toBeInTheDocument();
    expect(screen.queryByText('Bank one')).not.toBeInTheDocument();

    // No results: prompt adjusting the search term and do not render the first-create button
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

    // Favorites only; the list header title follows filter state (filterLabel is the single source of truth)
    setFilter({ kind: 'favorites' });
    expect(screen.getByRole('heading', { name: '收藏' })).toBeInTheDocument();
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Fav-one')).toBeInTheDocument();

    // Single-select: switching category replaces the favorites filter
    setFilter({ kind: 'category', value: 'api_keys' });
    expect(screen.getByRole('heading', { name: 'API 密钥' })).toBeInTheDocument();
    expect(screen.getByText('1 条凭据')).toBeInTheDocument();
    expect(screen.getByText('Dev-two')).toBeInTheDocument();
    expect(screen.queryByText('Fav-one')).not.toBeInTheDocument();

    // Switching tags likewise replaces rather than stacks
    setFilter({ kind: 'tag', value: 'dev' });
    expect(screen.getByText('Dev-two')).toBeInTheDocument();

    // Search term and tree filter are ANDed
    act(() => {
      useAppStore.setState({ credentialSearchQuery: 'zzz' });
    });
    expect(screen.getByText('未找到凭据')).toBeInTheDocument();

    // Return to all items and clear the search term
    setFilter({ kind: 'all' });
    act(() => {
      useAppStore.setState({ credentialSearchQuery: '' });
    });
    expect(screen.getByRole('heading', { name: '全部条目' })).toBeInTheDocument();
    expect(screen.getByText('2 条凭据')).toBeInTheDocument();
  });

  it('sorts by last_accessed under the recent filter (never-accessed sink, ties by name)', () => {
    setupList([
      makeCred({ id: '1', name: 'Zeta', credential_type: 'Password' }),
      makeCred({ id: '2', name: 'Alpha', credential_type: 'Password', last_accessed: '2026-10-01T00:00:00Z' }),
      makeCred({ id: '3', name: 'Mid', credential_type: 'Password', last_accessed: '2026-10-05T00:00:00Z' }),
      makeCred({ id: '4', name: 'Aard', credential_type: 'Password', last_accessed: '2026-10-01T00:00:00Z' }),
    ]);

    act(() => {
      useAppStore.setState({ sidebarFilter: { kind: 'recent' } });
    });

    // Recently accessed first (newest→oldest), same timestamp by name, never-accessed sinks to the bottom
    const order = screen
      .getAllByTestId(/^credential-row-/)
      .map((el) => el.getAttribute('data-testid'));
    expect(order).toEqual(['credential-row-3', 'credential-row-4', 'credential-row-2', 'credential-row-1']);
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

    // Cleared after consumption, avoiding another selection popup the next time the list is entered
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    // Injection also writes the store selection id (detail pane and global ⌘E rely on the same source of truth)
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
    // c1 is a Password; the sidebar api_keys category + search term both hide it
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

    // Injection also clears filters: target row visible, search term cleared, sidebar category reset
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

    // Target deleted: discard pending to prevent residue
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('keeps the pending selection while the credential list still belongs to the previous identity', () => {
    // Interim state after identity switch where the old list has not yet been replaced (first row identity mismatch): do not accidentally clear pending
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

    // Sidebar switched to the api_keys category: c1 is not in the result set → selection cleared (detail pane yields to its placeholder)
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

    // Five security color bands (unknown level falls back to default gray)
    expect(document.querySelector('.bg-red-100.text-red-800')).not.toBeNull();
    expect(document.querySelector('.bg-orange-100.text-orange-800')).not.toBeNull();
    expect(document.querySelector('.bg-yellow-100.text-yellow-800')).not.toBeNull();
    expect(document.querySelector('.bg-green-100.text-green-800')).not.toBeNull();
    expect(document.querySelector('.bg-gray-100.text-gray-800')).not.toBeNull();

    // A valid URL yields hostname; an invalid URL is echoed verbatim (catch branch)
    expect(screen.getByText('wallet.example.com')).toBeInTheDocument();
    expect(screen.getByText('not-a-url')).toBeInTheDocument();

    // Favorite heart (Last used assertion moved to CredentialDetailPane.test.tsx)
    expect(document.querySelector('svg.text-red-500')).not.toBeNull();
  });

  it('derives the row highlight from the store id (shared with global ⌘E)', () => {
    setupList([makeCred({ id: 'c1', name: 'One' })]);
    expect(screen.getByTestId('credential-row-c1').className).not.toContain('bg-primary-50');

    // An external path (global shortcut) writes the store id directly → row highlight
    act(() => {
      useAppStore.setState({ selectedCredentialId: 'c1' });
    });
    expect(screen.getByTestId('credential-row-c1')).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('credential-row-c1').className).toContain('bg-primary-50');

    // id cleared → highlight removed
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

    // Enter on a row: select
    fireEvent.keyDown(screen.getByTestId('credential-row-c1'), { key: 'Enter' });
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');

    // When focus is on the inline copy button, Enter does not trigger selection switching
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
    // stopPropagation works: selection was not triggered
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

  // "Closing the pane clears selection / loading state / deletion clears the pane" are App-layer composite behaviors (the pane is
  // mounted in App's detail column), so their coverage moved to App.test.tsx; "copy failure toast" moved with the real clipboard
  // chain to CredentialDetailPane.test.tsx.

  it('renders cached favicons on rows when the flag is on', () => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
      // Pre-populate the cache → useFavicons's batch read has no pending request, so no IPC is sent
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
