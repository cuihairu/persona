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
  travel_marked: false,
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
  travel_marked: false,
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

/** Open the overlay and let the debounced search settle */
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
    expect(screen.getByText('输入以跨所有身份搜索')).toBeInTheDocument();
  });

  it('closes on Escape and resets the query', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred()], 'git');

    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'Escape' });

    expect(screen.queryByTestId('quick-search-overlay')).not.toBeInTheDocument();
    // Reopening should be a clean empty state (both query and results reset)
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    expect(screen.getByTestId('quick-search-input')).toHaveValue('');
    expect(screen.getByText('输入以跨所有身份搜索')).toBeInTheDocument();
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

  it('drops a stale search response that resolves after the query changed', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    // First query: a slow response (resolving it manually)
    let resolveSlow: (v: any[]) => void = () => {};
    const slow = new Promise<any[]>((r) => {
      resolveSlow = r;
    });
    searchCredentials.mockImplementationOnce(() => slow);
    fireEvent.change(screen.getByTestId('quick-search-input'), { target: { value: 'git' } });
    await act(async () => {
      jest.advanceTimersByTime(250);
    });

    // Query changes: the new query returns immediately
    searchCredentials.mockResolvedValueOnce([makeCred({ id: 'new', name: 'NewCred' })]);
    fireEvent.change(screen.getByTestId('quick-search-input'), { target: { value: 'gith' } });
    await act(async () => {
      jest.advanceTimersByTime(250);
    });
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.getByText('NewCred')).toBeInTheDocument();

    // The old query's response arrives late: it must not overwrite the new results (cleanup stale guard)
    await act(async () => {
      resolveSlow([makeCred({ id: 'old', name: 'OldCred' })]);
      await Promise.resolve();
    });
    expect(screen.queryByText('OldCred')).toBeNull();
    expect(screen.getByText('NewCred')).toBeInTheDocument();
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
    // Identity group header, in the order of identities in the store
    expect(screen.getByText('Personal')).toBeInTheDocument();
    expect(screen.getByText('Work')).toBeInTheDocument();
    // Entries inside a group: name + type badge + username (a title containing the
    // query term is split by <mark>, so getByText's exact single-element match cannot
    // find it; assert on the row-level textContent instead)
    const items = screen.getAllByTestId('quick-search-item');
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent('GitHub');
    expect(items[1]).toHaveTextContent('GitHub PAT');
    expect(items[2]).toHaveTextContent('Gitea');
    expect(screen.getByText('alice')).toBeInTheDocument();
  });

  it('shows the no-results hint when nothing matches', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));

    await searchFor(searchCredentials, []);

    expect(screen.getByText('没有找到「git」的结果')).toBeInTheDocument();
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

    // ArrowUp steps back to the first item; one more step wraps from the first to the last
    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'ArrowUp' });
    expect(items()[0].getAttribute('data-active')).toBe('true');
    fireEvent.keyDown(screen.getByTestId('quick-search-input'), { key: 'ArrowUp' });
    expect(items()[1].getAttribute('data-active')).toBe('true');

    // Enter selects the currently highlighted item (same identity: no identity switch)
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

    // Pressing the mouse inside the card (e.g. about to select text) does not close it
    fireEvent.mouseDown(screen.getByTestId('quick-search-input'));
    expect(screen.getByTestId('quick-search-overlay')).toBeInTheDocument();

    // Pressing on the backdrop (the overlay itself) closes it
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

    // Results for unknown identities render no rows at all (filtered out during grouping)
    expect(screen.getByText('没有找到「git」的结果')).toBeInTheDocument();
    expect(screen.queryByTestId('quick-search-item')).not.toBeInTheDocument();
    expect(switchIdentity).not.toHaveBeenCalled();
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('renders cached favicons in results when the flag is on', async () => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
      // Primes the cache, so useFavicons' batched read has nothing pending and sends no IPC
      faviconCache: { 'github.com': { mime_type: 'image/png', data: 'AAA' } },
    });
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [makeCred({ url: 'https://github.com/x' })]);

    const img = screen.getByTestId('favicon-img');
    expect(img).toHaveAttribute('src', 'data:image/png;base64,AAA');
  });

  it('marks query hits in title and username, case-insensitively', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(searchCredentials, [
      makeCred({ name: 'GitHub Login', username: 'git-alice' }),
    ]);

    // Case-insensitive (matching SQLite LIKE's ASCII behavior): the Git / git fragments each hit
    const hits = screen.getAllByTestId('highlight-hit').map((el) => el.textContent);
    expect(hits).toEqual(['Git', 'git']);
  });

  it('renders plain text when fields do not contain the query', async () => {
    const { searchCredentials } = setup();
    fireEvent.click(screen.getByTestId('quick-search-trigger'));
    await searchFor(
      searchCredentials,
      // The hit comes from another backend field (such as url); the title/username do not contain the query term
      [makeCred({ name: 'GitHub', username: null, url: 'https://gitlab.com' })],
      'gitlab',
    );

    expect(screen.getByTestId('quick-search-item')).toHaveTextContent('GitHub');
    expect(screen.queryByTestId('highlight-hit')).not.toBeInTheDocument();
  });
});
