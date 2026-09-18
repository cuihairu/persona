import { useAppStore, DEFAULT_FEATURE_FLAGS, DEFAULT_SIDEBAR_FILTER } from './appStore';
import { THEME_STORAGE_KEY } from '@/utils/theme';

describe('stores/appStore', () => {
  beforeEach(() => {
    localStorage.removeItem(THEME_STORAGE_KEY); // jsdom localStorage 跨用例存活
    useAppStore.setState({
      isUnlocked: false,
      isInitialized: false,
      identities: [],
      currentIdentity: null,
      credentials: [],
      sshAgentStatus: null,
      sshKeys: [],
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      isLoading: false,
      error: null,
      theme: 'system',
      sidebarFilter: DEFAULT_SIDEBAR_FILTER,
      pendingCredentialSelection: null,
      selectedCredentialId: null,
      faviconCache: {},
      faviconMisses: {},
    });
  });

  it('has expected initial state', () => {
    const state = useAppStore.getState();
    expect(state.isUnlocked).toBe(false);
    expect(state.identities).toEqual([]);
    expect(state.currentIdentity).toBeNull();
    expect(state.error).toBeNull();
  });

  it('starts with every advanced feature flag off', () => {
    expect(DEFAULT_FEATURE_FLAGS).toEqual({
      ssh_agent: false,
      wallet: false,
      passkeys: false,
      fetch_favicons: false,
    });
    expect(useAppStore.getState().featureFlags).toEqual(DEFAULT_FEATURE_FLAGS);
  });

  it('updates state via actions', () => {
    const state = useAppStore.getState();
    state.setUnlocked(true);
    state.setInitialized(true);
    state.setLoading(true);
    state.setError('boom');

    const updated = useAppStore.getState();
    expect(updated.isUnlocked).toBe(true);
    expect(updated.isInitialized).toBe(true);
    expect(updated.isLoading).toBe(true);
    expect(updated.error).toBe('boom');

    updated.clearError();
    expect(useAppStore.getState().error).toBeNull();
  });

  it('setFeatureFlags copies the incoming flags instead of aliasing them', () => {
    const incoming = { ssh_agent: true, wallet: false, passkeys: true, fetch_favicons: false };
    useAppStore.getState().setFeatureFlags(incoming);

    const stored = useAppStore.getState().featureFlags;
    expect(stored).toEqual(incoming);
    expect(stored).not.toBe(incoming);

    // 后续改动入参不影响 store（optimistic 更新回滚路径依赖这一点）
    incoming.wallet = true;
    expect(useAppStore.getState().featureFlags.wallet).toBe(false);
  });

  it('initializes theme from localStorage when the store module loads', async () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    // store 是模块单例：isolateModules 重载后重新走 create() 的初始化分支
    let isolated!: typeof import('./appStore');
    await jest.isolateModulesAsync(async () => {
      isolated = await import('./appStore');
    });
    expect(isolated.useAppStore.getState().theme).toBe('dark');
  });

  it('setTheme updates only the theme field', () => {
    useAppStore.getState().setUnlocked(true);
    useAppStore.getState().setTheme('dark');

    const state = useAppStore.getState();
    expect(state.theme).toBe('dark');
    expect(state.isUnlocked).toBe(true);
    expect(state.error).toBeNull();
  });

  it('sidebarFilter defaults to all and set/resetSidebarFilter replace it', () => {
    expect(DEFAULT_SIDEBAR_FILTER).toEqual({ kind: 'all' });
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });

    useAppStore.getState().setSidebarFilter({ kind: 'tag', value: 'dev' });
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'tag', value: 'dev' });

    useAppStore.getState().resetSidebarFilter();
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
  });

  it('pendingCredentialSelection defaults to null and set/clear replace it', () => {
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();

    useAppStore.getState().setPendingCredentialSelection({ identityId: 'i2', credentialId: 'c9' });
    expect(useAppStore.getState().pendingCredentialSelection).toEqual({
      identityId: 'i2',
      credentialId: 'c9',
    });

    useAppStore.getState().clearPendingCredentialSelection();
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('selectedCredentialId defaults to null and setSelectedCredentialId replaces it', () => {
    expect(useAppStore.getState().selectedCredentialId).toBeNull();

    useAppStore.getState().setSelectedCredentialId('c1');
    expect(useAppStore.getState().selectedCredentialId).toBe('c1');

    // 锁屏清空走同一 action（null 即清）
    useAppStore.getState().setSelectedCredentialId(null);
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
  });

  it('setFaviconEntries merges into cache and clears hits from misses', () => {
    // 预置一个陈旧 miss（曾被批量读判为未命中）
    useAppStore.getState().setFaviconMisses(['a.com', 'b.com']);
    expect(useAppStore.getState().faviconMisses).toEqual({ 'a.com': true, 'b.com': true });

    useAppStore
      .getState()
      .setFaviconEntries([{ host: 'a.com', mime_type: 'image/png', data: 'AAA' }]);

    const state = useAppStore.getState();
    expect(state.faviconCache['a.com']).toEqual({ mime_type: 'image/png', data: 'AAA' });
    expect(state.faviconMisses).toEqual({ 'b.com': true });
  });

  it('setFaviconMisses skips hosts that already have cached entries', () => {
    useAppStore
      .getState()
      .setFaviconEntries([{ host: 'cached.com', mime_type: 'image/png', data: 'BBB' }]);

    useAppStore.getState().setFaviconMisses(['cached.com', 'missing.com']);

    const state = useAppStore.getState();
    // 缓存赢过陈旧 miss：不落负缓存，避免已抓取图标被覆盖判定
    expect(state.faviconMisses).toEqual({ 'missing.com': true });
    expect(state.faviconCache['cached.com']).toBeDefined();
  });

  it('clearFaviconCache resets both cache and misses (lock screen path)', () => {
    useAppStore
      .getState()
      .setFaviconEntries([{ host: 'a.com', mime_type: 'image/png', data: 'AAA' }]);
    useAppStore.getState().setFaviconMisses(['b.com']);

    useAppStore.getState().clearFaviconCache();

    expect(useAppStore.getState().faviconCache).toEqual({});
    expect(useAppStore.getState().faviconMisses).toEqual({});
  });
});
