import { useAppStore, DEFAULT_FEATURE_FLAGS } from './appStore';
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
    const incoming = { ssh_agent: true, wallet: false, passkeys: true };
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
});
