import { useAppStore, DEFAULT_FEATURE_FLAGS } from './appStore';

describe('stores/appStore', () => {
  beforeEach(() => {
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
});
