import { useAppStore } from './appStore';

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
});

