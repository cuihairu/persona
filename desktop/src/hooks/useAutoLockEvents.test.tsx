import { act, renderHook } from '@testing-library/react';
import { fireEvent } from '@testing-library/react';
import { useAutoLockEvents } from './useAutoLockEvents';
import { useAppStore } from '@/stores/appStore';

type Handler = (event: { payload: any }) => void;

const mockListen = jest.fn<Promise<() => void>, [string, Handler]>();
const mockInvoke = jest.fn();

jest.mock('@tauri-apps/api/event', () => ({
  listen: (...args: any[]) => mockListen(...(args as Parameters<typeof mockListen>)),
}));

jest.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: any[]) => mockInvoke(...args),
}));

/** Captures the registered event handler (listen resolves asynchronously). */
const registeredHandler = async (): Promise<Handler> => {
  await Promise.resolve();
  await Promise.resolve();
  expect(mockListen).toHaveBeenCalledWith('persona://auto-lock', expect.any(Function));
  return mockListen.mock.calls[mockListen.mock.calls.length - 1][1];
};

describe('hooks/useAutoLockEvents', () => {
  const unlisten = jest.fn();

  beforeEach(() => {
    jest.restoreAllMocks();
    mockListen.mockReset().mockResolvedValue(unlisten);
    mockInvoke.mockReset().mockResolvedValue(undefined);
    unlisten.mockReset();
    useAppStore.setState({
      isUnlocked: true,
      identities: [{ id: 'id-1' }] as any,
      currentIdentity: { id: 'id-1' } as any,
      credentials: [{ id: 'c1' }] as any,
      selectedCredentialId: 'c1',
      pendingCredentialSelection: { identityId: 'id-1', credentialId: 'c1' },
      faviconCache: { 'a.com': { mime_type: 'image/png', data: 'AAA' } },
      faviconMisses: { 'b.com': true },
      sidebarFilter: { kind: 'favorites' },
      error: null,
    });
  });

  it('does not subscribe when disabled and resets pending seconds', () => {
    const { result, rerender } = renderHook(({ enabled }) => useAutoLockEvents(enabled), {
      initialProps: { enabled: false },
    });

    expect(mockListen).not.toHaveBeenCalled();
    expect(result.current.pendingSeconds).toBeNull();

    // The listener is attached after unlocking; clearing the countdown when locking again (disabled)
    rerender({ enabled: true });
    expect(mockListen).toHaveBeenCalledTimes(1);
    rerender({ enabled: false });
    expect(result.current.pendingSeconds).toBeNull();
  });

  it('exposes remaining seconds from lock_pending and clears on unlocked/activity', async () => {
    const { result } = renderHook(() => useAutoLockEvents(true));
    const handler = await registeredHandler();

    await act(async () => {
      handler({ payload: { type: 'lock_pending', seconds_remaining: 25 } });
    });
    expect(result.current.pendingSeconds).toBe(25);

    await act(async () => {
      handler({ payload: { type: 'activity' } });
    });
    expect(result.current.pendingSeconds).toBe(25);

    await act(async () => {
      handler({ payload: { type: 'unlocked' } });
    });
    expect(result.current.pendingSeconds).toBeNull();
  });

  it('clears local session state when the backend reports locked', async () => {
    renderHook(() => useAutoLockEvents(true));
    const handler = await registeredHandler();

    await act(async () => {
      handler({ payload: { type: 'lock_pending', seconds_remaining: 3 } });
      handler({ payload: { type: 'locked' } });
    });

    const state = useAppStore.getState();
    expect(state.isUnlocked).toBe(false);
    expect(state.identities).toEqual([]);
    expect(state.currentIdentity).toBeNull();
    expect(state.credentials).toEqual([]);
    // Mirrors manual lockService cleanup: favicon cache, selection, and the pending injection jump are all invalidated
    expect(state.faviconCache).toEqual({});
    expect(state.faviconMisses).toEqual({});
    expect(state.selectedCredentialId).toBeNull();
    expect(state.pendingCredentialSelection).toBeNull();
    // Sidebar category selection is also reset with the lock
    expect(state.sidebarFilter).toEqual({ kind: 'all' });
  });

  it('unsubscribes on unmount and cancels a pending subscription', async () => {
    // A normal unmount -> unlisten
    const { unmount } = renderHook(() => useAutoLockEvents(true));
    await registeredHandler();
    unmount();
    expect(unlisten).toHaveBeenCalledTimes(1);

    // Unmounting before listen has resolved -> disposed race: unsubscribe immediately once it resolves
    mockListen.mockReset().mockResolvedValue(unlisten);
    const slow = renderHook(() => useAutoLockEvents(true));
    slow.unmount();
    await Promise.resolve();
    await Promise.resolve();
    expect(unlisten).toHaveBeenCalledTimes(2);
  });

  it('forwards user activity as touch_activity with a 30s throttle', async () => {
    const now = jest.spyOn(Date, 'now');
    let clock = 1_000_000;
    now.mockImplementation(() => clock);

    renderHook(() => useAutoLockEvents(true));

    act(() => {
      fireEvent(window, new Event('pointerdown'));
    });
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke).toHaveBeenCalledWith('touch_activity');

    // A second activity within 30s is throttled away
    clock += 10_000;
    act(() => {
      fireEvent(window, new Event('keydown'));
    });
    expect(mockInvoke).toHaveBeenCalledTimes(1);

    // Once the throttle window has passed, activity is reported again
    clock += 31_000;
    act(() => {
      fireEvent(window, new Event('keydown'));
    });
    expect(mockInvoke).toHaveBeenCalledTimes(2);

    now.mockRestore();
  });

  it('swallows touch_activity failures (service may be uninitialized)', async () => {
    mockInvoke.mockRejectedValue(new Error('SERVICE_LOCKED'));
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    renderHook(() => useAutoLockEvents(true));

    act(() => {
      fireEvent(window, new Event('pointerdown'));
    });
    // The rejection is swallowed by .catch, producing no unhandled rejection
    await Promise.resolve();
    await Promise.resolve();

    expect(mockInvoke).toHaveBeenCalledWith('touch_activity');
    consoleSpy.mockRestore();
  });
});
