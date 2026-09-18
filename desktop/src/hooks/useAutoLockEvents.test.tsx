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

/** 捕获已注册的事件 handler（listen 是异步 resolve 的）。 */
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
      error: null,
    });
  });

  it('does not subscribe when disabled and resets pending seconds', () => {
    const { result, rerender } = renderHook(({ enabled }) => useAutoLockEvents(enabled), {
      initialProps: { enabled: false },
    });

    expect(mockListen).not.toHaveBeenCalled();
    expect(result.current.pendingSeconds).toBeNull();

    // 解锁后挂监听；再落锁（disabled）时清空倒计时
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
    // 与手动 lockService 清理对齐：favicon、选中、待注入跳转一并作废
    expect(state.faviconCache).toEqual({});
    expect(state.faviconMisses).toEqual({});
    expect(state.selectedCredentialId).toBeNull();
    expect(state.pendingCredentialSelection).toBeNull();
  });

  it('unsubscribes on unmount and cancels a pending subscription', async () => {
    // 常规卸载 → unlisten
    const { unmount } = renderHook(() => useAutoLockEvents(true));
    await registeredHandler();
    unmount();
    expect(unlisten).toHaveBeenCalledTimes(1);

    // listen 尚未 resolve 时就卸载 → disposed 竞态：resolve 后立即退订
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

    // 30s 内的第二次活动被节流
    clock += 10_000;
    act(() => {
      fireEvent(window, new Event('keydown'));
    });
    expect(mockInvoke).toHaveBeenCalledTimes(1);

    // 超过节流窗口后再次回传
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
    // 拒绝被 .catch 吞掉，不产生 unhandled rejection
    await Promise.resolve();
    await Promise.resolve();

    expect(mockInvoke).toHaveBeenCalledWith('touch_activity');
    consoleSpy.mockRestore();
  });
});
