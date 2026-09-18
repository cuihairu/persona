import { act } from '@testing-library/react';
import { renderHook } from '@testing-library/react';
import { useTheme } from './useTheme';
import { useAppStore } from '@/stores/appStore';
import { THEME_STORAGE_KEY } from '@/utils/theme';

const mockSetTheme = jest.fn();

jest.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    setTheme: (...args: unknown[]) => mockSetTheme(...args),
  }),
}));

/** 可控的 matchMedia 替身：listeners 集合 + emit 触发 change 事件 */
const installMq = (initial: boolean) => {
  const listeners = new Set<(e: { matches: boolean }) => void>();
  const mq = {
    matches: initial,
    addEventListener: (_: string, cb: (e: { matches: boolean }) => void) => {
      listeners.add(cb);
    },
    removeEventListener: (_: string, cb: (e: { matches: boolean }) => void) => {
      listeners.delete(cb);
    },
  };
  window.matchMedia = (() => mq) as unknown as typeof window.matchMedia;
  return {
    listeners,
    emit: (v: boolean) => {
      mq.matches = v;
      listeners.forEach((l) => l({ matches: v }));
    },
    uninstall: () => {
      delete (window as { matchMedia?: unknown }).matchMedia;
    },
  };
};

describe('hooks/useTheme', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSetTheme.mockReset().mockResolvedValue(undefined);
    localStorage.clear();
    document.documentElement.className = '';
    delete (window as { matchMedia?: unknown }).matchMedia;
    useAppStore.setState({ theme: 'system' });
  });

  it('system + light system: no dark class, persists the preference, native setTheme(null)', () => {
    installMq(false);
    renderHook(() => useTheme());

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('system');
    expect(mockSetTheme).toHaveBeenCalledWith(null);
  });

  it('system + dark system: applies the dark class', () => {
    installMq(true);
    renderHook(() => useTheme());

    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('switching to light removes the class and takes over the native theme', () => {
    installMq(true);
    renderHook(() => useTheme());

    act(() => {
      useAppStore.getState().setTheme('light');
    });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(mockSetTheme).toHaveBeenLastCalledWith('light');
  });

  it('switching to dark applies the class regardless of the system mode', () => {
    installMq(false);
    renderHook(() => useTheme());

    act(() => {
      useAppStore.getState().setTheme('dark');
    });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(mockSetTheme).toHaveBeenLastCalledWith('dark');
  });

  it('does not register a matchMedia listener for explicit light/dark', () => {
    const mq = installMq(false);
    renderHook(() => useTheme());

    act(() => {
      useAppStore.getState().setTheme('dark');
    });
    expect(mq.listeners.size).toBe(0);

    act(() => {
      useAppStore.getState().setTheme('light');
    });
    expect(mq.listeners.size).toBe(0);
    mq.uninstall();
  });

  it('system mode follows live prefers-color-scheme changes', () => {
    const mq = installMq(false);
    renderHook(() => useTheme());

    act(() => mq.emit(true));
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    act(() => mq.emit(false));
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    mq.uninstall();
  });

  it('removes the matchMedia listener on unmount', () => {
    const mq = installMq(false);
    const { unmount } = renderHook(() => useTheme());
    expect(mq.listeners.size).toBe(1);

    unmount();
    expect(mq.listeners.size).toBe(0);
    mq.uninstall();
  });

  it('re-registers the listener after system → dark → system', () => {
    const mq = installMq(false);
    renderHook(() => useTheme());

    act(() => {
      useAppStore.getState().setTheme('dark');
    });
    expect(mq.listeners.size).toBe(0);

    act(() => {
      useAppStore.getState().setTheme('system');
    });
    expect(mq.listeners.size).toBe(1);
    mq.uninstall();
  });

  it('guards a missing matchMedia without crashing', () => {
    // window.matchMedia 保持未定义（jsdom 默认）
    renderHook(() => useTheme());
    act(() => {
      useAppStore.getState().setTheme('dark');
    });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(mockSetTheme).toHaveBeenLastCalledWith('dark');
  });

  it('survives a synchronous native setTheme failure', () => {
    installMq(false);
    mockSetTheme.mockImplementation(() => {
      throw new Error('no tauri runtime');
    });

    expect(() => renderHook(() => useTheme())).not.toThrow();
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('swallows a rejected native setTheme promise', async () => {
    installMq(false);
    mockSetTheme.mockRejectedValueOnce(new Error('boom'));

    renderHook(() => useTheme());
    await act(async () => {}); // 吸收微任务，避免 unhandled rejection
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('survives a failing localStorage write', () => {
    installMq(false);
    const spy = jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw 0;
    });

    expect(() => renderHook(() => useTheme())).not.toThrow();
    spy.mockRestore();
  });
});
