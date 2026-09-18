import { fireEvent, renderHook } from '@testing-library/react';
import { useGlobalShortcut } from './useGlobalShortcut';

const press = (key: string, mods: { metaKey?: boolean; ctrlKey?: boolean } = {}) =>
  fireEvent.keyDown(window, { key, ...mods });

describe('hooks/useGlobalShortcut', () => {
  it('fires the handler on cmd+key and ctrl+key', () => {
    const handler = jest.fn();
    renderHook(() => useGlobalShortcut('k', handler));

    press('k', { metaKey: true });
    press('k', { ctrlKey: true });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('normalizes key case (meta produces uppercase key on some layouts)', () => {
    const handler = jest.fn();
    renderHook(() => useGlobalShortcut('k', handler));

    press('K', { metaKey: true });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('ignores unmodified keys, other modifiers, and other keys', () => {
    const handler = jest.fn();
    renderHook(() => useGlobalShortcut('k', handler));

    press('k'); // 无修饰键
    press('k', { altKey: true } as any); // 仅 alt
    press('j', { metaKey: true }); // 修饰键对但 key 不对
    press('k', { metaKey: false, ctrlKey: false });
    expect(handler).not.toHaveBeenCalled();
  });

  it('calls preventDefault to suppress the browser default', () => {
    const preventDefault = jest.spyOn(KeyboardEvent.prototype, 'preventDefault');
    renderHook(() => useGlobalShortcut('l', jest.fn()));

    press('l', { metaKey: true });
    expect(preventDefault).toHaveBeenCalledTimes(1);
    preventDefault.mockRestore();
  });

  it('does not listen while disabled and resumes when re-enabled', () => {
    const handler = jest.fn();
    const { rerender } = renderHook(
      ({ enabled }) => useGlobalShortcut('l', handler, enabled),
      { initialProps: { enabled: false } },
    );

    press('l', { metaKey: true });
    expect(handler).not.toHaveBeenCalled();

    rerender({ enabled: true });
    press('l', { metaKey: true });
    expect(handler).toHaveBeenCalledTimes(1);

    rerender({ enabled: false });
    press('l', { metaKey: true });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('removes the listener on unmount', () => {
    const handler = jest.fn();
    const { unmount } = renderHook(() => useGlobalShortcut('e', handler));

    unmount();
    press('e', { metaKey: true });
    expect(handler).not.toHaveBeenCalled();
  });

  it('invokes the latest handler after a re-render (latest-ref)', () => {
    const first = jest.fn();
    const second = jest.fn();
    const { rerender } = renderHook(({ handler }) => useGlobalShortcut('e', handler), {
      initialProps: { handler: first },
    });

    rerender({ handler: second });
    press('e', { metaKey: true });
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });
});
