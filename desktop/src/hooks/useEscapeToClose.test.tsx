import { fireEvent, renderHook } from '@testing-library/react';
import { useEscapeToClose } from './useEscapeToClose';

const pressEscape = () => fireEvent.keyDown(window, { key: 'Escape' });

describe('hooks/useEscapeToClose', () => {
  it('calls onClose on Escape while open', () => {
    const onClose = jest.fn();
    renderHook(() => useEscapeToClose(true, onClose));

    pressEscape();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not listen while closed', () => {
    const onClose = jest.fn();
    const { rerender } = renderHook(
      ({ isOpen }) => useEscapeToClose(isOpen, onClose),
      { initialProps: { isOpen: false } },
    );

    pressEscape();
    expect(onClose).not.toHaveBeenCalled();

    rerender({ isOpen: true });
    pressEscape();
    expect(onClose).toHaveBeenCalledTimes(1);

    rerender({ isOpen: false });
    pressEscape();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('ignores other keys and always reads the latest onClose', () => {
    const first = jest.fn();
    const second = jest.fn();
    const { rerender } = renderHook(
      ({ onClose }) => useEscapeToClose(true, onClose),
      { initialProps: { onClose: first } },
    );

    fireEvent.keyDown(window, { key: 'Enter' });
    expect(first).not.toHaveBeenCalled();

    // latest-ref：换 onClose 引用无需重建监听
    rerender({ onClose: second });
    pressEscape();
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });

  it('unsubscribes on unmount', () => {
    const onClose = jest.fn();
    const { unmount } = renderHook(() => useEscapeToClose(true, onClose));

    unmount();
    pressEscape();
    expect(onClose).not.toHaveBeenCalled();
  });
});
