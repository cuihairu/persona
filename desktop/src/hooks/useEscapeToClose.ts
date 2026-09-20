import { useEffect, useRef } from 'react';

/**
 * Escape 关闭 modal：window keydown 监听（焦点无需落在 modal 内，
 * 对齐 1Password——modal 开着 Esc 即关）。isOpen=false 时不挂监听。
 *
 * onClose 走 latest-ref（useGlobalShortcut 先例），监听只随 isOpen 重建；
 * 叠开场景由调用方收口：下层 modal 把 isOpen 传成
 * `isOpen && !上层弹窗开启`，保证 Esc 只关最上层。
 */
export const useEscapeToClose = (isOpen: boolean, onClose: () => void) => {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseRef.current();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen]);
};
