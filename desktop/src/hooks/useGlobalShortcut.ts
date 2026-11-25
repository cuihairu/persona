import { useEffect, useRef } from 'react';

/**
 * Global shortcut (Cmd/Ctrl + key): listens on window keydown and, on a hit,
 * prevents the default and fires the handler. The key is case-insensitive (pressing meta
 * often yields an uppercase key, so everything is normalized).
 * The handler goes through a latest-ref (assigned during render, following the QuickSearch searchRef precedent),
 * so the listener is only rebuilt when key/enabled change; when enabled=false no listener is attached
 * (the App stays mounted and passes isUnlocked for the locked state; components such as QuickSearch
 * that only mount after unlocking can omit it).
 */
export const useGlobalShortcut = (key: string, handler: () => void, enabled = true) => {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;

  useEffect(() => {
    if (!enabled) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === key.toLowerCase()) {
        event.preventDefault();
        handlerRef.current();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [key, enabled]);
};
