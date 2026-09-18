import { useEffect, useRef } from 'react';

/**
 * 全局快捷键（Cmd/Ctrl + key）：window keydown 上监听，命中即 preventDefault
 * 并触发 handler。key 大小写不敏感（meta 按下常产生大写 key，统一归一）。
 * handler 走 latest-ref（渲染期赋值，照 QuickSearch searchRef 先例），
 * 监听只随 key/enabled 变化重建；enabled=false 时不挂监听
 * （App 恒挂载，锁定态传 isUnlocked；QuickSearch 这类只挂解锁后的组件可省略）。
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
