import { useEffect } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useAppStore } from '@/stores/appStore';
import {
  THEME_STORAGE_KEY,
  applyThemeClass,
  resolveTheme,
  systemPrefersDark,
} from '@/utils/theme';

/**
 * 主题联动，App 顶层挂载一次：
 * 1) 偏好变化 → 解析实际档位 → <html>.dark + localStorage 持久化 + 原生窗口 setTheme；
 * 2) 'system' 档 → 监听 prefers-color-scheme 变化实时翻转（卸载清理）。
 * 非 Tauri runtime（纯浏览器/jsdom）下 getCurrentWindow 会同步抛错、promise 会 reject，一律静默。
 */
export const useTheme = () => {
  const theme = useAppStore((s) => s.theme);

  useEffect(() => {
    applyThemeClass(resolveTheme(theme, systemPrefersDark()));
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // 无存储环境：只影响持久化，不影响本会话
    }
    try {
      // 'system' 传 null = 原生窗口回退跟随系统；'light'/'dark' 显式接管
      getCurrentWindow()
        .setTheme(theme === 'system' ? null : theme)
        .catch(() => {});
    } catch {
      // jsdom / 非 Tauri 环境：__TAURI_INTERNALS__ 缺失，同步 TypeError
    }
  }, [theme]);

  useEffect(() => {
    if (theme !== 'system') return;
    if (typeof window.matchMedia !== 'function') return; // jsdom 未 mock 时跳过
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => applyThemeClass(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);
};
