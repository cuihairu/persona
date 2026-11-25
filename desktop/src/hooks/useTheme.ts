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
 * Theme synchronization, mounted once at the top of the App tree:
 * 1) preference change -> resolve the actual tier -> <html>.dark + localStorage persistence + native window setTheme;
 * 2) 'system' tier -> watch prefers-color-scheme changes and flip in real time (cleaned up on unmount).
 * Under a non-Tauri runtime (plain browser/jsdom) getCurrentWindow throws synchronously and the promise rejects; both are silenced.
 */
export const useTheme = () => {
  const theme = useAppStore((s) => s.theme);

  useEffect(() => {
    applyThemeClass(resolveTheme(theme, systemPrefersDark()));
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // No storage available: this only affects persistence, not the current session
    }
    try {
      // 'system' passes null = native window falls back to following the OS; 'light'/'dark' take over explicitly
      getCurrentWindow()
        .setTheme(theme === 'system' ? null : theme)
        .catch(() => {});
    } catch {
      // jsdom / non-Tauri environment: __TAURI_INTERNALS__ is missing, throwing a synchronous TypeError
    }
  }, [theme]);

  useEffect(() => {
    if (theme !== 'system') return;
    if (typeof window.matchMedia !== 'function') return; // skip when jsdom has not mocked it
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => applyThemeClass(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);
};
