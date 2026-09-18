import type { ThemePreference } from '@/types';

/** 主题偏好持久化 key（全仓首个 localStorage 用例，读写一律 try/catch） */
export const THEME_STORAGE_KEY = 'persona-theme';

const VALID: ThemePreference[] = ['system', 'light', 'dark'];

/** 读取持久化偏好：无值/越界/环境无 localStorage 一律回退 'system' */
export const readStoredTheme = (): ThemePreference => {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw !== null && VALID.includes(raw as ThemePreference)) {
      return raw as ThemePreference;
    }
  } catch {
    // jsdom、隐私模式等无存储环境：静默走默认
  }
  return 'system';
};

/** 偏好 + 系统暗色 → 实际是否暗色 */
export const resolveTheme = (pref: ThemePreference, systemDark: boolean): boolean =>
  pref === 'dark' || (pref === 'system' && systemDark);

/** 系统当前是否暗色；jsdom 未实现 matchMedia 时按 false */
export const systemPrefersDark = (): boolean => {
  try {
    return (
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches
    );
  } catch {
    return false;
  }
};

/** 把解析结果落到 <html> class（幂等，可重复调用） */
export const applyThemeClass = (isDark: boolean): void => {
  document.documentElement.classList.toggle('dark', isDark);
};
