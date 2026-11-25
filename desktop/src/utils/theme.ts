import type { ThemePreference } from '@/types';

/** Storage key for the theme preference (the repo's first localStorage use; every read/write is wrapped in try/catch) */
export const THEME_STORAGE_KEY = 'persona-theme';

const VALID: ThemePreference[] = ['system', 'light', 'dark'];

/** Reads the persisted preference: missing value, out-of-range value, or an environment without localStorage all fall back to 'system' */
export const readStoredTheme = (): ThemePreference => {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw !== null && VALID.includes(raw as ThemePreference)) {
      return raw as ThemePreference;
    }
  } catch {
    // Storage-less environments such as jsdom or private mode: silently use the default
  }
  return 'system';
};

/** Preference + system dark → whether dark actually applies */
export const resolveTheme = (pref: ThemePreference, systemDark: boolean): boolean =>
  pref === 'dark' || (pref === 'system' && systemDark);

/** Whether the system currently prefers dark; false when jsdom lacks matchMedia */
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

/** Applies the resolved result to the <html> class (idempotent, safe to call repeatedly) */
export const applyThemeClass = (isDark: boolean): void => {
  document.documentElement.classList.toggle('dark', isDark);
};
