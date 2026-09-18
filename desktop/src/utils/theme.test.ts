import {
  THEME_STORAGE_KEY,
  readStoredTheme,
  resolveTheme,
  systemPrefersDark,
  applyThemeClass,
} from './theme';

describe('utils/theme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.className = '';
  });

  describe('readStoredTheme', () => {
    it.each(['system', 'light', 'dark'] as const)('returns a stored valid value %s', (value) => {
      localStorage.setItem(THEME_STORAGE_KEY, value);
      expect(readStoredTheme()).toBe(value);
    });

    it('falls back to system when the key is missing', () => {
      expect(readStoredTheme()).toBe('system');
    });

    it('falls back to system on a corrupted value', () => {
      localStorage.setItem(THEME_STORAGE_KEY, 'purple');
      expect(readStoredTheme()).toBe('system');
    });

    it('falls back to system when localStorage throws', () => {
      const spy = jest.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw 0;
      });
      expect(readStoredTheme()).toBe('system');
      spy.mockRestore();
    });
  });

  describe('resolveTheme', () => {
    it('maps preference + system darkness to the actual mode', () => {
      expect(resolveTheme('system', false)).toBe(false);
      expect(resolveTheme('system', true)).toBe(true);
      expect(resolveTheme('light', true)).toBe(false);
      expect(resolveTheme('dark', false)).toBe(true);
    });
  });

  describe('systemPrefersDark', () => {
    it('returns false when matchMedia is unavailable (jsdom)', () => {
      expect(systemPrefersDark()).toBe(false);
    });

    it('follows the media query result when matchMedia exists', () => {
      const stub = (query: string) => ({
        matches: query.includes('dark'),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      });
      window.matchMedia = stub as unknown as typeof window.matchMedia;
      try {
        expect(systemPrefersDark()).toBe(true);
        window.matchMedia = ((query: string) => ({
          ...stub(query),
          matches: false,
        })) as unknown as typeof window.matchMedia;
        expect(systemPrefersDark()).toBe(false);
      } finally {
        delete (window as { matchMedia?: unknown }).matchMedia;
      }
    });
  });

  describe('applyThemeClass', () => {
    it('toggles the dark class on <html> idempotently', () => {
      applyThemeClass(true);
      applyThemeClass(true);
      expect(document.documentElement.classList.contains('dark')).toBe(true);

      applyThemeClass(false);
      applyThemeClass(false);
      expect(document.documentElement.classList.contains('dark')).toBe(false);
    });
  });
});
