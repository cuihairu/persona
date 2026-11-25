import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zhCN from './locales/zh-CN';
import en from './locales/en';

/** Supported locales; zh-CN is the base locale (source of truth for keys), en is translated to follow */
export const SUPPORTED_LOCALES = ['zh-CN', 'en'] as const;
export type AppLocale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: AppLocale = 'zh-CN';

/** Persisted value -> supported locale; unknown values fall back to the base locale */
export function normalizeLocale(saved: string | null | undefined): AppLocale {
  return saved === 'en' ? 'en' : 'zh-CN';
}

// Initialise synchronously on module load (resources inlined, no async backend) -- main.tsx and the test
// setup each import it once, and components call useTranslation directly.
void i18n.use(initReactI18next).init({
  resources: {
    'zh-CN': { translation: zhCN },
    en: { translation: en },
  },
  lng: DEFAULT_LOCALE,
  fallbackLng: DEFAULT_LOCALE,
  interpolation: {
    // React escapes on its own, so i18next does not need HTML-escaping
    escapeValue: false,
  },
});

export default i18n;
