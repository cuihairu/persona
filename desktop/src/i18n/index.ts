import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zhCN from './locales/zh-CN';
import en from './locales/en';

/** 支持的语言列表；zh-CN 是基准语言（键的真相来源），en 跟随翻译 */
export const SUPPORTED_LOCALES = ['zh-CN', 'en'] as const;
export type AppLocale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: AppLocale = 'zh-CN';

/** 持久化值 → 受支持语言；未知值回退基准语言 */
export function normalizeLocale(saved: string | null | undefined): AppLocale {
  return saved === 'en' ? 'en' : 'zh-CN';
}

// 模块加载即同步初始化（资源内联，无异步 backend）——main.tsx 与测试
// setup 各 import 一次即可，组件侧直接 useTranslation。
void i18n.use(initReactI18next).init({
  resources: {
    'zh-CN': { translation: zhCN },
    en: { translation: en },
  },
  lng: DEFAULT_LOCALE,
  fallbackLng: DEFAULT_LOCALE,
  interpolation: {
    // React 自身转义，i18next 不需要再 HTML-escape
    escapeValue: false,
  },
});

export default i18n;
