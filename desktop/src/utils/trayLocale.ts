import type { TrayLocaleLabels } from '@/types';

/**
 * 托盘右键菜单文案：真值在 i18n locale 表（tray.* 命名空间）。原生托盘
 * 菜单不归 useTranslation 管（构建在 Rust 侧），由前端把当前语言的
 * 文案推给 set_tray_locale 命令渲染——语言切换后立即生效。
 */
export function trayLocaleLabels(t: (key: string) => string): TrayLocaleLabels {
  return {
    open: t('tray.open'),
    quickAccess: t('tray.quickAccess'),
    generator: t('tray.generator'),
    lock: t('tray.lock'),
    quit: t('tray.quit'),
  };
}
