import type { TrayLocaleLabels } from '@/types';

/**
 * Tray right-click menu labels: the source of truth is the i18n locale table
 * (the tray.* namespace). The native tray menu is outside useTranslation's
 * reach (it is built on the Rust side), so the frontend pushes the current
 * language's labels to the set_tray_locale command — switching language takes
 * effect immediately.
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
