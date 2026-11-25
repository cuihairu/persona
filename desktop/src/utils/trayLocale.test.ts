import { trayLocaleLabels } from './trayLocale';

/** Pure mapping from the locale table truth to the tray label payload: complete keys, stable order (the Rust side renders by field) */
describe('trayLocaleLabels', () => {
  it('maps every label through its tray.* i18n key', () => {
    const labels: Record<string, string> = {
      'tray.open': '打开 Persona',
      'tray.quickAccess': '快速访问',
      'tray.generator': '密码生成器',
      'tray.lock': '锁定',
      'tray.quit': '退出',
    };
    const calls: string[] = [];
    const t = (key: string) => {
      calls.push(key);
      return labels[key] ?? key;
    };

    expect(trayLocaleLabels(t)).toEqual({
      open: '打开 Persona',
      quickAccess: '快速访问',
      generator: '密码生成器',
      lock: '锁定',
      quit: '退出',
    });
    expect(calls).toEqual([
      'tray.open',
      'tray.quickAccess',
      'tray.generator',
      'tray.lock',
      'tray.quit',
    ]);
  });

  it('follows a language switch via the provided t', () => {
    const tables: Record<string, Record<string, string>> = {
      en: {
        'tray.open': 'Open Persona',
        'tray.quickAccess': 'Quick Access',
        'tray.generator': 'Password Generator',
        'tray.lock': 'Lock',
        'tray.quit': 'Quit',
      },
    };
    let current = 'en';
    const t = (key: string) => tables[current]?.[key] ?? key;

    expect(trayLocaleLabels(t).lock).toBe('Lock');
    current = 'zh-CN';
    // When the zh-CN table is not laid out inside this stub, t falls back to
    // the key: the real table is provided by the i18n resources. Here we only
    // verify that "swapping t swaps the language" with no stale labels cached.
    expect(trayLocaleLabels(t).lock).toBe('tray.lock');
  });
});
