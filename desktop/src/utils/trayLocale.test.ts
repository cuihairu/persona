import { trayLocaleLabels } from './trayLocale';

/** locale 表真值→托盘文案载荷的纯映射：键齐全、顺序稳定（Rust 侧按字段渲染） */
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
    // zh-CN 表未在此桩内铺开时 t 退回 key：真实表由 i18n 资源提供，
    // 这里只验证"换 t 即换语言"不缓存旧文案
    expect(trayLocaleLabels(t).lock).toBe('tray.lock');
  });
});
