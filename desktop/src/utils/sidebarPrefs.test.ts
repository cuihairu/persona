import { DEFAULT_SIDEBAR_PREFS, readSidebarPrefs, writeSidebarPrefs } from './sidebarPrefs';

describe('utils/sidebarPrefs', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('falls back to defaults when nothing is stored', () => {
    expect(readSidebarPrefs()).toEqual(DEFAULT_SIDEBAR_PREFS);
  });

  it('round-trips a written value', () => {
    writeSidebarPrefs({ collapsed: true, collapsedGroups: ['tools', 'tags'] });
    expect(readSidebarPrefs()).toEqual({ collapsed: true, collapsedGroups: ['tools', 'tags'] });
  });

  it('drops unknown group keys', () => {
    localStorage.setItem(
      'persona-sidebar-prefs',
      JSON.stringify({ collapsed: false, collapsedGroups: ['nope', 'tools'] }),
    );
    expect(readSidebarPrefs().collapsedGroups).toEqual(['tools']);
  });

  it('falls back to defaults on broken JSON', () => {
    localStorage.setItem('persona-sidebar-prefs', '{broken');
    expect(readSidebarPrefs()).toEqual(DEFAULT_SIDEBAR_PREFS);
  });
});
