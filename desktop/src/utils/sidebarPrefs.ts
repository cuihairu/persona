/** Sidebar preferences: full-column collapse plus per-group folding, persisted to localStorage just like the theme preference */
export const SIDEBAR_PREFS_STORAGE_KEY = 'persona-sidebar-prefs';

/** Collapsible group keys (one-to-one with the four group headings in sidebarNav) */
export type SidebarGroupKey = 'categories' | 'vaults' | 'tags' | 'tools';

export interface SidebarPrefs {
  /** Collapse the whole column into an icon strip */
  collapsed: boolean;
  /** List of collapsed group keys */
  collapsedGroups: SidebarGroupKey[];
}

const GROUP_KEYS: SidebarGroupKey[] = ['categories', 'vaults', 'tags', 'tools'];

export const DEFAULT_SIDEBAR_PREFS: SidebarPrefs = { collapsed: false, collapsedGroups: [] };

const sanitize = (raw: unknown): SidebarPrefs => {
  if (typeof raw !== 'object' || raw === null) return { ...DEFAULT_SIDEBAR_PREFS };
  const obj = raw as Record<string, unknown>;
  return {
    collapsed: obj.collapsed === true,
    collapsedGroups: Array.isArray(obj.collapsedGroups)
      ? obj.collapsedGroups.filter((k): k is SidebarGroupKey =>
          GROUP_KEYS.includes(k as SidebarGroupKey),
        )
      : [],
  };
};

/** Reads the persisted preferences: missing value, out-of-range value, or an environment without localStorage all fall back to the default expanded state */
export const readSidebarPrefs = (): SidebarPrefs => {
  try {
    const raw = localStorage.getItem(SIDEBAR_PREFS_STORAGE_KEY);
    if (raw !== null) return sanitize(JSON.parse(raw));
  } catch {
    // jsdom, private mode, bad JSON: silently use the default
  }
  return { ...DEFAULT_SIDEBAR_PREFS };
};

/** Writes the whole preference object back (all read-modify-write flows go through here so the two keys never drift) */
export const writeSidebarPrefs = (prefs: SidebarPrefs): void => {
  try {
    localStorage.setItem(SIDEBAR_PREFS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // No storage in the environment or quota full: losing the preference is not fatal
  }
};
