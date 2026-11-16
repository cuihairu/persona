/** 侧栏偏好：整栏收起 + 各分组折叠，随主题偏好一样落 localStorage */
export const SIDEBAR_PREFS_STORAGE_KEY = 'persona-sidebar-prefs';

/** 可折叠的分组 key（与 sidebarNav 的四个分组标题一一对应） */
export type SidebarGroupKey = 'categories' | 'vaults' | 'tags' | 'tools';

export interface SidebarPrefs {
  /** 整栏收成图标条 */
  collapsed: boolean;
  /** 折叠的分组 key 列表 */
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

/** 读取持久化偏好：无值/越界/环境无 localStorage 一律回退默认展开 */
export const readSidebarPrefs = (): SidebarPrefs => {
  try {
    const raw = localStorage.getItem(SIDEBAR_PREFS_STORAGE_KEY);
    if (raw !== null) return sanitize(JSON.parse(raw));
  } catch {
    // jsdom、隐私模式、坏 JSON：静默走默认
  }
  return { ...DEFAULT_SIDEBAR_PREFS };
};

/** 整份偏好写回（读改写都经这里，避免两个 key 漂移） */
export const writeSidebarPrefs = (prefs: SidebarPrefs): void => {
  try {
    localStorage.setItem(SIDEBAR_PREFS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // 环境无存储或写满：偏好不落盘不致命
  }
};
