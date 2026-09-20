import * as React from 'react';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Cog6ToothIcon,
  HeartIcon,
  LockClosedIcon,
  Squares2X2Icon,
} from '@heroicons/react/24/outline';
import { useAppStore, DEFAULT_SIDEBAR_FILTER } from '@/stores/appStore';
import { IdentitySwitcher } from './IdentitySwitcher';
import { getCredentialIcon } from './credentialDisplay';
import type { FeatureFlags, SidebarFilter } from '@/types';
import { clsx } from 'clsx';

export type ViewId = 'credentials' | 'statistics' | 'sshAgent' | 'wallets' | 'watchtower' | 'passkeys';

interface NavItem {
  id: ViewId;
  /** i18n key（nav.*）——模块级常量不能调 hook，渲染处 t() */
  label: string;
  /** 对应 workspace 功能开关；不带的为主航道视图，恒可见 */
  flag?: keyof FeatureFlags;
}

export const NAV_ITEMS: NavItem[] = [
  { id: 'credentials', label: 'nav.credentials' },
  { id: 'statistics', label: 'nav.statistics' },
  { id: 'sshAgent', label: 'nav.sshAgent', flag: 'ssh_agent' },
  { id: 'wallets', label: 'nav.wallets', flag: 'wallet' },
  { id: 'watchtower', label: 'nav.watchtower' },
  { id: 'passkeys', label: 'nav.passkeys', flag: 'passkeys' },
];

interface SidebarProps {
  currentView: ViewId;
  onNavigate: (view: ViewId) => void;
  /** 透传给 IdentitySwitcher 下拉的 "Create new identity" */
  onCreateIdentity: () => void;
  onOpenSettings: () => void;
  onLock: () => void;
}

/** 全局左侧栏：身份切换器（顶部）→ 视图导航 → 底部操作区；独立于主列滚动 */
const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onNavigate,
  onCreateIdentity,
  onOpenSettings,
  onLock,
}) => {
  const { t } = useTranslation();
  const featureFlags = useAppStore((s) => s.featureFlags);
  const credentials = useAppStore((s) => s.credentials);
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const setSidebarFilter = useAppStore((s) => s.setSidebarFilter);

  const visibleNav = useMemo(
    () => NAV_ITEMS.filter((item) => !item.flag || featureFlags[item.flag]),
    [featureFlags]
  );

  // 分类树聚合（仅当前身份的凭据；类型是自由 string，按数据动态收集）
  const availableTypes = useMemo(
    () => Array.from(new Set(credentials.map((c) => c.credential_type))).sort(),
    [credentials]
  );
  const availableTags = useMemo(
    () => Array.from(new Set(credentials.flatMap((c) => c.tags))).sort(),
    [credentials]
  );
  const favoriteCount = useMemo(
    () => credentials.filter((c) => c.is_favorite).length,
    [credentials]
  );
  const typeCounts = useMemo(
    () => new Map(availableTypes.map((t) => [t, credentials.filter((c) => c.credential_type === t).length])),
    [credentials, availableTypes]
  );
  const tagCounts = useMemo(
    () => new Map(availableTags.map((g) => [g, credentials.filter((c) => c.tags.includes(g)).length])),
    [credentials, availableTags]
  );

  const isNodeActive = (filter: SidebarFilter) =>
    JSON.stringify(filter) === JSON.stringify(sidebarFilter);

  const nodeClass = (active: boolean) =>
    clsx(
      'w-full flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-colors',
      active
        ? 'bg-primary-50 text-primary-900 dark:bg-primary-500/10 dark:text-primary-100'
        : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
    );
  const countClass = 'ml-auto text-xs text-gray-400 dark:text-gray-500';
  const groupTitleClass =
    'px-3 mb-1 text-xs font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500';

  return (
    <aside
      data-testid="app-sidebar"
      aria-label={t('sidebar.a11yLabel')}
      className="w-64 shrink-0 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-700 flex flex-col overflow-y-auto"
    >
      {/* 顶部：身份切换器（对应 1Password 账户切换器的位置） */}
      <div className="px-3 py-3 border-b border-gray-200 dark:border-gray-700">
        <IdentitySwitcher onCreateIdentity={onCreateIdentity} />
      </div>

      {/* 视图导航 */}
      <nav data-testid="sidebar-nav" aria-label={t('sidebar.a11yNav')} className="p-3 space-y-1">
        {visibleNav.map((item) => (
          <button
            key={item.id}
            data-testid={`nav-${item.id}`}
            aria-current={currentView === item.id ? 'page' : undefined}
            onClick={() => onNavigate(item.id)}
            className={clsx(
              'w-full text-left px-3 py-2 rounded-md text-sm font-medium transition-colors',
              currentView === item.id
                ? 'bg-primary-50 text-primary-900 dark:bg-primary-500/10 dark:text-primary-100'
                : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
            )}
          >
            {t(item.label)}
          </button>
        ))}
      </nav>

      {/* 分类树：仅凭据视图；单选，点中即替换 store 筛选 */}
      {currentView === 'credentials' && (
        <div data-testid="sidebar-filters" className="px-3 pb-3 space-y-1">
          <button
            data-testid="filter-all"
            onClick={() => setSidebarFilter(DEFAULT_SIDEBAR_FILTER)}
            className={nodeClass(isNodeActive(DEFAULT_SIDEBAR_FILTER))}
          >
            <Squares2X2Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span className="truncate">{t('sidebar.allItems')}</span>
            <span className={countClass}>{credentials.length}</span>
          </button>
          <button
            data-testid="filter-favorites"
            onClick={() => setSidebarFilter({ kind: 'favorites' })}
            className={nodeClass(isNodeActive({ kind: 'favorites' }))}
          >
            <HeartIcon className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span className="truncate">{t('sidebar.favorites')}</span>
            <span className={countClass}>{favoriteCount}</span>
          </button>

          {availableTypes.length > 0 && (
            <div className="pt-3">
              <p className={groupTitleClass}>{t('sidebar.types')}</p>
              {availableTypes.map((type) => {
                const TypeIcon = getCredentialIcon(type);
                return (
                  <button
                    key={type}
                    data-testid={`filter-type-${type}`}
                    onClick={() => setSidebarFilter({ kind: 'type', value: type })}
                    className={nodeClass(isNodeActive({ kind: 'type', value: type }))}
                  >
                    <TypeIcon className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span className="truncate">{type}</span>
                    <span className={countClass}>{typeCounts.get(type)}</span>
                  </button>
                );
              })}
            </div>
          )}

          {availableTags.length > 0 && (
            <div className="pt-3">
              <p className={groupTitleClass}>{t('sidebar.tags')}</p>
              {availableTags.map((tag) => (
                <button
                  key={tag}
                  data-testid={`filter-tag-${tag}`}
                  onClick={() => setSidebarFilter({ kind: 'tag', value: tag })}
                  className={nodeClass(isNodeActive({ kind: 'tag', value: tag }))}
                >
                  <span className="truncate">#{tag}</span>
                  <span className={countClass}>{tagCounts.get(tag)}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 底部操作区：设置 + 锁定 */}
      <div
        data-testid="sidebar-footer"
        className="mt-auto border-t border-gray-200 dark:border-gray-700 p-3 flex items-center gap-1"
      >
        <button className="btn-ghost" aria-label={t('sidebar.settings')} title={t('sidebar.settingsTitle')} onClick={onOpenSettings}>
          <Cog6ToothIcon className="w-4 h-4" />
        </button>
        <button
          className="btn-ghost text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-500/10"
          aria-label={t('sidebar.lock')}
          title={t('sidebar.lockTitle')}
          onClick={onLock}
        >
          <LockClosedIcon className="w-4 h-4" />
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
