import * as React from 'react';
import { useMemo } from 'react';
import { Cog6ToothIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import { useAppStore } from '@/stores/appStore';
import { IdentitySwitcher } from './IdentitySwitcher';
import type { FeatureFlags } from '@/types';
import { clsx } from 'clsx';

export type ViewId = 'credentials' | 'statistics' | 'sshAgent' | 'wallets' | 'watchtower' | 'passkeys';

interface NavItem {
  id: ViewId;
  label: string;
  /** 对应 workspace 功能开关；不带的为主航道视图，恒可见 */
  flag?: keyof FeatureFlags;
}

export const NAV_ITEMS: NavItem[] = [
  { id: 'credentials', label: 'Credentials' },
  { id: 'statistics', label: 'Statistics' },
  { id: 'sshAgent', label: 'SSH Agent', flag: 'ssh_agent' },
  { id: 'wallets', label: 'Wallets', flag: 'wallet' },
  { id: 'watchtower', label: 'Watchtower' },
  { id: 'passkeys', label: 'Passkeys', flag: 'passkeys' },
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
  const featureFlags = useAppStore((s) => s.featureFlags);

  const visibleNav = useMemo(
    () => NAV_ITEMS.filter((item) => !item.flag || featureFlags[item.flag]),
    [featureFlags]
  );

  return (
    <aside
      data-testid="app-sidebar"
      aria-label="Sidebar"
      className="w-64 shrink-0 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-700 flex flex-col overflow-y-auto"
    >
      {/* 顶部：身份切换器（对应 1Password 账户切换器的位置） */}
      <div className="px-3 py-3 border-b border-gray-200 dark:border-gray-700">
        <IdentitySwitcher onCreateIdentity={onCreateIdentity} />
      </div>

      {/* 视图导航 */}
      <nav data-testid="sidebar-nav" aria-label="Views" className="p-3 space-y-1">
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
            {item.label}
          </button>
        ))}
      </nav>

      {/* 底部操作区：设置 + 锁定 */}
      <div
        data-testid="sidebar-footer"
        className="mt-auto border-t border-gray-200 dark:border-gray-700 p-3 flex items-center gap-1"
      >
        <button className="btn-ghost" aria-label="Settings" onClick={onOpenSettings}>
          <Cog6ToothIcon className="w-4 h-4" />
        </button>
        <button
          className="btn-ghost text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-500/10"
          aria-label="Lock session"
          onClick={onLock}
        >
          <LockClosedIcon className="w-4 h-4" />
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
