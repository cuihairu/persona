import * as React from 'react';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import {
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  ChevronDownIcon,
  Cog6ToothIcon,
  LockClosedIcon,
  MagnifyingGlassIcon,
  TagIcon,
  UserCircleIcon,
} from '@heroicons/react/24/outline';
import { useAppStore } from '@/stores/appStore';
import { IdentitySwitcher } from './IdentitySwitcher';
import {
  ALL_ITEMS_FILTER,
  CATEGORY_NODES,
  TOP_NODES,
  TOOL_NODES,
  identityIcon,
  isSameFilter,
  navTestId,
  viewForFilter,
  type NavNode,
} from './sidebarNav';
import type { SidebarGroupKey } from '@/utils/sidebarPrefs';
import type { SidebarFilter } from '@/types';

interface SidebarProps {
  /** 侧栏是唯一的导航源：点击节点先写 store 筛选态，再回调通知 App（切身份等副作用） */
  onNavigate: (filter: SidebarFilter) => void;
  /** 透传给 IdentitySwitcher 下拉的 "Create new identity" */
  onCreateIdentity?: () => void;
  onOpenSettings: () => void;
  onLock: () => void;
}

interface RowProps {
  label: string;
  icon: NavNode['icon'];
  active: boolean;
  onClick: () => void;
  /** 数字徽标；undefined = 不显示（徽标对读屏隐藏，行名保持干净） */
  count?: number;
  testId: string;
  /** 图标条形态：只留图标，tooltip/aria 用行名兜底 */
  rail?: boolean;
}

/** 侧栏行：图标 + 名称 + 计数，紧凑行高（1Password 式单行选中块） */
const NavRow: React.FC<RowProps> = ({ label, icon: Icon, active, onClick, count, testId, rail }) => (
  <button
    type="button"
    data-testid={testId}
    aria-current={active ? 'page' : undefined}
    title={rail ? label : undefined}
    aria-label={rail ? label : undefined}
    onClick={onClick}
    className={clsx(
      'group flex items-center gap-2.5 rounded-md text-left text-[13px] leading-5 transition-colors',
      rail ? 'h-9 w-9 justify-center p-0' : 'w-full px-2.5 py-1.5',
      active
        ? 'bg-primary-50 font-medium text-primary-900 dark:bg-primary-500/15 dark:text-primary-100'
        : 'text-secondary-700 hover:bg-secondary-100 dark:text-secondary-300 dark:hover:bg-white/5',
    )}
  >
    <Icon
      className={clsx(
        'h-4 w-4 shrink-0 transition-colors',
        active
          ? 'text-primary-600 dark:text-primary-400'
          : 'text-secondary-400 group-hover:text-secondary-600 dark:text-secondary-500 dark:group-hover:text-secondary-300',
      )}
      aria-hidden="true"
    />
    {!rail && <span className="truncate">{label}</span>}
    {!rail && count !== undefined && (
      <span
        aria-hidden="true"
        className="ml-auto text-[11px] tabular-nums text-secondary-600 dark:text-secondary-400"
      >
        {count}
      </span>
    )}
  </button>
);

/** 分组标题（类别 / 保险库 / 标签 / 工具），点击折叠/展开整组 */
const GroupHeader: React.FC<{
  label: string;
  groupKey: SidebarGroupKey;
  open: boolean;
  onToggle: () => void;
  first?: boolean;
}> = ({ label, groupKey, open, onToggle, first }) => (
  <button
    type="button"
    data-testid={`sidebar-group-${groupKey}`}
    aria-expanded={open}
    onClick={onToggle}
    className={clsx(
      'flex w-full items-center gap-1 rounded-md px-2.5 pb-1 text-left text-[11px] font-semibold uppercase tracking-wider text-secondary-600 transition-colors hover:text-secondary-900 dark:text-secondary-400 dark:hover:text-secondary-200',
      first ? 'pt-1' : 'pt-4',
    )}
  >
    <ChevronDownIcon
      className={clsx('h-3 w-3 shrink-0 transition-transform', !open && '-rotate-90')}
      aria-hidden="true"
    />
    {label}
  </button>
);

/**
 * 全局左侧栏（1Password 式）：顶部身份切换器与大搜索框 → 顶部三行
 * （全部条目 / 收藏 / 最近使用）→ 类别 → 保险库（身份）→ 标签 → 工具；
 * 底部设置与锁定。整栏可收成图标条（窄窗口给主区让宽度），四个分组
 * 各自可折叠；两种偏好都落 localStorage。整栏独立滚动，分组之间留出呼吸间距。
 */
const Sidebar: React.FC<SidebarProps> = ({
  onNavigate,
  onCreateIdentity,
  onOpenSettings,
  onLock,
}) => {
  const { t } = useTranslation();
  const featureFlags = useAppStore((s) => s.featureFlags);
  const credentials = useAppStore((s) => s.credentials);
  const identities = useAppStore((s) => s.identities);
  const currentIdentity = useAppStore((s) => s.currentIdentity);
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const setSidebarFilter = useAppStore((s) => s.setSidebarFilter);
  const searchQuery = useAppStore((s) => s.credentialSearchQuery);
  const setCredentialSearchQuery = useAppStore((s) => s.setCredentialSearchQuery);
  const rail = useAppStore((s) => s.sidebarCollapsed);
  const toggleSidebarCollapsed = useAppStore((s) => s.toggleSidebarCollapsed);
  const collapsedGroups = useAppStore((s) => s.collapsedSidebarGroups);
  const toggleSidebarGroup = useAppStore((s) => s.toggleSidebarGroup);

  const visible = (nodes: NavNode[]) => nodes.filter((n) => !n.flag || featureFlags[n.flag]);

  // 计数口径：store 里的 credentials 即当前身份已加载的条目
  const counts = useMemo(
    () => ({
      all: credentials.length,
      favorites: credentials.filter((c) => c.is_favorite).length,
      recent: credentials.filter((c) => c.last_accessed).length,
    }),
    [credentials],
  );
  const countByTypes = useMemo(() => {
    const cache = new Map<string, number>();
    return (types: string[]) => {
      const key = types.join('|');
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      const n = credentials.filter((c) => types.includes(c.credential_type)).length;
      cache.set(key, n);
      return n;
    };
  }, [credentials]);

  const availableTags = useMemo(
    () => Array.from(new Set(credentials.flatMap((c) => c.tags))).sort(),
    [credentials],
  );
  const tagCounts = useMemo(
    () => new Map(availableTags.map((g) => [g, credentials.filter((c) => c.tags.includes(g)).length])),
    [credentials, availableTags],
  );
  const identityCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const c of credentials) map.set(c.identity_id, (map.get(c.identity_id) ?? 0) + 1);
    return map;
  }, [credentials]);

  const select = (filter: SidebarFilter) => {
    setSidebarFilter(filter);
    onNavigate(filter);
  };

  const handleSearch = (value: string) => {
    setCredentialSearchQuery(value);
    // 搜索只在列表视图有意义：正处于工具/管理面板时先切回全部条目
    if (value && viewForFilter(sidebarFilter) !== 'credentials') {
      select(ALL_ITEMS_FILTER);
    }
  };

  const nodeRow = (node: NavNode, count?: number) => (
    <NavRow
      key={navTestId(node.filter)}
      testId={navTestId(node.filter)}
      label={t(node.labelKey)}
      icon={node.icon}
      active={isSameFilter(node.filter, sidebarFilter)}
      count={count}
      rail={rail}
      onClick={() => select(node.filter)}
    />
  );

  const groupOpen = (key: SidebarGroupKey) => !collapsedGroups.includes(key);
  const groupHeader = (key: SidebarGroupKey, labelKey: string, first = false) => (
    <GroupHeader
      label={t(labelKey)}
      groupKey={key}
      open={groupOpen(key)}
      onToggle={() => toggleSidebarGroup(key)}
      first={first}
    />
  );

  const topRows = visible(TOP_NODES).map((node) =>
    nodeRow(
      node,
      node.filter.kind === 'all'
        ? counts.all
        : node.filter.kind === 'favorites'
          ? counts.favorites
          : counts.recent,
    ),
  );
  const categoryRows = visible(CATEGORY_NODES).map((node) =>
    nodeRow(node, node.types && countByTypes(node.types)),
  );
  const vaultRows = identities.map((identity) => {
    const loaded = identityCounts.get(identity.id) ?? 0;
    return (
      <NavRow
        key={identity.id}
        testId={navTestId({ kind: 'identity', value: identity.id })}
        label={identity.name}
        icon={identityIcon(identity.identity_type)}
        active={currentIdentity?.id === identity.id}
        // 只在条目已加载时给徽标：store 仅持有当前身份的条目，
        // 其余保险库留白而不是显示误导性的 0
        count={loaded > 0 ? loaded : undefined}
        rail={rail}
        onClick={() => onNavigate({ kind: 'identity', value: identity.id })}
      />
    );
  });
  const tagRows = availableTags.map((tag) => {
    const filter: SidebarFilter = { kind: 'tag', value: tag };
    return (
      <NavRow
        key={tag}
        testId={navTestId(filter)}
        label={`#${tag}`}
        icon={TagIcon}
        active={isSameFilter(filter, sidebarFilter)}
        count={tagCounts.get(tag)}
        rail={rail}
        onClick={() => select(filter)}
      />
    );
  });
  const toolRows = visible(TOOL_NODES).map((node) => nodeRow(node));

  // element（而非组件）：identityIcon 在渲染期返回图标组件，直接 JSX 化会被
  // react-hooks/static-components 拦下
  const railIdentityEl = currentIdentity ? (
    React.createElement(identityIcon(currentIdentity.identity_type), {
      className: 'h-5 w-5',
      'aria-hidden': 'true',
    })
  ) : (
    <UserCircleIcon className="h-5 w-5" aria-hidden="true" />
  );

  return (
    <aside
      data-testid="app-sidebar"
      aria-label={t('sidebar.a11yLabel')}
      className={clsx(
        'flex shrink-0 flex-col border-r border-secondary-200 bg-white dark:border-gray-800 dark:bg-gray-900',
        rail ? 'w-14 items-center' : 'w-[264px]',
      )}
    >
      {/* 顶部：身份切换器 + 大搜索框（对应 1Password 的账户行与搜索）；图标条形态只留身份图标 */}
      {rail ? (
        <div className="flex w-full flex-col items-center border-b border-secondary-200 px-1.5 py-3 dark:border-gray-800">
          <button
            type="button"
            data-testid="sidebar-rail-identity"
            title={currentIdentity?.name ?? t('identity.selectIdentity')}
            aria-label={t('sidebar.expand')}
            onClick={toggleSidebarCollapsed}
            className="flex h-9 w-9 items-center justify-center rounded-md text-secondary-400 transition-colors hover:bg-secondary-100 hover:text-secondary-600 dark:hover:bg-white/5 dark:hover:text-secondary-300"
          >
            {railIdentityEl}
          </button>
        </div>
      ) : (
        <div className="w-full space-y-2.5 border-b border-secondary-200 px-3 py-3 dark:border-gray-800">
          <IdentitySwitcher onCreateIdentity={() => onCreateIdentity?.()} />
          <div className="relative">
            <MagnifyingGlassIcon
              className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-secondary-400 dark:text-secondary-500"
              aria-hidden="true"
            />
            <input
              type="text"
              data-testid="sidebar-search"
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              placeholder={t('sidebar.searchPlaceholder')}
              aria-label={t('sidebar.searchPlaceholder')}
              className="h-9 w-full rounded-md border border-transparent bg-secondary-100 pl-8 pr-2 text-[13px] text-secondary-900 outline-none transition-colors placeholder:text-secondary-500 focus:border-primary-500 focus:bg-white focus:ring-2 focus:ring-primary-500/20 dark:bg-white/5 dark:text-secondary-100 dark:placeholder:text-secondary-400 dark:focus:bg-white/10"
            />
          </div>
        </div>
      )}

      <nav
        data-testid="sidebar-nav"
        aria-label={t('sidebar.a11yNav')}
        className="flex-1 overflow-y-auto px-2 pb-3"
      >
        {/* 顶部三行：全部条目 / 收藏 / 最近使用（不参与分组折叠） */}
        <div className={clsx('space-y-0.5 pt-2', rail && 'flex flex-col items-center')}>
          {topRows}
        </div>

        {/* 类别：1Password 的 item 分类（通行密钥指向独立管理视图，无列表计数） */}
        {rail ? (
          <div className="mt-2 flex flex-col items-center gap-0.5">{categoryRows}</div>
        ) : (
          <>
            {groupHeader('categories', 'sidebar.group.categories')}
            {groupOpen('categories') && <div className="space-y-0.5">{categoryRows}</div>}
          </>
        )}

        {/* 保险库：persona 的身份 = 1Password 的保险库，点击即切换当前身份 */}
        {identities.length > 0 &&
          (rail ? (
            <div className="mt-2 flex flex-col items-center gap-0.5">{vaultRows}</div>
          ) : (
            <>
              {groupHeader('vaults', 'sidebar.group.vaults')}
              {groupOpen('vaults') && <div className="space-y-0.5">{vaultRows}</div>}
            </>
          ))}

        {/* 标签 */}
        {availableTags.length > 0 &&
          (rail ? (
            <div className="mt-2 flex flex-col items-center gap-0.5">{tagRows}</div>
          ) : (
            <>
              {groupHeader('tags', 'sidebar.group.tags')}
              {groupOpen('tags') && <div className="space-y-0.5">{tagRows}</div>}
            </>
          ))}

        {/* 工具：统计 / SSH Agent / 钱包 / 安全瞭望 / 生成器 */}
        {rail ? (
          <div className="mt-2 flex flex-col items-center gap-0.5">{toolRows}</div>
        ) : (
          <>
            {groupHeader('tools', 'sidebar.group.tools')}
            {groupOpen('tools') && <div className="space-y-0.5">{toolRows}</div>}
          </>
        )}
      </nav>

      {/* 底部操作区：收起/展开 + 设置 + 锁定（title 只做快捷键提示，不参与可访问名） */}
      <div
        data-testid="sidebar-footer"
        className={clsx(
          'flex items-center gap-1 border-t border-secondary-200 dark:border-gray-800',
          rail ? 'w-full flex-col px-1 py-2' : 'px-2 py-2',
        )}
      >
        <button
          type="button"
          data-testid="sidebar-toggle"
          title={rail ? t('sidebar.expand') : t('sidebar.collapse')}
          aria-label={rail ? t('sidebar.expand') : t('sidebar.collapse')}
          className="flex h-8 w-8 items-center justify-center rounded-md text-secondary-700 transition-colors hover:bg-secondary-100 dark:text-secondary-300 dark:hover:bg-white/5"
          onClick={toggleSidebarCollapsed}
        >
          {rail ? (
            <ChevronDoubleRightIcon className="h-4 w-4 shrink-0 text-secondary-400" aria-hidden="true" />
          ) : (
            <ChevronDoubleLeftIcon className="h-4 w-4 shrink-0 text-secondary-400" aria-hidden="true" />
          )}
        </button>
        <button
          type="button"
          className={clsx(
            'flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] text-secondary-700 transition-colors hover:bg-secondary-100 dark:text-secondary-300 dark:hover:bg-white/5',
            rail ? 'w-8 justify-center px-0' : 'flex-1',
          )}
          aria-label={t('sidebar.settings')}
          title={t('sidebar.settingsTitle')}
          onClick={onOpenSettings}
        >
          <Cog6ToothIcon className="h-4 w-4 shrink-0 text-secondary-400" aria-hidden="true" />
          {!rail && <span className="truncate">{t('sidebar.settings')}</span>}
        </button>
        <button
          type="button"
          className={clsx(
            'flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] text-secondary-700 transition-colors hover:bg-red-50 hover:text-red-700 dark:text-secondary-300 dark:hover:bg-red-500/10 dark:hover:text-red-300',
            rail ? 'w-8 justify-center px-0' : 'flex-1',
          )}
          aria-label={t('sidebar.lock')}
          title={t('sidebar.lockTitle')}
          onClick={onLock}
        >
          <LockClosedIcon className="h-4 w-4 shrink-0 text-secondary-400" aria-hidden="true" />
          {!rail && <span className="truncate">{t('sidebar.lock')}</span>}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
