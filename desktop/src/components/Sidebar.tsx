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
  /** The sidebar is the only navigation source: clicking a node writes the store filter state first, then the callback notifies App (identity switches and other side effects) */
  onNavigate: (filter: SidebarFilter) => void;
  /** Passed through to the IdentitySwitcher dropdown's "Create new identity" */
  onCreateIdentity?: () => void;
  onOpenSettings: () => void;
  onLock: () => void;
}

interface RowProps {
  label: string;
  icon: NavNode['icon'];
  active: boolean;
  onClick: () => void;
  /** Numeric badge; undefined = not shown (the badge is hidden from screen readers, keeping the row name clean) */
  count?: number;
  testId: string;
  /** Icon-rail mode: icon only, with tooltip/aria falling back to the row name */
  rail?: boolean;
}

/** Sidebar row: icon + name + count with compact row height (1Password-style single-row selection block) */
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

/** Group header (categories / vaults / tags / tools); clicking collapses/expands the whole group */
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
 * Global left sidebar (1Password-style): identity switcher and large search
 * box on top → top three rows (All Items / Favorites / Recently Used) →
 * categories → vaults (identities) → tags → tools; settings and lock at the
 * bottom. The whole column can collapse into an icon rail (freeing width for
 * the main area in narrow windows), and each of the four groups can collapse
 * independently; both preferences persist to localStorage. The column scrolls
 * independently, with breathing room between groups.
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

  // Counting convention: the store's credentials are the entries loaded for the current identity
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
    // Search is only meaningful in the list view: switch back to All Items when currently in a tool/admin panel
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
        // Only badge when entries are loaded: the store holds just the current
        // identity's entries, so other vaults stay blank rather than showing a
        // misleading 0
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

  // element (not a component): identityIcon returns an icon component during
  // render, and JSX-ifying it directly trips react-hooks/static-components
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
      {/* Top: identity switcher + large search box (mirroring 1Password's account row and search); icon-rail mode keeps only the identity icon */}
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
        {/* Top three rows: All Items / Favorites / Recently Used (not part of group collapsing) */}
        <div className={clsx('space-y-0.5 pt-2', rail && 'flex flex-col items-center')}>
          {topRows}
        </div>

        {/* Categories: 1Password's item categories (passkeys point to a standalone admin view, no list count) */}
        {rail ? (
          <div className="mt-2 flex flex-col items-center gap-0.5">{categoryRows}</div>
        ) : (
          <>
            {groupHeader('categories', 'sidebar.group.categories')}
            {groupOpen('categories') && <div className="space-y-0.5">{categoryRows}</div>}
          </>
        )}

        {/* Vaults: a persona identity = a 1Password vault; clicking switches the current identity */}
        {identities.length > 0 &&
          (rail ? (
            <div className="mt-2 flex flex-col items-center gap-0.5">{vaultRows}</div>
          ) : (
            <>
              {groupHeader('vaults', 'sidebar.group.vaults')}
              {groupOpen('vaults') && <div className="space-y-0.5">{vaultRows}</div>}
            </>
          ))}

        {/* Tags */}
        {availableTags.length > 0 &&
          (rail ? (
            <div className="mt-2 flex flex-col items-center gap-0.5">{tagRows}</div>
          ) : (
            <>
              {groupHeader('tags', 'sidebar.group.tags')}
              {groupOpen('tags') && <div className="space-y-0.5">{tagRows}</div>}
            </>
          ))}

        {/* Tools: Statistics / SSH Agent / Wallets / Watchtower / Generator */}
        {rail ? (
          <div className="mt-2 flex flex-col items-center gap-0.5">{toolRows}</div>
        ) : (
          <>
            {groupHeader('tools', 'sidebar.group.tools')}
            {groupOpen('tools') && <div className="space-y-0.5">{toolRows}</div>}
          </>
        )}
      </nav>

      {/* Bottom action area: collapse/expand + settings + lock (title only hints at shortcuts, not part of the accessible name) */}
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
          <Cog6ToothIcon className="whitespace-nowrap h-4 w-4 shrink-0 text-secondary-400" aria-hidden="true" />
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
