import React, { useEffect, useMemo } from 'react';
import {
  KeyIcon,
  PlusIcon,
  DocumentDuplicateIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import type { Credential } from '@/types';
import { clsx } from 'clsx';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import {
  getCredentialIcon,
  getSecurityColor,
  getSafeHostname,
  credentialTypeLabel,
  securityLevelLabel,
} from './credentialDisplay';
import { CATEGORY_TYPES, filterLabel } from './sidebarNav';
import FaviconImg from './FaviconImg';
import { useFavicons } from '@/hooks/useFavicons';

/** 筛选条件（各维度为空 = 不过滤；多维度之间 AND） */
export interface CredentialFilter {
  query?: string;
  /** 选中类型集合（空 = 全部类型） */
  types?: Set<string>;
  /** 选中标签集合（空 = 全部标签） */
  tags?: Set<string>;
  /** 选中身份（空/缺省 = 当前身份的条目） */
  identityId?: string;
  favoritesOnly?: boolean;
}

/** 本地筛选凭据列表（纯函数，便于单测） */
export const filterCredentials = (
  credentials: Credential[],
  { query, types, tags, identityId, favoritesOnly }: CredentialFilter,
): Credential[] =>
  credentials.filter((cred) => {
    const q = (query ?? '').toLowerCase();
    const matchesQuery =
      !q ||
      cred.name.toLowerCase().includes(q) ||
      cred.credential_type.toLowerCase().includes(q);
    const matchesType = !types || types.size === 0 || types.has(cred.credential_type);
    const matchesTag =
      !tags || tags.size === 0 || cred.tags.some((t) => tags.has(t));
    const matchesIdentity = !identityId || cred.identity_id === identityId;
    const matchesFavorite = !favoritesOnly || cred.is_favorite;
    return matchesQuery && matchesType && matchesTag && matchesIdentity && matchesFavorite;
  });

interface CredentialListProps {
  onCreateCredential: () => void;
}

/**
 * 主区左栏：条目列表（行内复制）。搜索在侧栏大搜索框（写同一个 store 字段），
 * 本组件只负责"当前筛选 → 结果集 → 选中"这条链；详情面板由父级（App）
 * 监听 store 选中态渲染在列表右侧，窄屏（<lg）下隐藏。
 */
const CredentialList: React.FC<CredentialListProps> = ({ onCreateCredential }) => {
  const { t } = useTranslation();
  const { credentials, currentIdentity } = usePersonaService();
  // flag 开时批量预取列表页 favicon（纯缓存读；miss 不触发抓取）
  useFavicons(credentials.map((c) => c.url));
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  const identities = useAppStore((s) => s.identities);
  // 搜索词在 store（见 appStore 注释）：与选中/侧栏筛选同批更新，避免注入中间帧
  const searchQuery = useAppStore((s) => s.credentialSearchQuery);
  const setCredentialSearchQuery = useAppStore((s) => s.setCredentialSearchQuery);
  const pendingSelection = useAppStore((s) => s.pendingCredentialSelection);
  const clearPendingCredentialSelection = useAppStore((s) => s.clearPendingCredentialSelection);
  const selectedCredentialId = useAppStore((s) => s.selectedCredentialId);
  const setSelectedCredentialId = useAppStore((s) => s.setSelectedCredentialId);

  // 选中提升进 store（全局 ⌘E 复制用户名需要），对象从列表派生
  const selectedCredential = useMemo(
    () => credentials.find((c) => c.id === selectedCredentialId) ?? null,
    [credentials, selectedCredentialId],
  );

  // 侧栏筛选（单选）→ CredentialFilter 纯派生；搜索词独立叠加（AND）
  const treeFilter = useMemo<CredentialFilter>(() => {
    switch (sidebarFilter.kind) {
      case 'all':
      case 'recent':
        return {};
      case 'favorites':
        return { favoritesOnly: true };
      case 'category':
        return { types: new Set(CATEGORY_TYPES[sidebarFilter.value]) };
      case 'tag':
        return { tags: new Set([sidebarFilter.value]) };
      case 'identity':
        return { identityId: sidebarFilter.value };
      default:
        // 工具/通行密钥视图不渲染本组件
        return {};
    }
  }, [sidebarFilter]);

  const filteredCredentials = useMemo(() => {
    const result = filterCredentials(credentials, { query: searchQuery, ...treeFilter });
    // 「最近使用」是排序视图而不是筛选：最近访问过的在前，从未访问的沉底
    if (sidebarFilter.kind !== 'recent') return result;
    return [...result].sort((a, b) => {
      const at = a.last_accessed ? Date.parse(a.last_accessed) : null;
      const bt = b.last_accessed ? Date.parse(b.last_accessed) : null;
      if (at === bt) return a.name.localeCompare(b.name);
      if (at === null) return 1;
      if (bt === null) return -1;
      return bt - at;
    });
  }, [credentials, searchQuery, treeFilter, sidebarFilter.kind]);

  const handleCredentialClick = (credential: Credential) => {
    // 选中即写入 store（全局 ⌘E 复制用户名需要）；详情数据由 App 监听
    // store 选中变化统一加载，这里不再触碰 IPC（避免双取）
    setSelectedCredentialId(credential.id);
  };

  // 切身份后旧选中项悬空：清空右栏选中与搜索词
  useEffect(() => {
    setSelectedCredentialId(null);
    setCredentialSearchQuery('');
  }, [currentIdentity?.id, setSelectedCredentialId, setCredentialSearchQuery]);

  // 筛选（搜索词 / 侧栏分类）变化后选中项不再可见时清详情面板：
  // 1Password 语义——筛选是导航动作，不保留与结果集脱节的详情
  const isSelectionVisible =
    !selectedCredentialId ||
    filteredCredentials.some((c) => c.id === selectedCredentialId);
  useEffect(() => {
    if (!isSelectionVisible) {
      setSelectedCredentialId(null);
    }
  }, [isSelectionVisible, selectedCredentialId, setSelectedCredentialId]);

  // 全局搜索跨身份跳转：目标身份的凭据就绪后注入选中并清除 pending
  // （声明在清选中 effect 之后；凭据异步加载完成会再次触发本 effect）
  useEffect(() => {
    if (!pendingSelection || pendingSelection.identityId !== currentIdentity?.id) return;
    const target = credentials.find((c) => c.id === pendingSelection.credentialId);
    if (!target) {
      // 列表已归属目标身份（首元素校验，排除换身份后旧列表尚未替换的中间态）
      // 而目标不在其中（已删除）：pending 作废防残留
      if (credentials.length > 0 && credentials[0].identity_id === pendingSelection.identityId) {
        clearPendingCredentialSelection();
      }
      return;
    }
    // 清本地搜索词与侧栏筛选：保证跳转目标可见（否则注入的选中
    // 会被上面的"筛选不可见清选中"effect 立即清掉）
    setCredentialSearchQuery('');
    resetSidebarFilter();
    handleCredentialClick(target);
    clearPendingCredentialSelection();
  }, [pendingSelection, credentials, currentIdentity, clearPendingCredentialSelection, resetSidebarFilter, setCredentialSearchQuery]);

  if (!currentIdentity) {
    return (
      <div className="flex h-full items-center justify-center text-secondary-500 dark:text-secondary-400">
        <div className="text-center">
          <KeyIcon className="mx-auto mb-4 h-10 w-10 text-secondary-300 dark:text-secondary-600" />
          <p>{t('credList.selectIdentity')}</p>
        </div>
      </div>
    );
  }

  const title = filterLabel(t, sidebarFilter, identities);

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="credential-list">
      {/* 列表头：当前筛选名 + 计数 + 新建（1Password 式列表头） */}
      <div className="flex items-center gap-3 border-b border-secondary-200 px-4 py-2.5 dark:border-gray-800">
        <div className="min-w-0">
          <h2 className="truncate text-[15px] font-semibold text-secondary-900 dark:text-secondary-50">
            {title}
          </h2>
          <p className="text-xs text-secondary-500 dark:text-secondary-400">
            {t('credList.count', { count: filteredCredentials.length })}
          </p>
        </div>
        <button onClick={onCreateCredential} className="btn-primary ml-auto h-9 px-3">
          <PlusIcon className="mr-1.5 h-4 w-4" aria-hidden="true" />
          {t('credList.add')}
        </button>
      </div>

      {/* 条目行：单列、紧凑、选中即整行填充 */}
      <div
        className={clsx(
          'min-h-0 flex-1 overflow-y-auto p-2',
          filteredCredentials.length === 0 && 'flex flex-col',
        )}
      >
        {filteredCredentials.length === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center py-12 text-center">
            <KeyIcon className="mx-auto mb-4 h-10 w-10 text-secondary-300 dark:text-secondary-600" />
            <h3 className="mb-2 text-[15px] font-medium text-secondary-900 dark:text-secondary-100">
              {t('credList.noResults')}
            </h3>
            <p className="mb-4 text-secondary-500 dark:text-secondary-400">
              {searchQuery
                ? t('credList.tryAdjusting')
                : sidebarFilter.kind === 'all'
                  ? t('credList.getStarted')
                  : t('credList.tryCategory')}
            </p>
            {!searchQuery && sidebarFilter.kind === 'all' && (
              <button onClick={onCreateCredential} className="btn-primary h-9 px-3">
                {t('credList.addFirst')}
              </button>
            )}
          </div>
        ) : (
          <ul className="space-y-0.5">
            {filteredCredentials.map((credential) => {
              const IconComponent = getCredentialIcon(credential.credential_type);
              const selected = selectedCredential?.id === credential.id;
              return (
                // 行内有行内复制按钮，禁用 <button> 嵌套：li role="button" + 键盘处理
                <li
                  key={credential.id}
                  role="button"
                  tabIndex={0}
                  aria-current={selected ? 'true' : undefined}
                  data-testid={`credential-row-${credential.id}`}
                  onClick={() => handleCredentialClick(credential)}
                  onKeyDown={(e) => {
                    // 焦点在行内复制按钮上时不触发选中
                    if (e.target !== e.currentTarget) return;
                    if (e.key === 'Enter' || e.key === ' ') handleCredentialClick(credential);
                  }}
                  className={clsx(
                    'group flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 transition-colors',
                    selected
                      ? 'bg-primary-50 dark:bg-primary-500/15'
                      : 'hover:bg-secondary-100 dark:hover:bg-white/5',
                  )}
                >
                  <span
                    className={clsx(
                      'flex h-7 w-7 shrink-0 items-center justify-center rounded-md',
                      selected
                        ? 'bg-white text-primary-600 dark:bg-white/10 dark:text-primary-400'
                        : 'bg-secondary-100 text-secondary-600 dark:bg-white/5 dark:text-secondary-300',
                    )}
                  >
                    <FaviconImg
                      url={credential.url}
                      fallbackIcon={IconComponent}
                      className="h-4 w-4"
                    />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium text-secondary-900 dark:text-secondary-50">
                      {credential.name}
                    </span>
                    <span className="block truncate text-[11px] text-secondary-500 dark:text-secondary-400">
                      {credentialTypeLabel(t, credential.credential_type)}
                      {credential.url && ' · '}
                      {credential.url && <span>{getSafeHostname(credential.url)}</span>}
                    </span>
                  </span>
                  {credential.is_favorite && (
                    <HeartSolidIcon className="h-3.5 w-3.5 shrink-0 text-red-500" aria-hidden="true" />
                  )}
                  <span
                    className={clsx(
                      'shrink-0 rounded border px-1.5 py-px text-[10px] font-medium leading-4',
                      getSecurityColor(credential.security_level),
                    )}
                  >
                    {securityLevelLabel(t, credential.security_level)}
                  </span>
                  {credential.username && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        void copyToClipboardWithToast(credential.username!, t('app.username'));
                      }}
                      className="shrink-0 rounded p-1 text-secondary-400 opacity-0 transition-opacity hover:bg-secondary-200 hover:text-secondary-700 focus:opacity-100 group-hover:opacity-100 dark:hover:bg-white/10 dark:hover:text-secondary-200"
                      title={t('credList.copyUsername')}
                      aria-label={t('credList.copyUsername')}
                    >
                      <DocumentDuplicateIcon className="h-4 w-4" />
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
};

export default CredentialList;
