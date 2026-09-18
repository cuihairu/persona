import React, { useEffect, useState } from 'react';
import {
  KeyIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  DocumentDuplicateIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { Credential } from '@/types';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { copyWithAutoClear } from '@/utils/clipboard';
import { getCredentialIcon, getSecurityColor, getSafeHostname } from './credentialDisplay';
import CredentialDetailPane from './CredentialDetailPane';

/** 筛选条件（各维度为空 = 不过滤；多维度之间 AND） */
export interface CredentialFilter {
  query?: string;
  /** 选中类型集合（空 = 全部类型） */
  types?: Set<string>;
  /** 选中标签集合（空 = 全部标签） */
  tags?: Set<string>;
  favoritesOnly?: boolean;
}

/** 本地筛选凭据列表（纯函数，便于单测） */
export const filterCredentials = (
  credentials: Credential[],
  { query, types, tags, favoritesOnly }: CredentialFilter,
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
    const matchesFavorite = !favoritesOnly || cred.is_favorite;
    return matchesQuery && matchesType && matchesTag && matchesFavorite;
  });

interface CredentialListProps {
  onCreateCredential: () => void;
}

/**
 * 1Password 8 式双栏主视图：左侧条目列表（行内复制），右侧常驻详情面板。
 * 窄屏（<lg）退化为单列堆叠，面板出现在列表下方。
 */
const CredentialList: React.FC<CredentialListProps> = ({ onCreateCredential }) => {
  const { credentials, currentIdentity, getCredentialData } = usePersonaService();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [selectedCredential, setSelectedCredential] = useState<Credential | null>(null);
  const [credentialData, setCredentialData] = useState<any>(null);

  // 聚合当前身份下的全部类型/标签（去重排序）
  const availableTypes = Array.from(new Set(credentials.map((c) => c.credential_type))).sort();
  const availableTags = Array.from(new Set(credentials.flatMap((c) => c.tags))).sort();

  const hasActiveFilters =
    selectedTypes.size > 0 || selectedTags.size > 0 || favoritesOnly;

  const clearFilters = () => {
    setSelectedTypes(new Set());
    setSelectedTags(new Set());
    setFavoritesOnly(false);
  };

  const toggleInSet = (set: Set<string>, value: string): Set<string> => {
    const next = new Set(set);
    if (next.has(value)) {
      next.delete(value);
    } else {
      next.add(value);
    }
    return next;
  };

  const filteredCredentials = filterCredentials(credentials, {
    query: searchQuery,
    types: selectedTypes,
    tags: selectedTags,
    favoritesOnly,
  });

  const handleCredentialClick = async (credential: Credential) => {
    // 先清空旧数据再选中：同一批 setState，面板首帧即新条目 + loading，不闪现上一条
    setCredentialData(null);
    setSelectedCredential(credential);
    const data = await getCredentialData(credential.id);
    setCredentialData(data);
  };

  // 切身份后旧选中项悬空：清空右栏选中
  useEffect(() => {
    setSelectedCredential(null);
    setCredentialData(null);
  }, [currentIdentity?.id]);

  const copyToClipboard = async (text: string, label: string) => {
    const ok = await copyWithAutoClear(text, 30_000);
    if (ok) {
      toast.success(`${label} copied (clears in 30s)`);
    } else {
      toast.error('Failed to copy to clipboard');
    }
  };

  if (!currentIdentity) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
        <div className="text-center">
          <KeyIcon className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
          <p>Select an identity to view credentials</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100">
            Credentials for {currentIdentity.name}
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {filteredCredentials.length} credential{filteredCredentials.length !== 1 ? 's' : ''}
          </p>
        </div>
        <button
          onClick={onCreateCredential}
          className="btn-primary flex items-center"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          Add Credential
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-gray-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="input pl-10"
          placeholder="Search credentials..."
        />
      </div>

      {/* Filters: type / tags / favorites */}
      {(availableTypes.length > 0 || availableTags.length > 0) && (
        <div className="flex flex-wrap items-center gap-2" data-testid="credential-filters">
          <button
            onClick={() => setFavoritesOnly(!favoritesOnly)}
            className={clsx(
              'px-2.5 py-1 text-xs font-medium rounded-full border transition-colors',
              favoritesOnly
                ? 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300 border-red-300 dark:border-red-500/40'
                : 'bg-white dark:bg-gray-900 text-gray-600 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800',
            )}
            data-testid="filter-favorites"
          >
            ♥ Favorites
          </button>

          {availableTypes.map((type) => (
            <button
              key={type}
              onClick={() => setSelectedTypes(toggleInSet(selectedTypes, type))}
              className={clsx(
                'px-2.5 py-1 text-xs font-medium rounded-full border transition-colors',
                selectedTypes.has(type)
                  ? 'bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-300 border-primary-300 dark:border-primary-500/40'
                  : 'bg-white dark:bg-gray-900 text-gray-600 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800',
              )}
              data-testid={`filter-type-${type}`}
            >
              {type}
            </button>
          ))}

          {availableTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setSelectedTags(toggleInSet(selectedTags, tag))}
              className={clsx(
                'px-2.5 py-1 text-xs rounded-full border transition-colors',
                selectedTags.has(tag)
                  ? 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-500/40'
                  : 'bg-white dark:bg-gray-900 text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800',
              )}
              data-testid={`filter-tag-${tag}`}
            >
              #{tag}
            </button>
          ))}

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="px-2.5 py-1 text-xs text-gray-500 dark:text-gray-400 underline hover:text-gray-700 dark:hover:text-gray-200"
              data-testid="clear-filters"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* 空态跨整宽；右栏不渲染（选中项保留在 state，清筛选后面板原样回来） */}
      {filteredCredentials.length === 0 ? (
        <div className="text-center py-12">
          <KeyIcon className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No credentials found</h3>
          <p className="text-gray-500 dark:text-gray-400 mb-4">
            {searchQuery ? 'Try adjusting your search terms' : 'Get started by adding your first credential'}
          </p>
          {!searchQuery && (
            <button onClick={onCreateCredential} className="btn-primary">
              Add Your First Credential
            </button>
          )}
        </div>
      ) : (
        <div className="lg:grid lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-6 lg:items-start">
          {/* 左列：条目列表 */}
          <div className="space-y-1.5 min-w-0">
            {filteredCredentials.map((credential) => {
              const IconComponent = getCredentialIcon(credential.credential_type);
              return (
                // 行内有行内复制按钮，禁用 <button> 嵌套：div role="button" + 键盘处理
                <div
                  key={credential.id}
                  role="button"
                  tabIndex={0}
                  data-testid={`credential-row-${credential.id}`}
                  onClick={() => handleCredentialClick(credential)}
                  onKeyDown={(e) => {
                    // 焦点在行内复制按钮上时不触发选中
                    if (e.target !== e.currentTarget) return;
                    if (e.key === 'Enter' || e.key === ' ') handleCredentialClick(credential);
                  }}
                  className={clsx(
                    'group flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer transition-colors',
                    selectedCredential?.id === credential.id
                      ? 'bg-primary-50 dark:bg-primary-500/10 border-primary-300 dark:border-primary-500/40'
                      : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800',
                  )}
                >
                  <div className="p-2 bg-primary-50 dark:bg-primary-500/10 rounded-lg shrink-0">
                    <IconComponent className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {credential.name}
                    </h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {credential.credential_type}
                      {credential.url && ' · '}
                      {credential.url && <span>{getSafeHostname(credential.url)}</span>}
                    </p>
                  </div>
                  {credential.is_favorite && (
                    <HeartSolidIcon className="w-4 h-4 text-red-500 shrink-0" />
                  )}
                  <span
                    className={clsx(
                      'px-2 py-0.5 text-xs font-medium rounded-full border shrink-0',
                      getSecurityColor(credential.security_level),
                    )}
                  >
                    {credential.security_level}
                  </span>
                  {credential.username && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(credential.username!, 'Username');
                      }}
                      className="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-800 opacity-0 focus:opacity-100 group-hover:opacity-100 shrink-0"
                      title="Copy username"
                      aria-label="Copy username"
                    >
                      <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* 右列：常驻详情面板或占位（窄屏下自然堆叠在列表下方） */}
          <div className="mt-4 lg:mt-0">
            {selectedCredential ? (
              <CredentialDetailPane
                credential={selectedCredential}
                credentialData={credentialData}
                onClose={() => {
                  setSelectedCredential(null);
                  setCredentialData(null);
                }}
                onCopy={copyToClipboard}
              />
            ) : (
              <div
                className="card p-6 flex items-center justify-center h-64 text-gray-400 dark:text-gray-500"
                data-testid="detail-placeholder"
              >
                <div className="text-center">
                  <KeyIcon className="w-10 h-10 mx-auto mb-3 text-gray-300 dark:text-gray-600" />
                  <p>Select an item to see details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default CredentialList;
