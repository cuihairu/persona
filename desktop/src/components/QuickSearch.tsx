import { useEffect, useMemo, useRef, useState } from 'react';
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import { getCredentialIcon } from './credentialDisplay';
import FaviconImg from './FaviconImg';
import { useFavicons } from '@/hooks/useFavicons';
import type { Credential, Identity } from '@/types';

/** 输入停顿 200ms 才发起后端搜索（本地 SQLite LIKE 查询，无需更长） */
const DEBOUNCE_MS = 200;

/** 按 identities 顺序把命中结果归到各身份名下（组内保持后端 created_at DESC 序） */
const groupByIdentity = (
  results: Credential[],
  identities: Identity[],
): { identity: Identity; items: Credential[] }[] => {
  const byIdentity = new Map<string, Credential[]>();
  for (const cred of results) {
    const list = byIdentity.get(cred.identity_id) ?? [];
    list.push(cred);
    byIdentity.set(cred.identity_id, list);
  }
  return identities
    .map((identity) => ({ identity, items: byIdentity.get(identity.id) ?? [] }))
    .filter((group) => group.items.length > 0);
};

/**
 * 全局快速搜索（⌘K / 顶栏入口）：跨身份搜索凭据，结果按身份分组。
 * 点击结果 → 写入 pendingCredentialSelection（跨身份则顺带 switchIdentity），
 * 由 CredentialList 注入选中并打开详情面板。
 */
const QuickSearch = () => {
  const { searchCredentials, switchIdentity, currentIdentity } = usePersonaService();
  const identities = useAppStore((s) => s.identities);
  const setPendingCredentialSelection = useAppStore((s) => s.setPendingCredentialSelection);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Credential[]>([]);
  // flag 开时预取结果页 favicon（overlay 关闭也不影响缓存复用）
  useFavicons(results.map((c) => c.url));
  const [isSearching, setIsSearching] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  const searchRef = useRef(searchCredentials);
  searchRef.current = searchCredentials;

  // ⌘K / Ctrl+K 全局打开（组件只挂在解锁后的 workspace 内，锁定态天然无监听）
  useGlobalShortcut('k', () => setOpen(true));

  // debounce 搜索；空查询直接清结果不发请求
  useEffect(() => {
    const trimmed = query.trim();
    if (!open || !trimmed) {
      setResults([]);
      setIsSearching(false);
      return;
    }
    setIsSearching(true);
    const timer = setTimeout(async () => {
      setResults(await searchRef.current(trimmed));
      setIsSearching(false);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query, open]);

  const groups = useMemo(() => groupByIdentity(results, identities), [results, identities]);
  const flatResults = useMemo(() => groups.flatMap((group) => group.items), [groups]);

  const close = () => {
    setOpen(false);
    setQuery('');
    setResults([]);
    setIsSearching(false);
    setActiveIndex(0);
  };

  const openCredential = (credential: Credential) => {
    close();
    if (credential.identity_id === currentIdentity?.id) {
      setPendingCredentialSelection({
        identityId: credential.identity_id,
        credentialId: credential.id,
      });
      return;
    }
    const target = identities.find((identity) => identity.id === credential.identity_id);
    if (!target) return;
    setPendingCredentialSelection({
      identityId: credential.identity_id,
      credentialId: credential.id,
    });
    // silent：跳转目标是用户点击的条目，"Switched to ..." toast 只会盖住跳转本身
    switchIdentity(target, { silent: true });
  };

  const handleContainerKeyDown = (event: React.KeyboardEvent) => {
    const total = flatResults.length;
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
    } else if (event.key === 'ArrowDown' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index + 1) % total);
    } else if (event.key === 'ArrowUp' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index - 1 + total) % total);
    } else if (event.key === 'Enter' && total > 0) {
      event.preventDefault();
      openCredential(flatResults[Math.min(activeIndex, total - 1)]);
    }
  };

  return (
    <div className="ml-auto" onKeyDown={handleContainerKeyDown}>
      <button
        type="button"
        data-testid="quick-search-trigger"
        aria-label="Search"
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 rounded-md border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-400 dark:text-gray-500 hover:border-gray-300 dark:hover:border-gray-600 hover:text-gray-500 dark:hover:text-gray-400 transition-colors"
      >
        <MagnifyingGlassIcon className="w-4 h-4" />
        <span>Search...</span>
        <kbd className="text-xs font-medium text-gray-400 dark:text-gray-500">⌘K</kbd>
      </button>

      {open && (
        <div
          data-testid="quick-search-overlay"
          className="fixed inset-0 z-50 bg-black/50 flex items-start justify-center p-4 pt-[12vh]"
          onMouseDown={close}
        >
          <div
            className="w-full max-w-xl bg-white dark:bg-gray-900 rounded-lg shadow-xl overflow-hidden"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center gap-3 px-4 border-b border-gray-200 dark:border-gray-700">
              <MagnifyingGlassIcon className="w-4 h-4 shrink-0 text-gray-400 dark:text-gray-500" />
              <input
                type="text"
                data-testid="quick-search-input"
                autoFocus
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setActiveIndex(0);
                }}
                placeholder="Search all identities..."
                className="w-full py-3 text-sm bg-transparent outline-none text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500"
              />
            </div>

            <div className="max-h-80 overflow-y-auto py-2" data-testid="quick-search-results">
              {!query.trim() ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  Type to search across all identities
                </p>
              ) : isSearching && groups.length === 0 ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  Searching...
                </p>
              ) : groups.length === 0 ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  No results for &quot;{query.trim()}&quot;
                </p>
              ) : (
                (() => {
                  let flatIndex = -1;
                  return groups.map((group) => (
                    <div key={group.identity.id}>
                      <div className="px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
                        {group.identity.name}
                      </div>
                      {group.items.map((credential) => {
                        flatIndex += 1;
                        const index = flatIndex;
                        const TypeIcon = getCredentialIcon(credential.credential_type);
                        const isActive = index === activeIndex;
                        return (
                          <button
                            key={credential.id}
                            type="button"
                            data-testid="quick-search-item"
                            data-active={isActive}
                            onClick={() => openCredential(credential)}
                            onMouseEnter={() => setActiveIndex(index)}
                            className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                              isActive
                                ? 'bg-primary-50 dark:bg-primary-500/10'
                                : 'hover:bg-gray-50 dark:hover:bg-gray-800'
                            }`}
                          >
                            <FaviconImg
                              url={credential.url}
                              fallbackIcon={TypeIcon}
                              sizeClass="w-4 h-4"
                              className="text-gray-400 dark:text-gray-500"
                            />
                            <span className="text-sm text-gray-900 dark:text-gray-100 truncate">
                              {credential.name}
                            </span>
                            <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0">
                              {credential.credential_type}
                            </span>
                            {credential.username && (
                              <span className="ml-auto text-xs text-gray-400 dark:text-gray-500 truncate max-w-[40%]">
                                {credential.username}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  ));
                })()
              )}
            </div>

            <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-400 dark:text-gray-500">
              ↑↓ navigate · Enter open · Esc close
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default QuickSearch;
