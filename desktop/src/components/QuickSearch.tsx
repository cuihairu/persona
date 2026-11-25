import { useEffect, useMemo, useRef, useState } from 'react';
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import { credentialTypeLabel, getCredentialIcon } from './credentialDisplay';
import FaviconImg from './FaviconImg';
import Highlight from './Highlight';
import { useFavicons } from '@/hooks/useFavicons';
import type { Credential, Identity } from '@/types';

/** Only issue the backend search after a 200ms typing pause (a local SQLite LIKE query, nothing longer is needed) */
const DEBOUNCE_MS = 200;

/** Attribute the hits to each identity in identities order (within a group keep the backend created_at DESC order) */
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
 * Global quick search (⌘K / top-bar entry): searches credentials across
 * identities, grouping the results by identity. Clicking a result writes
 * pendingCredentialSelection (switching identity along the way when it crosses
 * identities), and CredentialList injects the selection and opens the detail
 * panel.
 */
const QuickSearch = () => {
  const { t } = useTranslation();
  const { searchCredentials, switchIdentity, currentIdentity } = usePersonaService();
  const identities = useAppStore((s) => s.identities);
  const setPendingCredentialSelection = useAppStore((s) => s.setPendingCredentialSelection);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Credential[]>([]);
  // Prefetch favicons for the result page when the flag is on (closing the overlay does not affect cache reuse)
  useFavicons(results.map((c) => c.url));
  const [isSearching, setIsSearching] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  const searchRef = useRef(searchCredentials);
  searchRef.current = searchCredentials;

  // ⌘K / Ctrl+K opens globally (the component is only mounted inside the post-unlock workspace, so there is naturally no listener while locked)
  useGlobalShortcut('k', () => setOpen(true));

  // Debounced search; an empty query clears the results without sending a request
  useEffect(() => {
    const trimmed = query.trim();
    if (!open || !trimmed) {
      setResults([]);
      setIsSearching(false);
      return;
    }
    setIsSearching(true);
    // Debounce cleanup cannot cancel the in-flight await: after the query changes a
    // late response from the old query would overwrite the new results. cleanup
    // flips stale and discards the expired result (React's standard
    // stale-request guard).
    let stale = false;
    const timer = setTimeout(async () => {
      const res = await searchRef.current(trimmed);
      if (stale) return;
      setResults(res);
      setIsSearching(false);
    }, DEBOUNCE_MS);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
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
    // silent: the navigation target is the entry the user clicked, and a
    // "Switched to ..." toast would only cover up the navigation itself
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
        aria-label={t('quickSearch.search')}
        onClick={() => setOpen(true)}
        className="whitespace-nowrap flex items-center gap-2 rounded-md border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 px-3 py-1.5 text-sm text-gray-400 dark:text-gray-500 hover:border-gray-300 dark:hover:border-gray-600 hover:text-gray-500 dark:hover:text-gray-400 transition-colors"
      >
        <MagnifyingGlassIcon className="w-4 h-4" />
        <span>{t('quickSearch.searchHint')}</span>
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
                placeholder={t('quickSearch.inputPlaceholder')}
                className="w-full py-3 text-sm bg-transparent outline-none text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500"
              />
            </div>

            <div className="max-h-80 overflow-y-auto py-2" data-testid="quick-search-results">
              {!query.trim() ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  {t('quickSearch.typeToSearch')}
                </p>
              ) : isSearching && groups.length === 0 ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  {t('quickSearch.searching')}
                </p>
              ) : groups.length === 0 ? (
                <p className="px-4 py-8 text-center text-sm text-gray-400 dark:text-gray-500">
                  {t('quickSearch.noResults', { query: query.trim() })}
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
                              <Highlight text={credential.name} query={query} />
                            </span>
                            <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0">
                              {credentialTypeLabel(t, credential.credential_type)}
                            </span>
                            {credential.username && (
                              <span className="ml-auto text-xs text-gray-400 dark:text-gray-500 truncate max-w-[40%]">
                                <Highlight text={credential.username} query={query} />
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
              {t('quickSearch.shortcuts')}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default QuickSearch;
