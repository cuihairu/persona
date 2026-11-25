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

/** Filter criteria (an empty dimension = no filtering; multiple dimensions AND together) */
export interface CredentialFilter {
  query?: string;
  /** Selected type set (empty = all types) */
  types?: Set<string>;
  /** Selected tag set (empty = all tags) */
  tags?: Set<string>;
  /** Selected identity (empty/absent = entries of the current identity) */
  identityId?: string;
  favoritesOnly?: boolean;
}

/** Filter the credential list locally (a pure function, for unit testing) */
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
 * Left column of the main area: the entry list (with inline copy). Search lives
 * in the sidebar's big search box (writing the same store field); this component
 * only owns the "current filter → result set → selection" chain. The detail pane
 * is rendered to the right of the list by the parent (App), which watches the
 * store selection; hidden below the lg breakpoint.
 */
const CredentialList: React.FC<CredentialListProps> = ({ onCreateCredential }) => {
  const { t } = useTranslation();
  const { credentials, currentIdentity } = usePersonaService();
  // Batch-prefetch favicons for the list page when the flag is on (pure cache reads; a miss never triggers a fetch)
  useFavicons(credentials.map((c) => c.url));
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  const identities = useAppStore((s) => s.identities);
  // The search term lives in the store (see the appStore comment): updated in the same batch as selection/sidebar filters, avoiding injected intermediate frames
  const searchQuery = useAppStore((s) => s.credentialSearchQuery);
  const setCredentialSearchQuery = useAppStore((s) => s.setCredentialSearchQuery);
  const pendingSelection = useAppStore((s) => s.pendingCredentialSelection);
  const clearPendingCredentialSelection = useAppStore((s) => s.clearPendingCredentialSelection);
  const selectedCredentialId = useAppStore((s) => s.selectedCredentialId);
  const setSelectedCredentialId = useAppStore((s) => s.setSelectedCredentialId);

  // Selection is lifted into the store (global ⌘E copy-username needs it), derived from the list
  const selectedCredential = useMemo(
    () => credentials.find((c) => c.id === selectedCredentialId) ?? null,
    [credentials, selectedCredentialId],
  );

  // Sidebar filter (single-select) → pure CredentialFilter derivation; the search term stacks on top independently (AND)
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
        // The tools/passkeys views do not render this component
        return {};
    }
  }, [sidebarFilter]);

  const filteredCredentials = useMemo(() => {
    const result = filterCredentials(credentials, { query: searchQuery, ...treeFilter });
    // "Recently used" is a sort view, not a filter: most recently accessed first, never-accessed sinks to the bottom
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
    // Selection is written straight into the store (global ⌘E copy-username needs
    // it); detail data is loaded centrally by App watching the store selection, so
    // no IPC happens here (avoids double fetching)
    setSelectedCredentialId(credential.id);
  };

  // After switching identity the old selection dangles: clear the right-pane selection and the search term
  useEffect(() => {
    setSelectedCredentialId(null);
    setCredentialSearchQuery('');
  }, [currentIdentity?.id, setSelectedCredentialId, setCredentialSearchQuery]);

  // When a filter (search term / sidebar category) change makes the selection
  // invisible, clear the detail pane: 1Password semantics — filtering is a
  // navigation action and does not keep a detail disconnected from the result set
  const isSelectionVisible =
    !selectedCredentialId ||
    filteredCredentials.some((c) => c.id === selectedCredentialId);
  useEffect(() => {
    if (!isSelectionVisible) {
      setSelectedCredentialId(null);
    }
  }, [isSelectionVisible, selectedCredentialId, setSelectedCredentialId]);

  // Global-search cross-identity navigation: once the target identity's credentials
  // are ready, inject the selection and clear pending (declared after the
  // clear-selection effect; async credential loading re-triggers this effect)
  useEffect(() => {
    if (!pendingSelection || pendingSelection.identityId !== currentIdentity?.id) return;
    const target = credentials.find((c) => c.id === pendingSelection.credentialId);
    if (!target) {
      // The list already belongs to the target identity (checked via the first
      // element, ruling out the intermediate state where an identity switch has not
      // yet replaced the old list) but the target is not in it (deleted): void the
      // pending to prevent leftovers
      if (credentials.length > 0 && credentials[0].identity_id === pendingSelection.identityId) {
        clearPendingCredentialSelection();
      }
      return;
    }
    // Clear the local search term and sidebar filter so the jump target is visible
    // (otherwise the injected selection is immediately cleared by the
    // "filter hides selection → clear" effect above)
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
      {/* List header: current filter name + count + create (a 1Password-style header) */}
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

      {/* Entry rows: single column, compact, and selecting fills the whole row */}
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
                // The row holds an inline copy button, and nested <button> is disallowed: li role="button" + keyboard handling
                <li
                  key={credential.id}
                  role="button"
                  tabIndex={0}
                  aria-current={selected ? 'true' : undefined}
                  data-testid={`credential-row-${credential.id}`}
                  onClick={() => handleCredentialClick(credential)}
                  onKeyDown={(e) => {
                    // Do not trigger selection while focus is on the inline copy button
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
