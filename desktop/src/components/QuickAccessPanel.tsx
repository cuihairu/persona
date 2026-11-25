import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { MagnifyingGlassIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import toast, { Toaster } from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { listen } from '@tauri-apps/api/event';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useReauth } from '@/hooks/useReauth';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import { credentialTypeLabel, getCredentialIcon } from './credentialDisplay';
import FaviconImg from './FaviconImg';
import Highlight from './Highlight';
import ReauthModal from './ReauthModal';
import type { ApiResponse, Credential, DesktopFillResult, Identity, SecretField } from '@/types';

/** Backend wake event (quick_access.rs OPENED_EVENT): on hotkey launch, clear the query and re-probe unlock state */
const OPENED_EVENT = 'persona://quick-access-opened';
/** Lock event (emitted both by a main-window lock and auto-lock expiry): the floating panel hides immediately */
const AUTO_LOCK_EVENT = 'persona://auto-lock';
/** Fires the backend search only after a 200ms typing pause (same as QuickSearch: local SQLite LIKE) */
const DEBOUNCE_MS = 200;

/**
 * Credential type -> the sensitive field Enter copies.
 *
 * Covers only the combinations the backend `extract_secret_field` actually supports
 * (Password / ApiKey / SshKey / CryptoWallet); the remaining types (bank cards,
 * identities, licenses, SecureNote...) have no single-field reveal entry in the
 * detail pane to begin with, so null is returned here -- the pane only offers
 * "copy username / copy TOTP / open in Persona", it does not pretend to fetch ciphertext.
 */
const primarySecretField = (type: string): SecretField | null => {
  switch (type) {
    case 'Password':
      return 'password';
    case 'ApiKey':
      return 'api_key';
    case 'SshKey':
      return 'ssh_private_key';
    case 'CryptoWallet':
      return 'wallet_private_key';
    default:
      return null;
  }
};

/** Bucket hits under each identity, following the identities order (within a group the backend created_at DESC order is kept) */
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

/** In a non-Tauri environment (jest/jsdom) getCurrentWindow throws synchronously, so the hide action degrades to a no-op */
const hideSelf = async () => {
  try {
    await getCurrentWindow().hide();
  } catch {
    // jsdom / non-Tauri environments: __TAURI_INTERNALS__ is missing
  }
};

/**
 * Quick Access floating panel (comparison matrix #22): cross-identity search surface summoned by an OS-level global hotkey.
 *
 * Keys (matching the i18n hint lines):
 * - Up/Down to move, Enter copies the primary secret (falls back to copying the username when there is no secret field)
 * - Cmd/Ctrl+U copies the username, Cmd/Ctrl+T copies the TOTP, Cmd/Ctrl+O opens in Persona
 * - Esc hides
 *
 * The locked state deliberately does **not reproduce the unlock flow** (a small window crammed with the
 * unlock screen plus the biometric prompt is a poor experience, and cross-window session sync would need a
 * separate channel): it only surfaces a hint and pulls the main window to the foreground.
 */
const QuickAccessPanel: React.FC = () => {
  const { t } = useTranslation();
  const { isUnlocked, searchCredentials, checkServiceStatus } = usePersonaService();
  const identities = useAppStore((s) => s.identities);
  const reauth = useReauth();

  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Credential[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);
  /**
   * Desktop-fill confirmation surface (security review P1): shows the target app name
   * (executable file name) plus the window title before injection; injection happens
   * only after the user explicitly confirms. null = no injection awaiting confirmation.
   * `snapshotId` is the snapshot identifier captured at probe time (P1 confirmation binding)
   * -- handed back to the backend unchanged after confirmation, and if the target is
   * re-captured or the panel is hidden while a request is in flight it is refused honestly,
   * never switched to a new target.
   */
  const [fillConfirm, setFillConfirm] = useState<{
    credential: Credential;
    app: string;
    title: string;
    snapshotId: string;
  } | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const searchRef = useRef(searchCredentials);
  searchRef.current = searchCredentials;
  const checkRef = useRef(checkServiceStatus);
  checkRef.current = checkServiceStatus;

  const groups = useMemo(() => groupByIdentity(results, identities), [results, identities]);
  const flatResults = useMemo(() => groups.flatMap((group) => group.items), [groups]);
  const active = flatResults[Math.min(activeIndex, Math.max(flatResults.length - 1, 0))];

  const reset = useCallback(() => {
    setQuery('');
    setResults([]);
    setIsSearching(false);
    setActiveIndex(0);
    setCopied(null);
    setFillConfirm(null);
  }, []);

  // Wake channel: every hotkey launch must re-probe unlock state (the main window's
  // unlock/lock is never delivered to this window as an event, and the store exists once
  // per window) + clear the previous query
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    try {
      const pending = listen(OPENED_EVENT, () => {
        void checkRef.current();
        reset();
        // Focus one frame later: only after show() does the webview receive keyboard focus
        window.setTimeout(() => inputRef.current?.focus(), 50);
      });
      // The rejection handler swallows listen failures in non-Tauri environments (as in useQuickAccessBridge)
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // Non-Tauri environments have no listen
    }
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [reset]);

  // Lock (including a main-window lock and auto-lock expiry) -> the panel hides immediately, leaving no search results on screen
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    try {
      const pending = listen(AUTO_LOCK_EVENT, () => {
        void hideSelf();
      });
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // Non-Tauri environments have no listen
    }
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Debounced search; an empty query clears results and issues no request
  useEffect(() => {
    const trimmed = query.trim();
    if (!isUnlocked || !trimmed) {
      setResults([]);
      setIsSearching(false);
      return;
    }
    setIsSearching(true);
    // After the query changes an old response may land later and overwrite the new one: the cleanup flag marks it stale to discard expired results.
    let stale = false;
    const timer = window.setTimeout(async () => {
      const res = await searchRef.current(trimmed);
      if (stale) return;
      setResults(res);
      setIsSearching(false);
    }, DEBOUNCE_MS);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [query, isUnlocked]);

  /** Reveal and copy a sensitive field; REAUTH_REQUIRED goes through ReauthModal for one retry */
  const copySecret = useCallback(
    async (credential: Credential, field: SecretField) => {
      const reveal = async (): Promise<string | null> => {
        const res = await personaAPI.revealCredentialSecret(credential.id, field);
        if (res.success && res.data) return res.data.value;
        if (res.error_code === 'REAUTH_REQUIRED') {
          if (await reauth.requestReauth()) return reveal();
          return null;
        }
        if (res.error_code === 'SERVICE_LOCKED') {
          toast.error(t('common.serviceLocked'));
          return null;
        }
        toast.error(res.error ?? t('reveal.failed'));
        return null;
      };

      const value = await reveal();
      if (value === null) return;
      await copyToClipboardWithToast(value, t('quickAccess.password'));
      setCopied(`${credential.id}:${field}`);
      window.setTimeout(() => setCopied(null), 2000);
    },
    [reauth, t],
  );

  const copyUsername = useCallback(
    (credential: Credential) => {
      if (!credential.username) {
        toast.error(t('app.noUsername'));
        return;
      }
      void copyToClipboardWithToast(credential.username, t('app.username'));
      setCopied(`${credential.id}:username`);
      window.setTimeout(() => setCopied(null), 2000);
    },
    [t],
  );

  const copyTotp = useCallback(
    async (credential: Credential) => {
      const res = await personaAPI.getTotpCode(credential.id);
      if (res.success && res.data) {
        await copyToClipboardWithToast(res.data.code, t('quickAccess.totp'));
        setCopied(`${credential.id}:totp`);
        window.setTimeout(() => setCopied(null), 2000);
      } else {
        toast.error(res.error ?? t('svc.totpFailed'));
      }
    },
    [t],
  );

  const openInPersona = useCallback(
    async (credential: Credential) => {
      const res = await personaAPI.quickAccessOpenCredential(credential.identity_id, credential.id);
      if (!res.success) {
        toast.error(res.error ?? t('quickAccess.openFailed'));
      }
    },
    [t],
  );

  /**
   * In-app desktop fill injection (#12) -- a **two-step confirmation flow** (tightened by security review P1):
   * step one (requestFill) probes the injection target and raises the confirmation surface: the panel shows the
   * target app name (executable file name) and window title and captures a snapshot identifier; only after the
   * user explicitly confirms does step two call the backend with `confirmed=true` + `snapshot_id` -- the
   * confirmation is bound to the specific snapshot, and the backend honestly refuses unconfirmed / target-changed /
   * target-discarded calls.
   * On success the panel auto-hides -- focus returns to the target window and the user sees the filled fields.
   */
  const requestFill = useCallback(
    async (credential: Credential) => {
      const status = await personaAPI.fillTargetStatus();
      if (
        !status.success ||
        !status.data?.ready ||
        !status.data.supported ||
        !status.data.snapshot_id
      ) {
        toast.error(t('quickAccess.fillNoTarget'));
        return;
      }
      setFillConfirm({
        credential,
        app: status.data.target_app ?? t('quickAccess.fillUnknownApp'),
        title: status.data.target_title ?? '',
        snapshotId: status.data.snapshot_id,
      });
    },
    [t],
  );

  const fillInTarget = useCallback(
    async (credential: Credential, snapshotId: string) => {
      const doFill = async (): Promise<ApiResponse<DesktopFillResult> | null> => {
        const res = await personaAPI.desktopFillCredential(credential.id, true, snapshotId);
        if (res.success) return res;
        if (res.error_code === 'REAUTH_REQUIRED') {
          if (await reauth.requestReauth()) return doFill();
          return null;
        }
        if (res.error_code === 'SERVICE_LOCKED') {
          toast.error(t('common.serviceLocked'));
          return null;
        }
        // Confirmation binding (P1): an in-flight request whose target changed or was discarded after confirmation --
        // report the reason honestly, prompt the user to redo the confirmation flow, never reuse the old confirmation
        if (res.error_code === 'FILL_TARGET_CHANGED') {
          toast.error(t('quickAccess.fillTargetChanged'));
          return null;
        }
        if (res.error_code === 'FILL_TARGET_DISCARDED') {
          toast.error(t('quickAccess.fillTargetDiscarded'));
          return null;
        }
        toast.error(res.error ?? t('quickAccess.fillFailed'));
        return null;
      };
      const res = await doFill();
      if (!res?.data) return;
      const d = res.data;
      if (d.username_filled && d.password_filled) {
        toast.success(t('quickAccess.fillDone', { target: d.target_title }));
      } else {
        toast(t('quickAccess.fillPartial', { target: d.target_title }));
      }
      setCopied(`${credential.id}:fill`);
      window.setTimeout(() => setCopied(null), 2000);
      void hideSelf();
    },
    [reauth, t],
  );

  /** Enter: copy the primary secret field first, falling back to copying the username (the pane does not guess at other secret fields) */
  const copyPrimary = useCallback(
    (credential: Credential) => {
      const field = primarySecretField(credential.credential_type);
      if (field) {
        void copySecret(credential, field);
      } else {
        copyUsername(credential);
      }
    },
    [copySecret, copyUsername],
  );

  const onKeyDown = (event: React.KeyboardEvent) => {
    // While the confirmation surface is open, intercept keyboard input: Esc cancels the fill confirmation, Enter confirms the fill
    if (fillConfirm) {
      event.preventDefault();
      if (event.key === 'Escape') {
        setFillConfirm(null);
      } else if (event.key === 'Enter') {
        const pending = fillConfirm;
        setFillConfirm(null);
        if (pending) void fillInTarget(pending.credential, pending.snapshotId);
      }
      return;
    }
    const total = flatResults.length;
    const mod = event.metaKey || event.ctrlKey;

    if (event.key === 'Escape') {
      event.preventDefault();
      void hideSelf();
      return;
    }
    if (!active) return;

    if (event.key === 'ArrowDown' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index + 1) % total);
    } else if (event.key === 'ArrowUp' && total > 0) {
      event.preventDefault();
      setActiveIndex((index) => (index - 1 + total) % total);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      copyPrimary(active);
    } else if (mod && event.key.toLowerCase() === 'u') {
      // Cmd+U does not clash with the input's native behavior (Cmd+C conflicts with text selection, so it is not used)
      event.preventDefault();
      copyUsername(active);
    } else if (mod && event.key.toLowerCase() === 't') {
      event.preventDefault();
      void copyTotp(active);
    } else if (mod && event.key.toLowerCase() === 'o') {
      event.preventDefault();
      void openInPersona(active);
    } else if (mod && event.key.toLowerCase() === 'f') {
      // Cmd+F desktop fill: probe the target first and raise the confirmation surface (only Password credentials;
      // the backend cannot fill username/password for the other types)
      event.preventDefault();
      if (active.credential_type === 'Password') {
        void requestFill(active);
      } else {
        toast.error(t('quickAccess.fillPasswordOnly'));
      }
    }
  };

  if (!isUnlocked) {
    return (
      <div
        className="h-screen w-screen bg-white dark:bg-gray-900 flex flex-col items-center justify-center gap-3 px-6 text-center"
        data-testid="quick-access-locked"
      >
        <LockClosedIcon className="w-8 h-8 text-gray-400 dark:text-gray-500" />
        <p className="text-sm text-gray-600 dark:text-gray-300">{t('quickAccess.lockedHint')}</p>
        <button
          type="button"
          data-testid="quick-access-unlock-button"
          onClick={() => void personaAPI.focusMainWindow()}
          className="whitespace-nowrap rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-4 py-2"
        >
          {t('quickAccess.openMainWindow')}
        </button>
        <Toaster position="top-center" toastOptions={{ className: 'persona-toast' }} />
      </div>
    );
  }

  return (
    <div
      className="relative h-screen w-screen bg-white dark:bg-gray-900 flex flex-col overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700"
      onKeyDown={onKeyDown}
      data-testid="quick-access-panel"
    >
      <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-200 dark:border-gray-700 shrink-0">
        <MagnifyingGlassIcon className="w-4 h-4 shrink-0 text-gray-400 dark:text-gray-500" />
        <input
          ref={inputRef}
          type="text"
          autoFocus
          data-testid="quick-access-input"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActiveIndex(0);
          }}
          placeholder={t('quickAccess.inputPlaceholder')}
          className="w-full bg-transparent outline-none text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500"
        />
      </div>

      <div className="flex-1 overflow-y-auto py-1" data-testid="quick-access-results">
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
                  const isActive = index === activeIndex;
                  const TypeIcon = getCredentialIcon(credential.credential_type);
                  return (
                    <button
                      key={credential.id}
                      type="button"
                      data-testid="quick-access-item"
                      data-active={isActive}
                      onClick={() => setActiveIndex(index)}
                      onDoubleClick={() => copyPrimary(credential)}
                      onMouseEnter={() => setActiveIndex(index)}
                      className={`whitespace-nowrap w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
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
                      {credential.username && (
                        <span className="text-xs text-gray-400 dark:text-gray-500 truncate max-w-[35%]">
                          <Highlight text={credential.username} query={query} />
                        </span>
                      )}
                      <span className="ml-auto flex items-center gap-2 shrink-0">
                        {isActive && primarySecretField(credential.credential_type) && (
                          <kbd className="text-[10px] text-gray-400 dark:text-gray-500">↵</kbd>
                        )}
                        {isActive && (
                          <kbd className="text-[10px] text-gray-400 dark:text-gray-500">⌘O</kbd>
                        )}
                        {copied === `${credential.id}:password` ||
                        copied === `${credential.id}:api_key` ||
                        copied === `${credential.id}:ssh_private_key` ||
                        copied === `${credential.id}:wallet_private_key` ? (
                          <span className="text-[10px] text-green-600 dark:text-green-400">
                            {t('quickAccess.copied')}
                          </span>
                        ) : null}
                        <span className="text-xs text-gray-400 dark:text-gray-500">
                          {credentialTypeLabel(t, credential.credential_type)}
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            ));
          })()
        )}
      </div>

      <div
        className="px-4 py-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-400 dark:text-gray-500 shrink-0 flex items-center gap-3"
        data-testid="quick-access-hints"
      >
        <span>{t('quickAccess.hintCopy')}</span>
        <span>{t('quickAccess.hintUsername')}</span>
        <span>{t('quickAccess.hintTotp')}</span>
        <span>{t('quickAccess.hintOpen')}</span>
        <span data-testid="quick-access-hint-fill">{t('quickAccess.hintFill')}</span>
      </div>

      {fillConfirm && (
        <div
          className="absolute inset-0 bg-black/40 flex items-center justify-center p-4 z-10"
          data-testid="quick-access-fill-confirm"
        >
          <div className="w-full max-w-sm bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('quickAccess.fillConfirmTitle')}
            </p>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-300 break-words">
              {t('quickAccess.fillConfirmBody', {
                app: fillConfirm.app,
                title: fillConfirm.title,
              })}
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                data-testid="quick-access-fill-cancel"
                onClick={() => setFillConfirm(null)}
                className="whitespace-nowrap rounded-md px-3 py-1.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                {t('quickAccess.fillCancel')}
              </button>
              <button
                type="button"
                data-testid="quick-access-fill-confirm-button"
                autoFocus
                onClick={() => {
                  const pending = fillConfirm;
                  setFillConfirm(null);
                  if (pending) void fillInTarget(pending.credential, pending.snapshotId);
                }}
                className="rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-3 py-1.5"
              >
                {t('quickAccess.fillConfirmButton')}
              </button>
            </div>
          </div>
        </div>
      )}
      <ReauthModal
        isOpen={reauth.isOpen}
        error={reauth.error}
        isVerifying={reauth.isVerifying}
        onSubmit={reauth.submit}
        onClose={reauth.cancel}
      />
      <Toaster position="top-center" toastOptions={{ className: 'persona-toast' }} />
    </div>
  );
};

export default QuickAccessPanel;
