import React, { useEffect, useMemo, useRef, useState } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { KeyIcon, UserGroupIcon, ShieldCheckIcon, StarIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import i18n, { normalizeLocale } from '@/i18n';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { useAutoLockEvents } from '@/hooks/useAutoLockEvents';
import { useQuickAccessBridge } from '@/hooks/useQuickAccessBridge';
import { useSshApprovals } from '@/hooks/useSshApprovals';
import { usePasskeyApprovals } from '@/hooks/usePasskeyApprovals';
import { useTheme } from '@/hooks/useTheme';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import { checkForUpdate, isUpdateCheckEnabled } from '@/utils/updateCheck';
import { trayLocaleLabels } from '@/utils/trayLocale';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import UnlockScreen from '@/components/UnlockScreen';
import { CreateIdentityModal } from '@/components/IdentitySwitcher';
import CredentialList from '@/components/CredentialList';
import CredentialDetailPane from '@/components/CredentialDetailPane';
import CreateCredentialModal from '@/components/CreateCredentialModal';
import { ErrorBoundary, ErrorDisplay, LoadingSpinner } from '@/components/ErrorHandling';
import SshApprovalModal from '@/components/SshApprovalModal';
import PasskeyApprovalModal from '@/components/PasskeyApprovalModal';
import UnlockGateModal from '@/components/UnlockGateModal';
import SshAgentPanel from '@/components/SshAgentPanel';
import WalletPanel from '@/components/WalletPanel';
import WatchtowerPanel from '@/components/WatchtowerPanel';
import PasskeyPanel from '@/components/PasskeyPanel';
import GeneratorPanel from '@/components/GeneratorPanel';
import SettingsModal from '@/components/SettingsModal';
import QuickSearch from '@/components/QuickSearch';
import Sidebar from '@/components/Sidebar';
import {
  ALL_ITEMS_FILTER,
  FLAG_BY_VIEW,
  filterLabel,
  viewForFilter,
} from '@/components/sidebarNav';
import type { SidebarFilter } from '@/components/sidebarNav';
import { credentialTypeLabel, securityLevelLabel } from '@/components/credentialDisplay';

/** Toast styling shared by both Toasters (locked state / main UI); colors come from the .persona-toast CSS variables and flip with the theme */
const TOAST_OPTIONS = { className: 'persona-toast' };

const App: React.FC = () => {
  // Theme wiring: preference -> <html>.dark + localStorage + native window theme (mounted before the early-return)
  useTheme();
  const { t } = useTranslation();

  const {
    isUnlocked,
    currentIdentity,
    error,
    isLoading,
    lockService,
    loadCredentialsForIdentity,
    switchIdentity,
    getCredentialData,
    clearError,
  } = usePersonaService();

  // Language preference restore: get_workspace_settings is readable without
  // unlocking, so it takes effect during the lock screen; skipped when already
  // unlocked at mount (the unlock path's settings read below the flags effect
  // applies the locale too), avoiding duplicate workspace settings calls in the
  // same frame. On read failure, silently keep the default zh-CN.
  useEffect(() => {
    if (isUnlocked) {
      return;
    }
    (async () => {
      try {
        const resp = await personaAPI.getWorkspaceSettings();
        if (resp.success && resp.data) {
          const next = normalizeLocale(resp.data.locale);
          await i18n.changeLanguage(next);
          // The tray context menu is a native menu and does not honor
          // useTranslation: push the locale table's values to the backend for
          // rendering. Use the global i18n.t (it reads the current language at call
          // time) — a component-level t is a getFixedT snapshot and still speaks the
          // old language after a switch.
          void personaAPI.setTrayLocale(trayLocaleLabels((key) => i18n.t(key)));
        }
      } catch {
        // keep default
      }
    })();
    // Decide the initial locked state only at mount (the effect references only module-level imports, no reactive deps)
  }, []);

  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const setSidebarFilter = useAppStore((s) => s.setSidebarFilter);
  const identities = useAppStore((s) => s.identities);
  // Credential being edited (written by the DetailPane Edit button; consumed by the modal, null = create mode)
  const editingCredential = useAppStore((s) => s.editingCredential);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);
  // Detail pane: the selected id lives in the store (shared by the list / ⌘E / global search), and data is loaded centrally here
  const credentials = useAppStore((s) => s.credentials);
  const selectedCredentialId = useAppStore((s) => s.selectedCredentialId);
  const setSelectedCredentialId = useAppStore((s) => s.setSelectedCredentialId);
  const selectedCredential = useMemo(
    () => credentials.find((c) => c.id === selectedCredentialId) ?? null,
    [credentials, selectedCredentialId],
  );
  const [credentialData, setCredentialData] = useState<any>(null);
  // The hook is not useCallback'd, so a ref holds the latest load function: the
  // effect depends only on the selected id, avoiding a refetch on every render
  const loadCredentialDataRef = useRef(getCredentialData);
  loadCredentialDataRef.current = getCredentialData;
  useEffect(() => {
    let cancelled = false;
    setCredentialData(null);
    if (!selectedCredentialId) return;
    void loadCredentialDataRef.current(selectedCredentialId).then((data) => {
      if (!cancelled) setCredentialData(data);
    });
    return () => {
      cancelled = true;
    };
  }, [selectedCredentialId]);

  const [showCreateIdentity, setShowCreateIdentity] = useState(false);
  const [showCreateCredential, setShowCreateCredential] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Navigation has a single source of truth: sidebar filter state -> the main-area view (tools/passkeys are panes, everything else is a list)
  const currentView = viewForFilter(sidebarFilter);

  // ⌘L to lock: App stays mounted, and enabled=isUnlocked guarantees the lock
  // screen has no listener. Also fixes an existing edge: modals open before
  // locking would auto-reopen after unlock (App never unmounts and the local bool
  // survives), so reset them together when locking.
  const handleLock = () => {
    setShowCreateIdentity(false);
    setShowCreateCredential(false);
    setShowSettings(false);
    setEditingCredential(null);
    void lockService();
  };
  useGlobalShortcut('l', handleLock, isUnlocked);

  // ⌘, toggles the settings modal
  useGlobalShortcut(',', () => setShowSettings((v) => !v), isUnlocked);

  // ⌘G opens the password generator (a main-path view; generating is pure computation and needs no selected identity)
  useGlobalShortcut('g', () => setSidebarFilter({ kind: 'generator' }), isUnlocked);

  // ⌘E copies the current selection's username (reads the store at keypress time: no subscription, no stale closure)
  const handleCopyUsername = () => {
    const { credentials, selectedCredentialId, currentIdentity } = useAppStore.getState();
    const selected = credentials.find((c) => c.id === selectedCredentialId);
    // No selection / a dangling selection (switching identity while parked on another view can leave a cross-identity id) both surface as "nothing selected"
    if (!selected || (currentIdentity && selected.identity_id !== currentIdentity.id)) {
      toast.error(t('app.selectEntryFirst'));
      return;
    }
    if (!selected.username) {
      toast.error(t('app.noUsername'));
      return;
    }
    void copyToClipboardWithToast(selected.username, t('app.username'));
  };
  useGlobalShortcut('e', handleCopyUsername, isUnlocked);

  // Auto-lock event stream: the lock_pending countdown banner + locked returns to the unlock screen (handled inside the hook)
  const { pendingSeconds } = useAutoLockEvents(isUnlocked);

  // Quick Access floating window's cross-window navigation (floating window -> main window switches identity + selects the entry)
  useQuickAccessBridge();

  // SSH signature approval queue: a dialog when the embedded agent asks for confirmation (Allow/Deny)
  const { pending: pendingApproval, pendingCount, respond } = useSshApprovals(isUnlocked);

  // Passkey approval queue: a dialog for create/assert requests relayed by the bridge (Allow/Deny)
  const {
    pending: pendingPasskeyApproval,
    pendingCount: pendingPasskeyCount,
    respond: respondPasskey,
  } = usePasskeyApprovals(isUnlocked);

  // SERVICE_LOCKED guided unlock: when an invoke gate hits a lazy auto-lock, the
  // unlock dialog appears and the suspended original operation retries
  // automatically after unlocking (utils/api requestUnlockGate).
  // No stacked dialog while the frontend is already on the unlock screen (store
  // isUnlocked=false) — the unlock screen itself is the guidance.
  const [unlockGateOpen, setUnlockGateOpen] = useState(false);
  const unlockGateResolveRef = useRef<((unlocked: boolean) => void) | null>(null);
  useEffect(() => {
    const onNeedUnlock = (e: Event) => {
      const detail = (e as CustomEvent).detail as { resolve: (unlocked: boolean) => void };
      if (!useAppStore.getState().isUnlocked) {
        detail.resolve(false);
        return;
      }
      unlockGateResolveRef.current = detail.resolve;
      setUnlockGateOpen(true);
    };
    window.addEventListener('persona:need-unlock', onNeedUnlock);
    return () => window.removeEventListener('persona:need-unlock', onNeedUnlock);
  }, []);
  const resolveUnlockGate = (unlocked: boolean) => {
    setUnlockGateOpen(false);
    unlockGateResolveRef.current?.(unlocked);
    unlockGateResolveRef.current = null;
  };

  // Start the backend auto-lock monitor after unlock, stop it after lock
  useEffect(() => {
    if (isUnlocked) {
      personaAPI.startAutoLockMonitoring().catch(() => {});
    } else {
      personaAPI.stopAutoLockMonitoring().catch(() => {});
    }
  }, [isUnlocked]);

  // Check for a version update once at startup per build channel (can be turned
  // off in settings; dev builds do not compare).
  // i18n.t reads the current language at callback time, so a language switch
  // needs no re-query.
  useEffect(() => {
    if (!isUpdateCheckEnabled()) return;
    void checkForUpdate()
      .then((outcome) => {
        if (outcome.status === 'update-available') {
          toast(
            i18n.t('settings.updateCheck.availableToast', {
              version: outcome.latestVersion ?? '',
            }),
            { duration: 8000, className: TOAST_OPTIONS.className },
          );
        }
      })
      .catch(() => {});
  }, []);

  // Fetch workspace feature flags after unlock; fall back to defaults (all off)
  // while locked. On read failure, silently keep the defaults: the unlock flow is
  // never interrupted by a settings read.
  useEffect(() => {
    if (!isUnlocked) {
      setFeatureFlags({ ...DEFAULT_FEATURE_FLAGS });
      return;
    }
    (async () => {
      try {
        const resp = await personaAPI.getWorkspaceSettings();
        if (resp.success && resp.data) {
          setFeatureFlags(resp.data.features);
          // The same read also refreshes the language preference (settings can
          // change across unlocks; idempotent) and re-pushes the tray context
          // menu copy (the native menu only honors pushed values; the global
          // i18n.t picks up the switched language, while a component-level t is
          // an old-language snapshot)
          const next = normalizeLocale(resp.data.locale);
          await i18n.changeLanguage(next);
          void personaAPI.setTrayLocale(trayLocaleLabels((key) => i18n.t(key)));
        }
      } catch {
        // keep defaults
      }
    })();
  }, [isUnlocked, setFeatureFlags]);

  // When a flag the current view depends on turns off, fall back to all entries (the sidebar entry disappears too, so the UI never sits on an unreachable view)
  useEffect(() => {
    const flag = FLAG_BY_VIEW[currentView];
    if (flag && !featureFlags[flag]) {
      setSidebarFilter(ALL_ITEMS_FILTER);
    }
  }, [currentView, featureFlags, setSidebarFilter]);

  // Clicking the vault in the sidebar = switch the current identity (the identity is the vault; entries load per identity)
  const handleNavigate = (filter: SidebarFilter) => {
    if (filter.kind === 'identity') {
      const targetIdentity = identities.find((i) => i.id === filter.value);
      if (targetIdentity) {
        void switchIdentity(targetIdentity);
      }
    }
  };

  // Load credentials when identity changes
  useEffect(() => {
    if (currentIdentity) {
      loadCredentialsForIdentity(currentIdentity.id);
    }
    // Switching identity drops the old category-tree selection (the new identity may not have that type/tag anymore)
    resetSidebarFilter();
  }, [currentIdentity]);

  // The fullscreen spinner is only for startup checks / unlock-screen
  // initialization. Post-unlock write operations also share the global isLoading
  // (gate unlocks, create/edit entry, etc.); if the main UI were torn down here,
  // remounting would trip CredentialList's "dangling selection gets cleared"
  // effect and wipe the user's selection — guided unlocks mid-operation
  // (UnlockGateModal) are exactly the unlocked-state path, so the page context
  // must stay intact.
  if (isLoading && !isUnlocked) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center">
        <LoadingSpinner message={t('app.initializing')} />
      </div>
    );
  }

  // Show unlock screen if not unlocked
  if (!isUnlocked) {
    return (
      <ErrorBoundary>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
          {error && (
            <div className="p-4">
              <ErrorDisplay
                error={error}
                type="error"
                onDismiss={clearError}
              />
            </div>
          )}
          <UnlockScreen onUnlock={() => {}} />
          <Toaster position="top-right" toastOptions={TOAST_OPTIONS} />
        </div>
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      {/* app shell: fixed viewport height; scrolling lives in the sidebar's and main column's own inner containers */}
      <div className="h-screen flex flex-col overflow-hidden bg-gray-50 dark:bg-gray-950">
        {/* Auto-lock countdown banner */}
        {pendingSeconds !== null && (
          <div
            data-testid="auto-lock-banner"
            className="bg-amber-50 dark:bg-amber-500/10 border-b border-amber-200 dark:border-amber-500/20 px-4 py-2 text-center text-sm text-amber-800 dark:text-amber-300"
          >
            {t('app.autoLockBanner', { seconds: pendingSeconds })}
          </div>
        )}

        {/* Global error display */}
        {error && (
          <div className="p-4">
            <ErrorDisplay
              error={error}
              type="error"
              onDismiss={clearError}
            />
          </div>
        )}

        <div className="flex min-h-0 flex-1">
          <Sidebar
            onNavigate={handleNavigate}
            onCreateIdentity={() => setShowCreateIdentity(true)}
            onOpenSettings={() => setShowSettings(true)}
            onLock={handleLock}
          />

          {/* Main column: toolbar (current node title + global search) + an independently scrolling main area */}
          <div className="flex min-w-0 flex-1 flex-col bg-background dark:bg-gray-950">
            <div className="flex h-12 shrink-0 items-center gap-3 border-b border-secondary-200 px-4 dark:border-gray-800">
              <h1
                data-testid="view-title"
                className="truncate text-sm font-semibold text-secondary-900 dark:text-secondary-50"
              >
                {filterLabel(t, sidebarFilter, identities)}
              </h1>
              <QuickSearch />
            </div>

            {currentView === 'credentials' ? (
              <main className="min-h-0 flex-1 overflow-hidden p-4">
                <div className="mx-auto flex h-full max-w-7xl overflow-hidden rounded-lg border border-secondary-200 bg-white dark:border-gray-800 dark:bg-gray-900">
                  <div className="flex h-full min-w-0 flex-1 flex-col">
                    <CredentialList onCreateCredential={() => setShowCreateCredential(true)} />
                  </div>
                  {/* Detail pane column: placeholder when nothing is selected; hidden below lg, details omitted in the mobile layout */}
                  <div className="hidden w-[360px] shrink-0 overflow-y-auto border-l border-secondary-200 dark:border-gray-800 lg:block">
                    {selectedCredential ? (
                      <CredentialDetailPane
                        credential={selectedCredential}
                        credentialData={credentialData}
                        onClose={() => {
                          setSelectedCredentialId(null);
                          setCredentialData(null);
                        }}
                        onCopy={copyToClipboardWithToast}
                      />
                    ) : (
                      <div
                        data-testid="detail-placeholder"
                        className="flex h-full items-center justify-center p-6 text-secondary-400 dark:text-secondary-500"
                      >
                        <div className="text-center">
                          <KeyIcon className="mx-auto mb-3 h-10 w-10 text-secondary-300 dark:text-secondary-600" />
                          <p>{t('credList.selectItem')}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </main>
            ) : (
              <main className="min-h-0 flex-1 overflow-y-auto">
                <div className="mx-auto max-w-7xl px-4 py-6">
                  {currentView === 'statistics' && <StatisticsView />}
                  {currentView === 'sshAgent' && <SshAgentPanel />}
                  {currentView === 'wallets' && <WalletPanel />}
                  {currentView === 'watchtower' && <WatchtowerPanel />}
                  {currentView === 'passkeys' && <PasskeyPanel />}
                  {currentView === 'generator' && <GeneratorPanel />}
                </div>
              </main>
            )}
          </div>
        </div>

        {/* Modals */}
        <CreateIdentityModal
          isOpen={showCreateIdentity}
          onClose={() => setShowCreateIdentity(false)}
        />

        <CreateCredentialModal
          isOpen={showCreateCredential || editingCredential !== null}
          editCredential={editingCredential}
          onClose={() => {
            setShowCreateCredential(false);
            setEditingCredential(null);
          }}
        />

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
        />

        {/* SSH signature approval dialog */}
        <SshApprovalModal
          request={pendingApproval}
          pendingCount={pendingCount}
          onRespond={respond}
        />

        {/* Passkey approval dialog (bridge request) */}
        <PasskeyApprovalModal
          request={pendingPasskeyApproval}
          pendingCount={pendingPasskeyCount}
          onRespond={respondPasskey}
        />

        {/* SERVICE_LOCKED guided unlock (lazy auto-lock race) */}
        <UnlockGateModal isOpen={unlockGateOpen} onResolve={resolveUnlockGate} />

        {/* Toast Notifications */}
        <Toaster position="top-right" toastOptions={TOAST_OPTIONS} />
      </div>
    </ErrorBoundary>
  );
};

const StatisticsView: React.FC = () => {
  const { t } = useTranslation();
  const [statistics, setStatistics] = useState<any>(null);

  useEffect(() => {
    // Load statistics when component mounts
    loadStatistics();
  }, []);

  const loadStatistics = async () => {
    try {
      const response = await import('@/utils/api').then(module =>
        module.personaAPI.getStatistics()
      );
      if (response.success && response.data) {
        setStatistics(response.data);
      }
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  };

  if (!statistics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.title')}</h2>
      </div>

      {/* Overview Cards — the icons are chrome, not data: one neutral ink color
          plus semantic glyphs, no decorative multi-color blocks (dataviz: color
          follows data entities only, and state colors stay reserved for state). */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg mr-4">
              <UserGroupIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.totalIdentities')}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.total_identities}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg mr-4">
              <KeyIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.totalCredentials')}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.total_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg mr-4">
              <ShieldCheckIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.activeCredentials')}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.active_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg mr-4">
              <StarIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.favorites')}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.favorite_credentials}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Credential Types Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.credentialTypes')}</h3>
          <div className="space-y-3">
            {Object.entries(statistics.credential_types).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{credentialTypeLabel(t, type)}</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{count as number}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.securityLevels')}</h3>
          <div className="space-y-3">
            {Object.entries(statistics.security_levels).map(([level, count]) => (
              <div key={level} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{securityLevelLabel(t, level)}</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
