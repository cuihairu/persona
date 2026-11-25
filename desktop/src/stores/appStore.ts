import { create } from 'zustand';
import type {
  Identity,
  Credential,
  CredentialData,
  SshAgentStatus,
  SshAgentKey,
  FeatureFlags,
  FaviconData,
  ThemePreference,
  SidebarFilter,
  PendingCredentialSelection,
} from '@/types';
import { readStoredTheme } from '@/utils/theme';
import { readSidebarPrefs, writeSidebarPrefs, type SidebarGroupKey, type SidebarPrefs } from '@/utils/sidebarPrefs';

/** Out-of-box advanced feature flags: 1Password-style, all off by default, fetched from workspace settings after unlock */
export const DEFAULT_FEATURE_FLAGS: FeatureFlags = {
  ssh_agent: false,
  wallet: false,
  passkeys: false,
  fetch_favicons: false,
};

/** favicon cache entry (host level; data is base64, rendered by building a data: URL) */
export interface FaviconEntry {
  mime_type: string;
  data: string;
}

/** Out-of-box sidebar category filter: all entries (reset back to this on identity switch) */
export const DEFAULT_SIDEBAR_FILTER: SidebarFilter = { kind: 'all' };

interface AppState {
  // Authentication state
  isUnlocked: boolean;
  isInitialized: boolean;

  // Data state
  identities: Identity[];
  currentIdentity: Identity | null;
  credentials: Credential[];
  sshAgentStatus: SshAgentStatus | null;
  sshKeys: SshAgentKey[];
  featureFlags: FeatureFlags;

  // UI state
  isLoading: boolean;
  error: string | null;
  /** Set when init returns PASSWORD_CHANGE_REQUIRED: the unlock screen renders the forced password-change modal */
  passwordChangeRequired: boolean;
  /** Theme preference ('system' follows the OS; useTheme is the sole application site for <html>.dark) */
  theme: ThemePreference;
  /** Selected sidebar category (single choice; written by Sidebar, read by CredentialList, reset on identity switch) */
  sidebarFilter: SidebarFilter;
  /** Sidebar collapsed as a whole (icon rail form; persisted in localStorage across sessions) */
  sidebarCollapsed: boolean;
  /** Keys of groups collapsed inside the sidebar (category/vault/tag/tool; persisted the same way) */
  collapsedSidebarGroups: SidebarGroupKey[];
  /** Local search query for the credential list (read/written by CredentialList; cleared on identity switch/lock).
   *  Lives in the store rather than component state: a pending injection must land in the same batch as the
   *  selection and sidebar filter, since React state lagging a frame creates an intermediate frame where the
   *  selection is set but the query is not cleared, which wrongly trips the selection-clear effect */
  credentialSearchQuery: string;
  /** Pending credential selection to inject (written by QuickSearch, cleared once CredentialList consumes it) */
  pendingCredentialSelection: PendingCredentialSelection | null;
  /** Currently selected credential id (CredentialList derives the detail object from it; cleared on lock) */
  selectedCredentialId: string | null;
  /** Credential being edited (null = none; written by DetailPane, consumed by the App-level CreateCredentialModal.
   *  data is the payload already decrypted when the pane opened; null = could not be fetched (fields left blank for re-entry) */
  editingCredential: { credential: Credential; data: CredentialData | null } | null;
  /** favicon cache (host -> entry; hits are rendered, cleared on lock but not on identity switch -- shared across identities) */
  faviconCache: Record<string, FaviconEntry>;
  /** favicon negative cache: hosts missed by a batch read, to avoid duplicate IPC (dropped after a successful fetch) */
  faviconMisses: Record<string, true>;

  // Actions
  setUnlocked: (unlocked: boolean) => void;
  setInitialized: (initialized: boolean) => void;
  setIdentities: (identities: Identity[]) => void;
  setCurrentIdentity: (identity: Identity | null) => void;
  setCredentials: (credentials: Credential[]) => void;
  setSshAgentStatus: (status: SshAgentStatus | null) => void;
  setSshKeys: (keys: SshAgentKey[]) => void;
  setFeatureFlags: (flags: FeatureFlags) => void;
  setTheme: (theme: ThemePreference) => void;
  setSidebarFilter: (filter: SidebarFilter) => void;
  resetSidebarFilter: () => void;
  toggleSidebarCollapsed: () => void;
  toggleSidebarGroup: (key: SidebarGroupKey) => void;
  setCredentialSearchQuery: (query: string) => void;
  setPendingCredentialSelection: (selection: PendingCredentialSelection) => void;
  clearPendingCredentialSelection: () => void;
  setSelectedCredentialId: (id: string | null) => void;
  setEditingCredential: (editing: { credential: Credential; data: CredentialData | null } | null) => void;
  /** Merge favicon cache entries in bulk, dropping the hit hosts from the negative cache */
  setFaviconEntries: (entries: FaviconData[]) => void;
  /** Mark hosts missed by a batch read (ignore ones already cached) */
  setFaviconMisses: (hosts: string[]) => void;
  /** Clear the favicon cache and negative cache (called on lock) */
  clearFaviconCache: () => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
  setPasswordChangeRequired: (required: boolean) => void;
}

const initialSidebarPrefs: SidebarPrefs = readSidebarPrefs();

export const useAppStore = create<AppState>((set) => ({
  // Initial state
  isUnlocked: false,
  isInitialized: false,
  identities: [],
  currentIdentity: null,
  credentials: [],
  sshAgentStatus: null,
  sshKeys: [],
  featureFlags: { ...DEFAULT_FEATURE_FLAGS },
  isLoading: false,
  error: null,
  passwordChangeRequired: false,
  theme: readStoredTheme(),
  sidebarFilter: DEFAULT_SIDEBAR_FILTER,
  sidebarCollapsed: initialSidebarPrefs.collapsed,
  collapsedSidebarGroups: initialSidebarPrefs.collapsedGroups,
  credentialSearchQuery: '',
  pendingCredentialSelection: null,
  selectedCredentialId: null,
  editingCredential: null,
  faviconCache: {},
  faviconMisses: {},

  // Actions
  setUnlocked: (unlocked) => set({ isUnlocked: unlocked }),
  setInitialized: (initialized) => set({ isInitialized: initialized }),
  setIdentities: (identities) => set({ identities }),
  setCurrentIdentity: (identity) => set({ currentIdentity: identity }),
  setCredentials: (credentials) => set({ credentials }),
  setSshAgentStatus: (status) => set({ sshAgentStatus: status }),
  setSshKeys: (keys) => set({ sshKeys: keys }),
  setFeatureFlags: (flags) => set({ featureFlags: { ...flags } }),
  setTheme: (theme) => set({ theme }),
  setSidebarFilter: (filter) => set({ sidebarFilter: filter }),
  resetSidebarFilter: () => set({ sidebarFilter: DEFAULT_SIDEBAR_FILTER }),
  toggleSidebarCollapsed: () =>
    set((s) => {
      const sidebarCollapsed = !s.sidebarCollapsed;
      writeSidebarPrefs({ collapsed: sidebarCollapsed, collapsedGroups: s.collapsedSidebarGroups });
      return { sidebarCollapsed };
    }),
  toggleSidebarGroup: (key: SidebarGroupKey) =>
    set((s) => {
      const collapsedSidebarGroups = s.collapsedSidebarGroups.includes(key)
        ? s.collapsedSidebarGroups.filter((k) => k !== key)
        : [...s.collapsedSidebarGroups, key];
      writeSidebarPrefs({ collapsed: s.sidebarCollapsed, collapsedGroups: collapsedSidebarGroups });
      return { collapsedSidebarGroups };
    }),
  setCredentialSearchQuery: (query) => set({ credentialSearchQuery: query }),
  setPendingCredentialSelection: (selection) => set({ pendingCredentialSelection: selection }),
  clearPendingCredentialSelection: () => set({ pendingCredentialSelection: null }),
  setSelectedCredentialId: (id) => set({ selectedCredentialId: id }),
  setEditingCredential: (editing) => set({ editingCredential: editing }),
  setFaviconEntries: (entries) =>
    set((state) => {
      const faviconCache = { ...state.faviconCache };
      const faviconMisses = { ...state.faviconMisses };
      for (const entry of entries) {
        faviconCache[entry.host] = { mime_type: entry.mime_type, data: entry.data };
        delete faviconMisses[entry.host];
      }
      return { faviconCache, faviconMisses };
    }),
  setFaviconMisses: (hosts) =>
    set((state) => {
      const faviconMisses = { ...state.faviconMisses };
      for (const host of hosts) {
        // Hosts already cached do not go into the negative cache (a cache hit beats a stale miss)
        if (!(host in state.faviconCache)) {
          faviconMisses[host] = true;
        }
      }
      return { faviconMisses };
    }),
  clearFaviconCache: () => set({ faviconCache: {}, faviconMisses: {} }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),
  setPasswordChangeRequired: (required) => set({ passwordChangeRequired: required }),
}));
