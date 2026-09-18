import { create } from 'zustand';
import type {
  Identity,
  Credential,
  SshAgentStatus,
  SshAgentKey,
  FeatureFlags,
  ThemePreference,
  SidebarFilter,
  PendingCredentialSelection,
} from '@/types';
import { readStoredTheme } from '@/utils/theme';

/** 高级功能开关出厂值：1Password 式默认全关，解锁后从 workspace settings 拉取 */
export const DEFAULT_FEATURE_FLAGS: FeatureFlags = {
  ssh_agent: false,
  wallet: false,
  passkeys: false,
};

/** 侧栏分类树出厂筛选：全部条目（换身份时 reset 回此值） */
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
  /** 主题偏好（'system' 跟随系统；<html>.dark 的唯一应用点是 useTheme） */
  theme: ThemePreference;
  /** 侧栏分类树选中项（单选；Sidebar 写、CredentialList 读，换身份时 reset） */
  sidebarFilter: SidebarFilter;
  /** 待注入的凭据选中项（QuickSearch 写、CredentialList 消费后清除） */
  pendingCredentialSelection: PendingCredentialSelection | null;

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
  setPendingCredentialSelection: (selection: PendingCredentialSelection) => void;
  clearPendingCredentialSelection: () => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
}

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
  theme: readStoredTheme(),
  sidebarFilter: DEFAULT_SIDEBAR_FILTER,
  pendingCredentialSelection: null,

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
  setPendingCredentialSelection: (selection) => set({ pendingCredentialSelection: selection }),
  clearPendingCredentialSelection: () => set({ pendingCredentialSelection: null }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),
}));
