import { create } from 'zustand';
import type {
  Identity,
  Credential,
  SshAgentStatus,
  SshAgentKey,
  FeatureFlags,
  ThemePreference,
} from '@/types';
import { readStoredTheme } from '@/utils/theme';

/** 高级功能开关出厂值：1Password 式默认全关，解锁后从 workspace settings 拉取 */
export const DEFAULT_FEATURE_FLAGS: FeatureFlags = {
  ssh_agent: false,
  wallet: false,
  passkeys: false,
};

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
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),
}));
