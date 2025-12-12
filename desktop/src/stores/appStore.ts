import { create } from 'zustand';
import type { Identity, Credential, SshAgentStatus, SshAgentKey } from '@/types';

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

  // UI state
  isLoading: boolean;
  error: string | null;

  // Actions
  setUnlocked: (unlocked: boolean) => void;
  setInitialized: (initialized: boolean) => void;
  setIdentities: (identities: Identity[]) => void;
  setCurrentIdentity: (identity: Identity | null) => void;
  setCredentials: (credentials: Credential[]) => void;
  setSshAgentStatus: (status: SshAgentStatus | null) => void;
  setSshKeys: (keys: SshAgentKey[]) => void;
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
  isLoading: false,
  error: null,

  // Actions
  setUnlocked: (unlocked) => set({ isUnlocked: unlocked }),
  setInitialized: (initialized) => set({ isInitialized: initialized }),
  setIdentities: (identities) => set({ identities }),
  setCurrentIdentity: (identity) => set({ currentIdentity: identity }),
  setCredentials: (credentials) => set({ credentials }),
  setSshAgentStatus: (status) => set({ sshAgentStatus: status }),
  setSshKeys: (keys) => set({ sshKeys: keys }),
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),
}));
