import { useEffect, useRef } from 'react';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type {
  AttachmentEntry,
  ApiResponse,
  CredentialHistoryEntry,
  CustomField,
  Identity,
  SshKeyGenerated,
  SshKeyImported,
  SshKeyInspection,
  UpdateCredentialRequest,
  UpdateCredentialDataRequest,
} from '@/types';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';

export const usePersonaService = () => {
  const { t } = useTranslation();
  const {
    isUnlocked,
    isInitialized,
    identities,
    currentIdentity,
    credentials,
    isLoading,
    error,
    passwordChangeRequired,
    sshAgentStatus,
    sshKeys,
    setUnlocked,
    setInitialized,
    setIdentities,
    setCurrentIdentity,
    setCredentials,
    setSshAgentStatus,
    setSshKeys,
    setLoading,
    setError,
    clearError,
    setFaviconEntries,
    clearFaviconCache,
    clearPendingCredentialSelection,
    setSelectedCredentialId,
    setEditingCredential,
    setPasswordChangeRequired,
    resetSidebarFilter,
    setCredentialSearchQuery,
  } = useAppStore();

  // Stale-response guard for identity switching / credential loading (JS-5): when identities are
  // switched in quick succession, the slow previous request can arrive last and clobber the new
  // identity's state. Every operation bumps a sequence number, and once it completes the result is
  // dropped if a newer operation has superseded it, preventing identity/credential crossover.
  const switchSeq = useRef(0);
  const credentialLoadSeq = useRef(0);

  // Check if service is unlocked on mount
  useEffect(() => {
    checkServiceStatus();
  }, []);

  const checkServiceStatus = async () => {
    try {
      const response = await personaAPI.isServiceUnlocked();
      if (response.success && response.data !== undefined) {
        setUnlocked(response.data);
        setInitialized(true);
        if (response.data) {
          await loadIdentities();
        }
      }
    } catch (err) {
      console.error('Failed to check service status:', err);
      setError(t('svc.checkStatusFailed'));
    }
  };

  const initializeService = async (masterPassword: string, dbPath?: string): Promise<boolean> => {
    setLoading(true);
    clearError();

    try {
      const response = await personaAPI.initService({
        master_password: masterPassword,
        db_path: dbPath,
      });

      if (response.success) {
        setUnlocked(true);
        setInitialized(true);
        // Clear any leftover forced password-change flag once unlocking succeeds (a new session needs no rotation)
        setPasswordChangeRequired(false);
        await loadIdentities();
        toast.success(t('svc.initSuccess'));
        return true;
      } else if (response.error_code === 'PASSWORD_CHANGE_REQUIRED') {
        // The master password needs rotation per policy: the unlock screen renders the forced change dialog,
        // without a generic error box/toast (the password itself is not wrong)
        setPasswordChangeRequired(true);
        return false;
      } else {
        setError(response.error || t('svc.initFailed'));
        toast.error(response.error || t('svc.initFailed'));
        return false;
      }
    } catch {
      const errorMessage = t('svc.initFailed');
      setError(errorMessage);
      toast.error(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  /** Biometric unlock: the backend already runs the full init_service chain (OS authentication ->
   *  retrieving the password from the keyring), so the frontend only orchestrates session state. The raw
   *  ApiResponse is returned so the unlock screen can branch on error_code (BIOMETRIC_RESET refreshes status
   *  to hide the button; a password change goes through the existing forced mechanism). Failures are not
   *  toasted—the unlock screen's error bar and button visibility are the only feedback surface. */
  const unlockWithBiometric = async (dbPath?: string): Promise<ApiResponse<boolean>> => {
    setLoading(true);
    clearError();
    try {
      const response = await personaAPI.biometricUnlock(dbPath);
      if (response.success) {
        setUnlocked(true);
        setInitialized(true);
        setPasswordChangeRequired(false);
        await loadIdentities();
        toast.success(t('svc.initSuccess'));
        return response;
      }
      if (response.error_code === 'PASSWORD_CHANGE_REQUIRED') {
        // Biometric unlock succeeded but policy requires rotation: share the password path's forced change dialog
        setPasswordChangeRequired(true);
      } else if (response.error_code === 'BIOMETRIC_RESET') {
        // The managed entry is missing or was self-deleted: localized hint (the backend message is English), and the unlock screen refreshes status afterwards
        setError(t('svc.biometricReset'));
      } else if (response.error_code === 'BIOMETRIC_CANCELLED') {
        // The user dismissed the prompt on purpose: the vault is still valid, so return silently to the unlock screen
        // (the entry point already clearError'd and the fingerprint button stays)—deliberately not setting an error,
        // since cancelling is not a failure (design doc §3.4)
      } else {
        setError(response.error || t('svc.initFailed'));
      }
      return response;
    } catch {
      setError(t('svc.initFailed'));
      return { success: false } as ApiResponse<boolean>;
    } finally {
      setLoading(false);
    }
  };

  const lockService = async () => {
    try {
      const response = await personaAPI.lockService();
      if (response.success) {
        setUnlocked(false);
        // Clear the forced password-change flag when locking (backend policy re-decides on the next unlock)
        setPasswordChangeRequired(false);
        setIdentities([]);
        setCurrentIdentity(null);
        setCredentials([]);
        // The favicon cache is cleared with the lock (the backend vault is not locked and the file is still there,
        // so skipping a disk write is harmless; it gets re-read on demand after re-unlocking)
        clearFaviconCache();
        // Both the selection and the pending cross-identity jump are invalidated with the lock (otherwise unlocking could auto-select a stale entry)
        clearPendingCredentialSelection();
        setSelectedCredentialId(null);
        // Sidebar category selection is reset with the lock too (otherwise the tree selection would carry the previous session's state into the next unlock)
        resetSidebarFilter();
        // The list search query is also cleared with the lock
        setCredentialSearchQuery('');
        // The editing dialog is invalidated with the lock too (a decrypted payload must not survive across locks)
        setEditingCredential(null);
        toast.success(t('svc.lockSuccess'));
      } else {
        toast.error(response.error || t('svc.lockFailed'));
      }
    } catch {
      toast.error(t('svc.lockFailed'));
    }
  };

  /** Frontend wrap-up after a restore with a vault swap (S5 restore-from-file): the backend's swap stage has
   *  already taken the service down (connections drained, and the master password may have come from a backup).
   *  The old vault's identities/credentials are cleared from memory the same way lockService does (a leftover
   *  currentIdentity would make loadIdentities skip reselection after unlocking), but **lockService is not called**
   *  —the backend slot is already None and a lock command would surely fail; finally the unlock state is re-probed
   *  to drive the App back to the unlock screen (is_service_unlocked is queryable without unlocking). */
  const finalizeVaultRestore = async () => {
    setPasswordChangeRequired(false);
    setIdentities([]);
    setCurrentIdentity(null);
    setCredentials([]);
    clearFaviconCache();
    clearPendingCredentialSelection();
    setSelectedCredentialId(null);
    resetSidebarFilter();
    setCredentialSearchQuery('');
    setEditingCredential(null);
    await checkServiceStatus();
  };

  const loadIdentities = async () => {
    try {
      const response = await personaAPI.getIdentities();
      if (response.success && response.data) {
        setIdentities(response.data);
        // Select current identity: prefer workspace active identity, fall back to first.
        const storedCurrentIdentity = useAppStore.getState().currentIdentity;
        if (!storedCurrentIdentity && response.data.length > 0) {
          try {
            const active = await personaAPI.getActiveIdentity();
            const activeId = active.success ? (active.data ?? null) : null;
            const match = activeId
              ? response.data.find((id) => id.id === activeId) ?? null
              : null;

            const selected = match ?? response.data[0];
            setCurrentIdentity(selected);

            if (!match) {
              // Keep workspace state consistent so other clients (bridge/CLI) can reuse it.
              await personaAPI.setActiveIdentity(selected.id);
            }
          } catch {
            setCurrentIdentity(response.data[0]);
          }
        }
      } else {
        setError(response.error || t('svc.loadIdentitiesFailed'));
      }
    } catch {
      setError(t('svc.loadIdentitiesFailed'));
    }
  };

  const createIdentity = async (name: string, identityType: string, description?: string) => {
    setLoading(true);
    clearError();

    try {
      const response = await personaAPI.createIdentity({
        name,
        identity_type: identityType,
        description,
      });

      if (response.success && response.data) {
        await loadIdentities();
        setCurrentIdentity(response.data);
        try {
          await personaAPI.setActiveIdentity(response.data.id);
        } catch {
          // The creation is already confirmed by the server and is not rolled back; but the activation failure must be visible—
          // the workspace's active identity still points at the old one, so the CLI/browser would keep working with it; this cannot silently succeed
          toast.error(t('svc.activateIdentityFailed'));
        }
        toast.success(t('svc.identityCreated'));
        return response.data;
      } else {
        setError(response.error || t('svc.identityCreateFailed'));
        toast.error(response.error || t('svc.identityCreateFailed'));
      }
    } catch {
      const errorMessage = t('svc.identityCreateFailed');
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const updateIdentity = async (identity: Identity) => {
    setLoading(true);
    clearError();

    try {
      const response = await personaAPI.updateIdentity({
        id: identity.id,
        name: identity.name,
        identity_type: identity.identity_type,
        description: identity.description,
        email: identity.email,
        phone: identity.phone,
        tags: identity.tags,
      });

      if (response.success && response.data) {
        await loadIdentities();
        setCurrentIdentity(response.data);
        toast.success(t('svc.identityUpdated'));
        return response.data;
      }
      setError(response.error || t('svc.identityUpdateFailed'));
      toast.error(response.error || t('svc.identityUpdateFailed'));
      return null;
    } catch {
      const errorMessage = t('svc.identityUpdateFailed');
      setError(errorMessage);
      toast.error(errorMessage);
      return null;
    } finally {
      setLoading(false);
    }
  };

  const deleteIdentity = async (identityId: string) => {
    try {
      const response = await personaAPI.deleteIdentity(identityId);
      if (response.success && response.data) {
        const wasCurrent = useAppStore.getState().currentIdentity?.id === identityId;
        if (wasCurrent) {
          setCurrentIdentity(null);
          setCredentials([]);
        }
        await loadIdentities();
        toast.success(t('svc.identityDeleted'));
        return true;
      }
      toast.error(response.error || t('svc.identityDeleteFailed'));
      return false;
    } catch {
      toast.error(t('svc.identityDeleteFailed'));
      return false;
    }
  };

  /** Switches the active identity. The UI identity and credentials are only updated once the server commit succeeds;
   * on failure the original identity is kept and setError is used, with no success toast (silent only suppresses the
   * success toast, not failure feedback—a silent failure would make the user believe they are already working in the target identity). */
  const switchIdentity = async (
    identity: Identity,
    options?: { silent?: boolean },
  ): Promise<boolean> => {
    clearError();
    // Sequence guard: with concurrent switches, a slow older switch finishing later must not clobber the new switch's currentIdentity
    const seq = ++switchSeq.current;
    try {
      const response = await personaAPI.setActiveIdentity(identity.id);
      if (seq !== switchSeq.current) return false;
      if (!response.success) {
        const errorMessage = response.error || t('svc.switchFailed');
        setError(errorMessage);
        toast.error(errorMessage);
        return false;
      }
      setCurrentIdentity(identity);
      await loadCredentialsForIdentity(identity.id);
      // Scenarios like search jumps pass silent: the switch is a means rather than a user action, so a success toast would be noise
      if (!options?.silent) {
        toast.success(t('svc.switchedTo', { name: identity.name }));
      }
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : t('svc.switchFailed');
      setError(errorMessage);
      toast.error(errorMessage);
      return false;
    }
  };

  const loadCredentialsForIdentity = async (identityId: string) => {
    // Sequence guard: a slow response for the old identity's credentials must not clobber the new identity (JS-5 credential crossover)
    const seq = ++credentialLoadSeq.current;
    try {
      const response = await personaAPI.getCredentialsForIdentity(identityId);
      if (seq !== credentialLoadSeq.current) return;
      if (response.success && response.data) {
        setCredentials(response.data);
      } else {
        setError(response.error || t('svc.loadCredentialsFailed'));
        // With no credentials loaded, the pending jump can never be injected; clear it so a later visit to this identity does not select something unexpectedly
        clearPendingCredentialSelection();
      }
    } catch {
      if (seq !== credentialLoadSeq.current) return;
      setError(t('svc.loadCredentialsFailed'));
      clearPendingCredentialSelection();
    }
  };

  const createCredential = async (credentialData: any) => {
    setLoading(true);
    clearError();

    try {
      const response = await personaAPI.createCredential(credentialData);
      if (response.success && response.data) {
        if (currentIdentity) {
          await loadCredentialsForIdentity(currentIdentity.id);
        }
        toast.success(t('svc.credentialCreated'));
        return response.data;
      } else {
        setError(response.error || t('svc.credentialCreateFailed'));
        toast.error(response.error || t('svc.credentialCreateFailed'));
      }
    } catch {
      const errorMessage = t('svc.credentialCreateFailed');
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  /** Metadata edit: on success refreshes the list and returns the updated row; error codes such as REAUTH go to a toast */
  const updateCredential = async (request: UpdateCredentialRequest) => {
    setLoading(true);
    clearError();
    try {
      const response = await personaAPI.updateCredential(request);
      if (response.success && response.data) {
        if (currentIdentity) {
          await loadCredentialsForIdentity(currentIdentity.id);
        }
        toast.success(t('svc.itemSaved'));
        return response.data;
      }
      setError(response.error || t('svc.credentialUpdateFailed'));
      toast.error(response.error || t('svc.credentialUpdateFailed'));
      return null;
    } catch {
      setError(t('svc.credentialUpdateFailed'));
      toast.error(t('svc.credentialUpdateFailed'));
      return null;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Encrypted payload editing (sensitive: the backend reseals with the original item key plus a sensitivity gate).
   * The raw ApiResponse is returned for the caller to orchestrate (the modal must recognize REAUTH_REQUIRED,
   * open the ReauthModal and retry, rather than swallowing the code in a toast).
   */
  const updateCredentialData = async (request: UpdateCredentialDataRequest) => {
    return personaAPI.updateCredentialData(request);
  };

  const searchCredentials = async (query: string) => {
    try {
      const response = await personaAPI.searchCredentials(query);
      if (response.success && response.data) {
        return response.data;
      } else {
        toast.error(response.error || t('svc.searchFailed'));
        return [];
      }
    } catch {
      toast.error(t('svc.searchFailed'));
      return [];
    }
  };

  const generatePassword = async (length: number = 16, includeSymbols: boolean = true) => {
    try {
      const response = await personaAPI.generatePassword(length, includeSymbols);
      if (response.success && response.data) {
        return response.data;
      } else {
        toast.error(response.error || t('svc.generatePasswordFailed'));
        return '';
      }
    } catch {
      toast.error(t('svc.generatePasswordFailed'));
      return '';
    }
  };

  const getCredentialData = async (credentialId: string) => {
    try {
      const response = await personaAPI.getCredentialData(credentialId);
      if (response.success) {
        return response.data;
      } else {
        toast.error(response.error || t('svc.getCredentialDataFailed'));
        return null;
      }
    } catch {
      toast.error(t('svc.getCredentialDataFailed'));
      return null;
    }
  };

  const getCredentialHistory = async (credentialId: string) => {
    try {
      const response = await personaAPI.getCredentialHistory(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || t('svc.loadHistoryFailed'));
      return [] as CredentialHistoryEntry[];
    } catch {
      toast.error(t('svc.loadHistoryFailed'));
      return [] as CredentialHistoryEntry[];
    }
  };

  /** Restores metadata to a historical version: on success refreshes the list and returns the updated row (secrets are never rolled back) */
  const restoreCredentialVersion = async (credentialId: string, version: number) => {
    try {
      const response = await personaAPI.restoreCredentialVersion(credentialId, version);
      if (response.success && response.data) {
        if (currentIdentity) {
          await loadCredentialsForIdentity(currentIdentity.id);
        }
        toast.success(t('svc.itemRestored'));
        return response.data;
      }
      toast.error(response.error || t('svc.restoreFailed'));
      return null;
    } catch {
      toast.error(t('svc.restoreFailed'));
      return null;
    }
  };

  /** The four attachment actions. A failed list returns [] (the panel shows an empty state); failed add/delete/save toast and return null/[] */
  const listAttachments = async (credentialId: string) => {
    try {
      const response = await personaAPI.listAttachments(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || t('svc.loadAttachmentsFailed'));
      return [] as AttachmentEntry[];
    } catch {
      toast.error(t('svc.loadAttachmentsFailed'));
      return [] as AttachmentEntry[];
    }
  };

  /**
   * Structured custom fields (aligned with 1Password). A failed read returns null (to distinguish it from an
   * "empty table", so the panel shows an error row rather than an empty state); values are decrypted alongside the
   * list, and the UI layer masks concealed ones.
   */
  const getCredentialCustomFields = async (credentialId: string): Promise<CustomField[] | null> => {
    try {
      const response = await personaAPI.getCredentialCustomFields(credentialId);
      if (response.success && Array.isArray(response.data)) {
        return response.data;
      }
      return null;
    } catch {
      return null;
    }
  };

  const attachFileToCredential = async (credentialId: string, filePath: string, encrypt: boolean) => {
    try {
      const response = await personaAPI.attachFileToCredential(credentialId, filePath, encrypt);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || t('svc.attachFileFailed'));
      return null;
    } catch {
      toast.error(t('svc.attachFileFailed'));
      return null;
    }
  };

  const saveAttachmentToFile = async (attachmentId: string, outputPath: string) => {
    try {
      const response = await personaAPI.saveAttachmentToFile(attachmentId, outputPath);
      if (response.success) {
        return true;
      }
      toast.error(response.error || t('svc.saveAttachmentFailed'));
      return false;
    } catch {
      toast.error(t('svc.saveAttachmentFailed'));
      return false;
    }
  };

  const deleteAttachment = async (attachmentId: string) => {
    try {
      const response = await personaAPI.deleteAttachment(attachmentId);
      if (response.success) {
        return true;
      }
      toast.error(response.error || t('svc.deleteAttachmentFailed'));
      return false;
    } catch {
      toast.error(t('svc.deleteAttachmentFailed'));
      return false;
    }
  };

  const getTotpCode = async (credentialId: string) => {
    try {
      const response = await personaAPI.getTotpCode(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || t('svc.totpFailed'));
      return null;
    } catch {
      toast.error(t('svc.totpFailed'));
      return null;
    }
  };

  const toggleCredentialFavorite = async (credentialId: string) => {
    try {
      const response = await personaAPI.toggleCredentialFavorite(credentialId);
      if (response.success && response.data) {
        setCredentials(
          credentials.map((cred) => (cred.id === credentialId ? response.data! : cred)),
        );
        toast.success(response.data.is_favorite ? t('svc.favoriteAdded') : t('svc.favoriteRemoved'));
        return response.data;
      }
      toast.error(response.error || t('svc.toggleFavoriteFailed'));
      return null;
    } catch {
      toast.error(t('svc.toggleFavoriteFailed'));
      return null;
    }
  };

  /** Fetches a credential site's favicon on demand (the only outbound request; success merges into the cache, failure toasts) */
  const fetchFavicon = async (credentialId: string) => {
    try {
      const response = await personaAPI.fetchCredentialFavicon(credentialId);
      if (response.success && response.data) {
        setFaviconEntries([response.data]);
        toast.success(t('svc.iconFetched'));
        return response.data;
      }
      toast.error(response.error || t('svc.fetchIconFailed'));
      return null;
    } catch {
      toast.error(t('svc.fetchIconFailed'));
      return null;
    }
  };

  const deleteCredential = async (credentialId: string) => {
    try {
      const response = await personaAPI.deleteCredential(credentialId);
      if (response.success && response.data) {
        setCredentials(credentials.filter((cred) => cred.id !== credentialId));
        toast.success(t('svc.credentialDeleted'));
        return true;
      }
      toast.error(response.error || t('svc.credentialDeleteFailed'));
      return false;
    } catch {
      toast.error(t('svc.credentialDeleteFailed'));
      return false;
    }
  };

  const refreshSshAgentStatus = async () => {
    try {
      const response = await personaAPI.getSshAgentStatus();
      if (response.success) {
        setSshAgentStatus(response.data ?? null);
      } else {
        toast.error(response.error || t('svc.sshStatusFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('svc.sshStatusFailed'));
    }
  };

  const startSshAgent = async (masterPassword?: string) => {
    try {
      const response = await personaAPI.startSshAgent(masterPassword);
      if (response.success) {
        setSshAgentStatus(response.data ?? null);
        toast.success(t('svc.sshAgentStarted'));
      } else {
        toast.error(response.error || t('svc.sshAgentStartFailed'));
      }
    } catch (err) {
      // The api layer has already normalized Tauri's string rejection into an Error—include the underlying
      // cause here (missing vault / socket path permissions / IPC argument issues) rather than only reporting "failed to start"
      toast.error(err instanceof Error ? err.message : t('svc.sshAgentStartFailed'));
    }
  };

  const stopSshAgent = async () => {
    try {
      const response = await personaAPI.stopSshAgent();
      if (response.success) {
        setSshAgentStatus(null);
        toast.success(t('svc.sshAgentStopped'));
      } else {
        toast.error(response.error || t('svc.sshAgentStopFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('svc.sshAgentStopFailed'));
    }
  };

  const loadSshKeys = async () => {
    try {
      const response = await personaAPI.getSshKeys();
      if (response.success && response.data) {
        setSshKeys(response.data);
      } else {
        toast.error(response.error || t('svc.sshKeysFailed'));
      }
    } catch {
      toast.error(t('svc.sshKeysFailed'));
    }
  };

  /** The two stages of SSH private key file import (inspect/import) do not toast here: the import dialog
   *  must branch on the response (a protected key needs a passphrase, a wrong one needs an in-place retry), so errors are shown in place */
  const inspectSshKeyFile = async (path: string) => {
    try {
      return await personaAPI.inspectSshKeyFile(path);
    } catch (err) {
      return {
        success: false,
        data: undefined,
        error: err instanceof Error ? err.message : String(err),
        error_code: undefined,
      } as ApiResponse<SshKeyInspection>;
    }
  };

  const importSshKey = async (request: {
    identity_id: string;
    path: string;
    name?: string;
    passphrase?: string;
  }) => {
    try {
      return await personaAPI.importSshKey(request);
    } catch (err) {
      return {
        success: false,
        data: undefined,
        error: err instanceof Error ? err.message : String(err),
        error_code: undefined,
      } as ApiResponse<SshKeyImported>;
    }
  };

  /** Generates an SSH key pair and stores it; like import, no toast at the hook level—the generation dialog
   *  needs a long loading state for RSA 4096 and the public key display on success, so the branching happens inside the dialog */
  const generateSshKey = async (request: {
    identity_id: string;
    key_type: string;
    comment?: string;
    name?: string;
  }) => {
    try {
      return await personaAPI.generateSshKey(request);
    } catch (err) {
      return {
        success: false,
        data: undefined,
        error: err instanceof Error ? err.message : String(err),
        error_code: undefined,
      } as ApiResponse<SshKeyGenerated>;
    }
  };

  return {
    // State
    isUnlocked,
    isInitialized,
    identities,
    currentIdentity,
    credentials,
    isLoading,
    error,
    passwordChangeRequired,
    sshAgentStatus,
    sshKeys,

    // Actions
    initializeService,
    unlockWithBiometric,
    lockService,
    /** Re-probes the backend unlock state (the Quick Access popover has to ask every time it is summoned:
     *  the two windows each have their own store, so unlocking/locking in the main window does not reach here automatically) */
    checkServiceStatus,
    /** Clears memory and re-probes the unlock state after a restore with a vault swap (called after BackupSection succeeds) */
    finalizeVaultRestore,
    loadIdentities,
    createIdentity,
    updateIdentity,
    deleteIdentity,
    switchIdentity,
    loadCredentialsForIdentity,
    createCredential,
    updateCredential,
    updateCredentialData,
    searchCredentials,
    generatePassword,
    getCredentialData,
    getCredentialHistory,
    restoreCredentialVersion,
    listAttachments,
    getCredentialCustomFields,
    attachFileToCredential,
    saveAttachmentToFile,
    deleteAttachment,
    getTotpCode,
    toggleCredentialFavorite,
    fetchFavicon,
    deleteCredential,
    refreshSshAgentStatus,
    startSshAgent,
    stopSshAgent,
    loadSshKeys,
    inspectSshKeyFile,
    importSshKey,
    generateSshKey,
    clearError,
  };
};
