import { useEffect } from 'react';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type { Identity } from '@/types';
import toast from 'react-hot-toast';

export const usePersonaService = () => {
  const {
    isUnlocked,
    isInitialized,
    identities,
    currentIdentity,
    credentials,
    isLoading,
    error,
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
  } = useAppStore();

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
      setError('Failed to check service status');
    }
  };

  const initializeService = async (masterPassword: string, dbPath?: string) => {
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
        await loadIdentities();
        toast.success('Service initialized successfully');
      } else {
        setError(response.error || 'Failed to initialize service');
        toast.error(response.error || 'Failed to initialize service');
      }
    } catch (err) {
      const errorMessage = 'Failed to initialize service';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const lockService = async () => {
    try {
      const response = await personaAPI.lockService();
      if (response.success) {
        setUnlocked(false);
        setIdentities([]);
        setCurrentIdentity(null);
        setCredentials([]);
        toast.success('Service locked');
      } else {
        toast.error(response.error || 'Failed to lock service');
      }
    } catch (err) {
      toast.error('Failed to lock service');
    }
  };

  const loadIdentities = async () => {
    try {
      const response = await personaAPI.getIdentities();
      if (response.success && response.data) {
        setIdentities(response.data);
        // Set first identity as current if none selected
        if (!currentIdentity && response.data.length > 0) {
          setCurrentIdentity(response.data[0]);
        }
      } else {
        setError(response.error || 'Failed to load identities');
      }
    } catch (err) {
      setError('Failed to load identities');
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
        toast.success('Identity created successfully');
        return response.data;
      } else {
        setError(response.error || 'Failed to create identity');
        toast.error(response.error || 'Failed to create identity');
      }
    } catch (err) {
      const errorMessage = 'Failed to create identity';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const switchIdentity = async (identity: Identity) => {
    setCurrentIdentity(identity);
    await loadCredentialsForIdentity(identity.id);
    toast.success(`Switched to ${identity.name}`);
  };

  const loadCredentialsForIdentity = async (identityId: string) => {
    try {
      const response = await personaAPI.getCredentialsForIdentity(identityId);
      if (response.success && response.data) {
        setCredentials(response.data);
      } else {
        setError(response.error || 'Failed to load credentials');
      }
    } catch (err) {
      setError('Failed to load credentials');
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
        toast.success('Credential created successfully');
        return response.data;
      } else {
        setError(response.error || 'Failed to create credential');
        toast.error(response.error || 'Failed to create credential');
      }
    } catch (err) {
      const errorMessage = 'Failed to create credential';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const searchCredentials = async (query: string) => {
    try {
      const response = await personaAPI.searchCredentials(query);
      if (response.success && response.data) {
        return response.data;
      } else {
        toast.error(response.error || 'Failed to search credentials');
        return [];
      }
    } catch (err) {
      toast.error('Failed to search credentials');
      return [];
    }
  };

  const generatePassword = async (length: number = 16, includeSymbols: boolean = true) => {
    try {
      const response = await personaAPI.generatePassword(length, includeSymbols);
      if (response.success && response.data) {
        return response.data;
      } else {
        toast.error(response.error || 'Failed to generate password');
        return '';
      }
    } catch (err) {
      toast.error('Failed to generate password');
      return '';
    }
  };

  const getCredentialData = async (credentialId: string) => {
    try {
      const response = await personaAPI.getCredentialData(credentialId);
      if (response.success) {
        return response.data;
      } else {
        toast.error(response.error || 'Failed to get credential data');
        return null;
      }
    } catch (err) {
      toast.error('Failed to get credential data');
      return null;
    }
  };

  const refreshSshAgentStatus = async () => {
    try {
      const response = await personaAPI.getSshAgentStatus();
      if (response.success) {
        setSshAgentStatus(response.data ?? null);
      } else {
        toast.error(response.error || 'Failed to get SSH agent status');
      }
    } catch (err) {
      toast.error('Failed to get SSH agent status');
    }
  };

  const startSshAgent = async (masterPassword?: string) => {
    try {
      const response = await personaAPI.startSshAgent(masterPassword);
      if (response.success) {
        setSshAgentStatus(response.data ?? null);
        toast.success('SSH agent started');
      } else {
        toast.error(response.error || 'Failed to start SSH agent');
      }
    } catch (err) {
      toast.error('Failed to start SSH agent');
    }
  };

  const stopSshAgent = async () => {
    try {
      const response = await personaAPI.stopSshAgent();
      if (response.success) {
        setSshAgentStatus(null);
        toast.success('SSH agent stopped');
      } else {
        toast.error(response.error || 'Failed to stop SSH agent');
      }
    } catch (err) {
      toast.error('Failed to stop SSH agent');
    }
  };

  const loadSshKeys = async () => {
    try {
      const response = await personaAPI.getSshKeys();
      if (response.success && response.data) {
        setSshKeys(response.data);
      } else {
        toast.error(response.error || 'Failed to load SSH keys');
      }
    } catch (err) {
      toast.error('Failed to load SSH keys');
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
    sshAgentStatus,
    sshKeys,

    // Actions
    initializeService,
    lockService,
    loadIdentities,
    createIdentity,
    switchIdentity,
    loadCredentialsForIdentity,
    createCredential,
    searchCredentials,
    generatePassword,
    getCredentialData,
    refreshSshAgentStatus,
    startSshAgent,
    stopSshAgent,
    loadSshKeys,
    clearError,
  };
};
