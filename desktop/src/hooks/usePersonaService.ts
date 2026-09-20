import { useEffect } from 'react';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type {
  AttachmentEntry,
  CredentialHistoryEntry,
  Identity,
  UpdateCredentialRequest,
  UpdateCredentialDataRequest,
} from '@/types';
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
        // 解锁成功即清除遗留的强制改密标志（新会话无需再轮换）
        setPasswordChangeRequired(false);
        await loadIdentities();
        toast.success('Service initialized successfully');
        return true;
      } else if (response.error_code === 'PASSWORD_CHANGE_REQUIRED') {
        // 主密码按策略需要轮换：解锁屏渲染强制改密弹窗，
        // 不走通用错误框/toast（密码本身没错）
        setPasswordChangeRequired(true);
        return false;
      } else {
        setError(response.error || 'Failed to initialize service');
        toast.error(response.error || 'Failed to initialize service');
        return false;
      }
    } catch {
      const errorMessage = 'Failed to initialize service';
      setError(errorMessage);
      toast.error(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const lockService = async () => {
    try {
      const response = await personaAPI.lockService();
      if (response.success) {
        setUnlocked(false);
        // 锁屏清强制改密标志（下次解锁由后端策略重新判定）
        setPasswordChangeRequired(false);
        setIdentities([]);
        setCurrentIdentity(null);
        setCredentials([]);
        // favicon 缓存随锁清空（后端 vault 未锁文件仍在，前端不落盘无害；
        // 重新解锁后按需重读）
        clearFaviconCache();
        // 选中与待注入的跨身份跳转都随锁作废（否则解锁后可能自动选中陈旧条目）
        clearPendingCredentialSelection();
        setSelectedCredentialId(null);
        // 侧栏分类选中同随锁复位（否则解锁后树选中残留上一会话状态）
        resetSidebarFilter();
        // 列表搜索词同随锁清空
        setCredentialSearchQuery('');
        // 编辑弹窗同随锁作废（解密 payload 不得跨锁存活）
        setEditingCredential(null);
        toast.success('Service locked');
      } else {
        toast.error(response.error || 'Failed to lock service');
      }
    } catch {
      toast.error('Failed to lock service');
    }
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
        setError(response.error || 'Failed to load identities');
      }
    } catch {
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
        try {
          await personaAPI.setActiveIdentity(response.data.id);
        } catch {
          // ignore
        }
        toast.success('Identity created successfully');
        return response.data;
      } else {
        setError(response.error || 'Failed to create identity');
        toast.error(response.error || 'Failed to create identity');
      }
    } catch {
      const errorMessage = 'Failed to create identity';
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
        toast.success('Identity updated');
        return response.data;
      }
      setError(response.error || 'Failed to update identity');
      toast.error(response.error || 'Failed to update identity');
      return null;
    } catch {
      const errorMessage = 'Failed to update identity';
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
        toast.success('Identity deleted');
        return true;
      }
      toast.error(response.error || 'Failed to delete identity');
      return false;
    } catch {
      toast.error('Failed to delete identity');
      return false;
    }
  };

  const switchIdentity = async (identity: Identity, options?: { silent?: boolean }) => {
    setCurrentIdentity(identity);
    try {
      await personaAPI.setActiveIdentity(identity.id);
    } catch {
      // ignore
    }
    await loadCredentialsForIdentity(identity.id);
    // 搜索跳转等场景传 silent：切换是手段不是用户动作，toast 属噪声
    if (!options?.silent) {
      toast.success(`Switched to ${identity.name}`);
    }
  };

  const loadCredentialsForIdentity = async (identityId: string) => {
    try {
      const response = await personaAPI.getCredentialsForIdentity(identityId);
      if (response.success && response.data) {
        setCredentials(response.data);
      } else {
        setError(response.error || 'Failed to load credentials');
        // 凭据没加载出来，pending 跳转永远不会被注入；清掉防下次进该身份突然选中
        clearPendingCredentialSelection();
      }
    } catch {
      setError('Failed to load credentials');
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
        toast.success('Credential created successfully');
        return response.data;
      } else {
        setError(response.error || 'Failed to create credential');
        toast.error(response.error || 'Failed to create credential');
      }
    } catch {
      const errorMessage = 'Failed to create credential';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  /** 元数据编辑：成功后刷新列表并返回更新行；REAUTH 等错误码走 toast */
  const updateCredential = async (request: UpdateCredentialRequest) => {
    setLoading(true);
    clearError();
    try {
      const response = await personaAPI.updateCredential(request);
      if (response.success && response.data) {
        if (currentIdentity) {
          await loadCredentialsForIdentity(currentIdentity.id);
        }
        toast.success('Item saved');
        return response.data;
      }
      setError(response.error || 'Failed to update credential');
      toast.error(response.error || 'Failed to update credential');
      return null;
    } catch {
      setError('Failed to update credential');
      toast.error('Failed to update credential');
      return null;
    } finally {
      setLoading(false);
    }
  };

  /**
   * 密文 payload 编辑（敏感：后端复用原 item key 重封 + 敏感门禁）。
   * 返回原始 ApiResponse 交调用方编排（modal 需识别 REAUTH_REQUIRED
   * 弹 ReauthModal 重试，不做吞码 toast）。
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
        toast.error(response.error || 'Failed to search credentials');
        return [];
      }
    } catch {
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
    } catch {
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
    } catch {
      toast.error('Failed to get credential data');
      return null;
    }
  };

  const getCredentialHistory = async (credentialId: string) => {
    try {
      const response = await personaAPI.getCredentialHistory(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || 'Failed to load item history');
      return [] as CredentialHistoryEntry[];
    } catch {
      toast.error('Failed to load item history');
      return [] as CredentialHistoryEntry[];
    }
  };

  /** 附件四动作。列表失败回 []（面板显示空态）；增删保存失败 toast 且返回 null/[] */
  const listAttachments = async (credentialId: string) => {
    try {
      const response = await personaAPI.listAttachments(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || 'Failed to load attachments');
      return [] as AttachmentEntry[];
    } catch {
      toast.error('Failed to load attachments');
      return [] as AttachmentEntry[];
    }
  };

  const attachFileToCredential = async (credentialId: string, filePath: string, encrypt: boolean) => {
    try {
      const response = await personaAPI.attachFileToCredential(credentialId, filePath, encrypt);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || 'Failed to attach file');
      return null;
    } catch {
      toast.error('Failed to attach file');
      return null;
    }
  };

  const saveAttachmentToFile = async (attachmentId: string, outputPath: string) => {
    try {
      const response = await personaAPI.saveAttachmentToFile(attachmentId, outputPath);
      if (response.success) {
        return true;
      }
      toast.error(response.error || 'Failed to save attachment');
      return false;
    } catch {
      toast.error('Failed to save attachment');
      return false;
    }
  };

  const deleteAttachment = async (attachmentId: string) => {
    try {
      const response = await personaAPI.deleteAttachment(attachmentId);
      if (response.success) {
        return true;
      }
      toast.error(response.error || 'Failed to delete attachment');
      return false;
    } catch {
      toast.error('Failed to delete attachment');
      return false;
    }
  };

  const getTotpCode = async (credentialId: string) => {
    try {
      const response = await personaAPI.getTotpCode(credentialId);
      if (response.success && response.data) {
        return response.data;
      }
      toast.error(response.error || 'Failed to generate TOTP code');
      return null;
    } catch {
      toast.error('Failed to generate TOTP code');
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
        toast.success(response.data.is_favorite ? 'Added to favorites' : 'Removed from favorites');
        return response.data;
      }
      toast.error(response.error || 'Failed to toggle favorite');
      return null;
    } catch {
      toast.error('Failed to toggle favorite');
      return null;
    }
  };

  /** 按需抓取凭据站点 favicon（唯一外联入口；成功并入缓存，失败 toast） */
  const fetchFavicon = async (credentialId: string) => {
    try {
      const response = await personaAPI.fetchCredentialFavicon(credentialId);
      if (response.success && response.data) {
        setFaviconEntries([response.data]);
        toast.success('Icon fetched');
        return response.data;
      }
      toast.error(response.error || 'Failed to fetch icon');
      return null;
    } catch {
      toast.error('Failed to fetch icon');
      return null;
    }
  };

  const deleteCredential = async (credentialId: string) => {
    try {
      const response = await personaAPI.deleteCredential(credentialId);
      if (response.success && response.data) {
        setCredentials(credentials.filter((cred) => cred.id !== credentialId));
        toast.success('Credential deleted');
        return true;
      }
      toast.error(response.error || 'Failed to delete credential');
      return false;
    } catch {
      toast.error('Failed to delete credential');
      return false;
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
    } catch {
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
    } catch {
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
    } catch {
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
    } catch {
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
    passwordChangeRequired,
    sshAgentStatus,
    sshKeys,

    // Actions
    initializeService,
    lockService,
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
    listAttachments,
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
    clearError,
  };
};
