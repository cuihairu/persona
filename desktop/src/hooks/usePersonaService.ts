import { useEffect } from 'react';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type {
  AttachmentEntry,
  ApiResponse,
  CredentialHistoryEntry,
  Identity,
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
        // 解锁成功即清除遗留的强制改密标志（新会话无需再轮换）
        setPasswordChangeRequired(false);
        await loadIdentities();
        toast.success(t('svc.initSuccess'));
        return true;
      } else if (response.error_code === 'PASSWORD_CHANGE_REQUIRED') {
        // 主密码按策略需要轮换：解锁屏渲染强制改密弹窗，
        // 不走通用错误框/toast（密码本身没错）
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

  /** biometric 解锁：后端已走 init_service 全链路（OS 认证 → keyring 取回
   * 密码），前端只做会话状态编排。返回原始 ApiResponse 供解锁屏按
   * error_code 分流（BIOMETRIC_RESET 刷 status 隐藏按钮；改密码走既有
   * forced 机制）。失败不 toast——解锁屏的错误条/按钮显隐是唯一反馈面。 */
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
        // 生物解锁成功但策略要求轮换：与密码路径共用 forced 改密弹窗
        setPasswordChangeRequired(true);
      } else if (response.error_code === 'BIOMETRIC_RESET') {
        // 托管条目不存在/已自删：本地化提示（后端消息为英文），解锁屏随后刷 status
        setError(t('svc.biometricReset'));
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
        toast.success(t('svc.lockSuccess'));
      } else {
        toast.error(response.error || t('svc.lockFailed'));
      }
    } catch {
      toast.error(t('svc.lockFailed'));
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
          // ignore
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
      toast.success(t('svc.switchedTo', { name: identity.name }));
    }
  };

  const loadCredentialsForIdentity = async (identityId: string) => {
    try {
      const response = await personaAPI.getCredentialsForIdentity(identityId);
      if (response.success && response.data) {
        setCredentials(response.data);
      } else {
        setError(response.error || t('svc.loadCredentialsFailed'));
        // 凭据没加载出来，pending 跳转永远不会被注入；清掉防下次进该身份突然选中
        clearPendingCredentialSelection();
      }
    } catch {
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

  /** 附件四动作。列表失败回 []（面板显示空态）；增删保存失败 toast 且返回 null/[] */
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

  /** 按需抓取凭据站点 favicon（唯一外联入口；成功并入缓存，失败 toast） */
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
    } catch {
      toast.error(t('svc.sshStatusFailed'));
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
    } catch {
      toast.error(t('svc.sshAgentStartFailed'));
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
    } catch {
      toast.error(t('svc.sshAgentStopFailed'));
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
