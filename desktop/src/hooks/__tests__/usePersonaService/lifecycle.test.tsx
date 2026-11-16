import { act, renderHook, waitFor } from '@testing-library/react';
import { usePersonaService } from '../../usePersonaService';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';

const toastSuccess = jest.fn();
const toastError = jest.fn();

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: (...args: any[]) => toastSuccess(...args),
    error: (...args: any[]) => toastError(...args),
  },
}));

describe('hooks/usePersonaService', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    toastSuccess.mockReset();
    toastError.mockReset();
    useAppStore.setState({
      isUnlocked: false,
      isInitialized: false,
      identities: [],
      currentIdentity: null,
      credentials: [],
      sshAgentStatus: null,
      sshKeys: [],
      isLoading: false,
      error: null,
      passwordChangeRequired: false,
      sidebarFilter: { kind: 'all' },
    });
  });

  const makeIdentity = (id: string, name = 'Test') =>
    ({
      id,
      name,
      identity_type: 'Personal',
      description: null,
      email: null,
      phone: null,
      ssh_key: null,
      gpg_key: null,
      tags: [],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
    }) as any;


  const mockUnlockedOnMount = () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
  };

  it('checks service status on mount and sets initialized', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });

    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [],
      error: undefined,
    });

    renderHook(() => usePersonaService());

    await waitFor(() => {
      expect(useAppStore.getState().isInitialized).toBe(true);
    });
    expect(useAppStore.getState().isUnlocked).toBe(false);
  });

  it('initializeService sets unlocked and loads identities on success', async () => {
    const identity = {
      id: 'id-1',
      name: 'Test',
      identity_type: 'Personal',
      description: null,
      email: null,
      phone: null,
      ssh_key: null,
      gpg_key: null,
      tags: [],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
    } as any;

    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });

    jest.spyOn(personaAPI, 'initService').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [identity],
      error: undefined,
    });

    jest.spyOn(personaAPI, 'getActiveIdentity').mockResolvedValue({
      success: true,
      data: null,
      error: undefined,
    });

    jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());

    await act(async () => {
      await expect(result.current.initializeService('pw')).resolves.toBe(true);
    });

    expect(useAppStore.getState().isUnlocked).toBe(true);
    expect(useAppStore.getState().isInitialized).toBe(true);
    expect(useAppStore.getState().identities).toHaveLength(1);
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-1');
    expect(toastSuccess).toHaveBeenCalled();
  });

  // -- 以下为补全：各 action 的成功/失败/异常臂 ----------------------------

  it('lockService clears session state on success', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({
      isUnlocked: true,
      selectedCredentialId: 'c1',
      pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
      sidebarFilter: { kind: 'category', value: 'passwords' },
    });
    jest.spyOn(personaAPI, 'lockService').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.lockService();
    });

    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().identities).toEqual([]);
    expect(useAppStore.getState().currentIdentity).toBeNull();
    expect(useAppStore.getState().credentials).toEqual([]);
    // 选中与待注入跳转随锁作废
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    // 侧栏分类选中随锁复位（解锁后不残留上一会话的树选中）
    expect(useAppStore.getState().sidebarFilter).toEqual({ kind: 'all' });
    expect(toastSuccess).toHaveBeenCalledWith('服务已锁定');
  });

  it('lockService toasts error on failure and on thrown exception', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'lockService').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'backend refused',
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.lockService();
    });
    expect(toastError).toHaveBeenCalledWith('backend refused');

    jest.spyOn(personaAPI, 'lockService').mockRejectedValueOnce(new Error('x'));
    await act(async () => {
      await result.current.lockService();
    });
    expect(toastError).toHaveBeenLastCalledWith('锁定服务失败');
  });

  it('checkServiceStatus marks error when the probe throws and loads identities when unlocked', async () => {
    jest
      .spyOn(personaAPI, 'isServiceUnlocked')
      .mockRejectedValueOnce(new Error('bridge down'))
      .mockResolvedValueOnce({ success: true, data: true, error: undefined });

    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [makeIdentity('id-a')],
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getActiveIdentity').mockResolvedValue({
      success: true,
      data: 'id-a',
      error: undefined,
    });

    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});

    // 第一次 mount：探针抛异常 → setError
    renderHook(() => usePersonaService());
    await waitFor(() => {
      expect(useAppStore.getState().error).toBe('检查服务状态失败');
    });

    // 第二次 mount：已解锁 → 拉身份列表
    renderHook(() => usePersonaService());
    await waitFor(() => {
      expect(useAppStore.getState().isUnlocked).toBe(true);
      expect(useAppStore.getState().identities).toHaveLength(1);
    });

    consoleError.mockRestore();
  });

  // -- biometric 解锁（返回原始 ApiResponse 供解锁屏分流） ------------------

  it('unlockWithBiometric succeeds, unlocks and returns the raw response', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'biometricUnlock').mockResolvedValueOnce({
      success: true,
      data: true,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [makeIdentity('id-1')],
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getActiveIdentity').mockResolvedValue({
      success: true,
      data: 'id-1',
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());

    let resp: any;
    await act(async () => {
      resp = await result.current.unlockWithBiometric('/tmp/x.db');
    });

    expect(personaAPI.biometricUnlock).toHaveBeenCalledWith('/tmp/x.db');
    expect(resp.success).toBe(true);
    expect(useAppStore.getState().isUnlocked).toBe(true);
    expect(useAppStore.getState().identities).toHaveLength(1);
    // 成功路径与密码解锁同款 toast
    expect(toastSuccess).toHaveBeenCalled();
  });

  it('unlockWithBiometric maps BIOMETRIC_RESET to a localized error without unlocking', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'biometricUnlock').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'Biometric entry missing',
      error_code: 'BIOMETRIC_RESET',
    } as any);

    const { result } = renderHook(() => usePersonaService());

    let resp: any;
    await act(async () => {
      resp = await result.current.unlockWithBiometric();
    });

    expect(resp.success).toBe(false);
    expect(resp.error_code).toBe('BIOMETRIC_RESET');
    expect(useAppStore.getState().isUnlocked).toBe(false);
    // 后端消息是英文：给用户的是本地化提示
    expect(useAppStore.getState().error).toBe(
      '指纹解锁已失效（系统钥匙串中的托管条目不存在或密码已变更），请改用主密码解锁。',
    );
  });

  it('unlockWithBiometric keeps BIOMETRIC_CANCELLED silent (cancel is not a failure)', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'biometricUnlock').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'Biometric prompt cancelled',
      error_code: 'BIOMETRIC_CANCELLED',
    } as any);

    const { result } = renderHook(() => usePersonaService());

    let resp: any;
    await act(async () => {
      resp = await result.current.unlockWithBiometric();
    });

    // 取消 ≠ 失败：错误码原样透传（解锁屏据此静默回原状态、保留指纹
    // 按钮），但全局 error 不被置位、不弹任何提示（入口 clearError 后
    // 保持 null）
    expect(resp.success).toBe(false);
    expect(resp.error_code).toBe('BIOMETRIC_CANCELLED');
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().error).toBeNull();
  });

  it('unlockWithBiometric flags PASSWORD_CHANGE_REQUIRED instead of toasting an error', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'biometricUnlock').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'password change required',
      error_code: 'PASSWORD_CHANGE_REQUIRED',
    } as any);

    const { result } = renderHook(() => usePersonaService());

    await act(async () => {
      await result.current.unlockWithBiometric();
    });

    // 与密码路径共用 forced 改密弹窗机制，不走通用错误
    expect(useAppStore.getState().passwordChangeRequired).toBe(true);
    expect(toastError).not.toHaveBeenCalled();
  });

  it('unlockWithBiometric survives an IPC rejection without unlocking', async () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'biometricUnlock').mockRejectedValueOnce(
      new Error('bridge down'),
    );

    const { result } = renderHook(() => usePersonaService());

    let resp: any;
    await act(async () => {
      resp = await result.current.unlockWithBiometric();
    });

    expect(resp.success).toBe(false);
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().error).toBe('服务初始化失败');
    // 失败不 toast：解锁屏的错误条是唯一反馈面
    expect(toastError).not.toHaveBeenCalled();
  });

  it('finalizeVaultRestore clears stale vault state and re-probes unlock status', async () => {
    // 旧库的内存残留（恢复换库后不得跨库存活）
    useAppStore.setState({
      isUnlocked: true,
      identities: [{ id: 'old-id', name: 'Old' } as any],
      currentIdentity: { id: 'old-id', name: 'Old' } as any,
      credentials: [{ id: 'old-cred' } as any],
      passwordChangeRequired: true,
    });
    const isUnlockedSpy = jest
      .spyOn(personaAPI, 'isServiceUnlocked')
      .mockResolvedValue({ success: true, data: false, error: undefined });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [],
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.finalizeVaultRestore();
    });

    // 后端换库段已取下 service（is_service_unlocked=false）→ 前端回解锁屏
    expect(isUnlockedSpy).toHaveBeenCalled();
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().isInitialized).toBe(true);
    // 旧库身份/凭据清空，重新解锁时 loadIdentities 才会按新库重选
    expect(useAppStore.getState().identities).toEqual([]);
    expect(useAppStore.getState().currentIdentity).toBeNull();
    expect(useAppStore.getState().credentials).toEqual([]);
    expect(useAppStore.getState().passwordChangeRequired).toBe(false);
  });

  // -- 补全：解锁/创建的错误与异常臂 --------------------------------------

  it('initializeService flags PASSWORD_CHANGE_REQUIRED without a generic error toast', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'initService').mockResolvedValue({
      success: false,
      error: 'policy rotation required',
      error_code: 'PASSWORD_CHANGE_REQUIRED',
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.initializeService('pw');
    });

    expect(out).toBe(false);
    expect(useAppStore.getState().passwordChangeRequired).toBe(true);
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(toastError).not.toHaveBeenCalled();
  });

  it('initializeService surfaces a plain failure through error state and toast', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'initService').mockResolvedValue({
      success: false,
      error: 'wrong master password',
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.initializeService('pw');
    });

    expect(out).toBe(false);
    expect(useAppStore.getState().error).toBe('wrong master password');
    expect(toastError).toHaveBeenCalledWith('wrong master password');
    expect(useAppStore.getState().passwordChangeRequired).toBe(false);
  });

  it('initializeService survives an IPC rejection with the localized message', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'initService').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.initializeService('pw');
    });

    expect(out).toBe(false);
    expect(useAppStore.getState().error).toBeTruthy();
    expect(toastError).toHaveBeenCalled();
    expect(useAppStore.getState().isLoading).toBe(false);
  });

  it('unlockWithBiometric surfaces a generic failure via error state', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'biometricUnlock').mockResolvedValue({
      success: false,
      error: 'os dialog denied',
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.unlockWithBiometric();
    });

    expect(out.success).toBe(false);
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().error).toBe('os dialog denied');
    expect(toastError).not.toHaveBeenCalled();
  });
});
