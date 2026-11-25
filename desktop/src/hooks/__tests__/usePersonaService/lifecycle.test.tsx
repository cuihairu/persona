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

  // -- remaining coverage: success/failure/exception arms of each action ----

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
    // The selection and the pending injection jump are invalidated with the lock
    expect(useAppStore.getState().selectedCredentialId).toBeNull();
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    // Sidebar category selection is reset with the lock (no leftover tree selection from the previous session after unlocking)
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

    // First mount: the probe throws -> setError
    renderHook(() => usePersonaService());
    await waitFor(() => {
      expect(useAppStore.getState().error).toBe('检查服务状态失败');
    });

    // Second mount: already unlocked -> fetch the identity list
    renderHook(() => usePersonaService());
    await waitFor(() => {
      expect(useAppStore.getState().isUnlocked).toBe(true);
      expect(useAppStore.getState().identities).toHaveLength(1);
    });

    consoleError.mockRestore();
  });

  // -- biometric unlock (returns the raw ApiResponse for the unlock screen to route on) --

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
    // The success path toasts the same way password unlock does
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
    // The backend message is English: what the user sees is the localized hint
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

    // Cancel is not failure: the error code is passed through untouched (the unlock screen uses it to
    // silently return to its previous state and keep the fingerprint button), but the global error is
    // not set and nothing is toasted (it stays null after the entry point's clearError)
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

    // Shares the password path's forced password-change dialog mechanism, instead of the generic error
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
    // No toast on failure: the unlock screen's error bar is the only feedback surface
    expect(toastError).not.toHaveBeenCalled();
  });

  it('finalizeVaultRestore clears stale vault state and re-probes unlock status', async () => {
    // In-memory leftovers from the old vault (must not survive a restore that swaps the vault)
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

    // The backend's vault-swap stage has already taken the service down (is_service_unlocked=false) -> the frontend returns to the unlock screen
    expect(isUnlockedSpy).toHaveBeenCalled();
    expect(useAppStore.getState().isUnlocked).toBe(false);
    expect(useAppStore.getState().isInitialized).toBe(true);
    // The old vault's identities/credentials are cleared, so loadIdentities will reselect against the new vault once unlocking happens again
    expect(useAppStore.getState().identities).toEqual([]);
    expect(useAppStore.getState().currentIdentity).toBeNull();
    expect(useAppStore.getState().credentials).toEqual([]);
    expect(useAppStore.getState().passwordChangeRequired).toBe(false);
  });

  // -- remaining coverage: error and exception arms of unlock/create -------

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
