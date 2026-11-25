import { act, renderHook } from '@testing-library/react';
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

  const mockUnlockedOnMount = () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
  };

  it('ssh agent trio: refresh status, start, stop and load keys', async () => {
    mockUnlockedOnMount();
    const status = jest.spyOn(personaAPI, 'getSshAgentStatus');

    status.mockResolvedValueOnce({ success: true, data: { running: true } as any, error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.refreshSshAgentStatus();
    });
    expect(useAppStore.getState().sshAgentStatus).toEqual({ running: true });

    // Empty data is normalized to null (Rust actually sends null; the type narrows to undefined,
    // so the hook normalizes it with `?? null`)
    status.mockResolvedValueOnce({ success: true, data: undefined, error: undefined });
    await act(async () => {
      await result.current.refreshSshAgentStatus();
    });
    expect(useAppStore.getState().sshAgentStatus).toBeNull();

    jest.spyOn(personaAPI, 'startSshAgent').mockResolvedValueOnce({
      success: true,
      data: { running: true } as any,
      error: undefined,
    });
    await act(async () => {
      await result.current.startSshAgent('pw');
    });
    expect(toastSuccess).toHaveBeenCalledWith('SSH Agent 已启动');

    jest.spyOn(personaAPI, 'stopSshAgent').mockResolvedValueOnce({
      success: true,
      data: true,
      error: undefined,
    });
    await act(async () => {
      await result.current.stopSshAgent();
    });
    expect(useAppStore.getState().sshAgentStatus).toBeNull();
    expect(toastSuccess).toHaveBeenCalledWith('SSH Agent 已停止');

    jest.spyOn(personaAPI, 'getSshKeys').mockResolvedValueOnce({
      success: true,
      data: [{ id: 'k1' }] as any,
      error: undefined,
    });
    await act(async () => {
      await result.current.loadSshKeys();
    });
    expect(useAppStore.getState().sshKeys).toEqual([{ id: 'k1' }]);
  });

  it('ssh agent failure arms toast the API error message', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getSshAgentStatus').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'agent gone',
    });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.refreshSshAgentStatus();
    });
    expect(toastError).toHaveBeenCalledWith('agent gone');

    jest.spyOn(personaAPI, 'startSshAgent').mockRejectedValueOnce(new Error('x'));
    await act(async () => {
      await result.current.startSshAgent();
    });
    // The exception path must surface the underlying error text (the api layer normalizes a Tauri
    // string rejection into an Error, so we get the message here) instead of only the generic
    // "failed to start the SSH Agent"
    expect(toastError).toHaveBeenLastCalledWith('x');

    jest.spyOn(personaAPI, 'stopSshAgent').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'still running',
    });
    await act(async () => {
      await result.current.stopSshAgent();
    });
    expect(toastError).toHaveBeenLastCalledWith('still running');

    jest.spyOn(personaAPI, 'getSshKeys').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'keys locked',
    });
    await act(async () => {
      await result.current.loadSshKeys();
    });
    expect(toastError).toHaveBeenLastCalledWith('keys locked');
  });

  it('refreshSshAgentStatus toasts the thrown message on IPC rejection', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getSshAgentStatus').mockRejectedValue(new Error('socket gone'));

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.refreshSshAgentStatus();
    });
    expect(toastError).toHaveBeenCalledWith('socket gone');
  });

  it('startSshAgent toasts the API error when the backend refuses to start', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'startSshAgent').mockResolvedValue({
      success: false,
      error: 'agent already running',
    } as any);

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.startSshAgent('pw');
    });
    expect(toastError).toHaveBeenCalledWith('agent already running');
    expect(useAppStore.getState().sshAgentStatus).toBeNull();
  });

  it('stopSshAgent toasts the thrown message on IPC rejection', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'stopSshAgent').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.stopSshAgent();
    });
    expect(toastError).toHaveBeenCalledWith('ipc down');
  });

  it('loadSshKeys toasts the localized message on IPC rejection', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getSshKeys').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.loadSshKeys();
    });
    expect(toastError).toHaveBeenCalled();
    expect(useAppStore.getState().sshKeys).toEqual([]);
  });

  it('ssh key file seams normalize IPC rejections into failed responses', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'inspectSshKeyFile').mockRejectedValue(new Error('bad path'));
    jest.spyOn(personaAPI, 'importSshKey').mockRejectedValue(new Error('denied'));
    jest.spyOn(personaAPI, 'generateSshKey').mockRejectedValue(new Error('quota'));

    const { result } = renderHook(() => usePersonaService());
    let inspected: any;
    let imported: any;
    let generated: any;
    await act(async () => {
      inspected = await result.current.inspectSshKeyFile('/tmp/k');
      imported = await result.current.importSshKey({
        identity_id: 'id-1',
        path: '/tmp/k',
      });
      generated = await result.current.generateSshKey({
        identity_id: 'id-1',
        key_type: 'ed25519',
      });
    });

    expect(inspected.success).toBe(false);
    expect(inspected.error).toBe('bad path');
    expect(imported.success).toBe(false);
    expect(imported.error).toBe('denied');
    expect(generated.success).toBe(false);
    expect(generated.error).toBe('quota');
  });
});
