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

  it('listAttachments returns entries on success and empty list on failure', async () => {
    mockUnlockedOnMount();
    const entries = [{ id: 'att-1' }] as any[];
    jest.spyOn(personaAPI, 'listAttachments').mockResolvedValue({
      success: true,
      data: entries,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.listAttachments('c1');
    });
    expect(out).toEqual(entries);

    jest.spyOn(personaAPI, 'listAttachments').mockResolvedValue({
      success: false,
      error: 'locked',
    } as any);
    await act(async () => {
      out = await result.current.listAttachments('c1');
    });
    expect(out).toEqual([]);
    expect(toastError).toHaveBeenCalledWith('locked');
  });

  it('listAttachments survives an IPC rejection with empty list', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'listAttachments').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.listAttachments('c1');
    });
    expect(out).toEqual([]);
    expect(toastError).toHaveBeenCalled();
  });

  it('attachFileToCredential returns the entry on success and reports failure', async () => {
    mockUnlockedOnMount();
    const entry = { id: 'att-1' } as any;
    jest.spyOn(personaAPI, 'attachFileToCredential').mockResolvedValue({
      success: true,
      data: entry,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.attachFileToCredential('c1', '/tmp/a.txt', true);
    });
    expect(out).toEqual(entry);

    jest.spyOn(personaAPI, 'attachFileToCredential').mockResolvedValue({
      success: false,
      error: 'file too large',
    } as any);
    await act(async () => {
      out = await result.current.attachFileToCredential('c1', '/tmp/a.txt', true);
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalledWith('file too large');
  });

  it('attachFileToCredential survives an IPC rejection and returns null', async () => {
    mockUnlockedOnMount();
    jest
      .spyOn(personaAPI, 'attachFileToCredential')
      .mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.attachFileToCredential('c1', '/tmp/a.txt', true);
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
  });

  it('saveAttachmentToFile returns true on success and reports failure', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'saveAttachmentToFile').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.saveAttachmentToFile('att-1', '/tmp/out');
    });
    expect(out).toBe(true);

    jest.spyOn(personaAPI, 'saveAttachmentToFile').mockResolvedValue({
      success: false,
      error: 'path not writable',
    } as any);
    await act(async () => {
      out = await result.current.saveAttachmentToFile('att-1', '/tmp/out');
    });
    expect(out).toBe(false);
    expect(toastError).toHaveBeenCalledWith('path not writable');
  });

  it('saveAttachmentToFile survives an IPC rejection and returns false', async () => {
    mockUnlockedOnMount();
    jest
      .spyOn(personaAPI, 'saveAttachmentToFile')
      .mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.saveAttachmentToFile('att-1', '/tmp/out');
    });
    expect(out).toBe(false);
    expect(toastError).toHaveBeenCalled();
  });

  it('deleteAttachment returns true on success and reports failure', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'deleteAttachment').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.deleteAttachment('att-1');
    });
    expect(out).toBe(true);

    jest.spyOn(personaAPI, 'deleteAttachment').mockResolvedValue({
      success: false,
      error: 'attachment in use',
    } as any);
    await act(async () => {
      out = await result.current.deleteAttachment('att-1');
    });
    expect(out).toBe(false);
    expect(toastError).toHaveBeenCalledWith('attachment in use');
  });

  it('deleteAttachment survives an IPC rejection and returns false', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'deleteAttachment').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.deleteAttachment('att-1');
    });
    expect(out).toBe(false);
    expect(toastError).toHaveBeenCalled();
  });

  // -- remaining catch / else arms -------------------------------------
});
