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

  it('generatePassword returns generated value or empty string on failure', async () => {
    mockUnlockedOnMount();
    const gen = jest.spyOn(personaAPI, 'generatePassword');

    gen.mockResolvedValueOnce({ success: true, data: 's3cret!', error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await expect(result.current.generatePassword()).resolves.toBe('s3cret!');
    });

    gen.mockResolvedValueOnce({ success: false, data: undefined, error: 'rng down' });
    await act(async () => {
      await expect(result.current.generatePassword()).resolves.toBe('');
    });
    expect(toastError).toHaveBeenCalledWith('rng down');
  });

  it('getCredentialData returns payload or null on failure', async () => {
    mockUnlockedOnMount();
    const get = jest.spyOn(personaAPI, 'getCredentialData');

    get.mockResolvedValueOnce({ success: true, data: { password: 'p' } as any, error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await expect(result.current.getCredentialData('c1')).resolves.toEqual({ password: 'p' });
    });

    get.mockResolvedValueOnce({ success: false, data: undefined, error: 'locked' });
    await act(async () => {
      await expect(result.current.getCredentialData('c1')).resolves.toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('locked');
  });

  it('getTotpCode returns the response or null on failure', async () => {
    mockUnlockedOnMount();
    const totp = jest.spyOn(personaAPI, 'getTotpCode');

    const totpResponse = {
      code: '123456',
      remaining_seconds: 25,
      period: 30,
      digits: 6,
      algorithm: 'SHA1',
      issuer: 'Example',
      account_name: 'alice',
    };
    totp.mockResolvedValueOnce({ success: true, data: totpResponse, error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await expect(result.current.getTotpCode('c1')).resolves.toEqual(totpResponse);
    });

    totp.mockResolvedValueOnce({ success: false, data: undefined, error: 'no totp' });
    await act(async () => {
      await expect(result.current.getTotpCode('c1')).resolves.toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('no totp');
  });

  it('fetchFavicon caches the entry and toasts both ways', async () => {
    mockUnlockedOnMount();

    const fav = jest.spyOn(personaAPI, 'fetchCredentialFavicon');
    fav.mockResolvedValueOnce({
      success: true,
      data: { host: 'a.com', mime_type: 'image/png', data: 'AAA' },
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      const entry = await result.current.fetchFavicon('c1');
      expect(entry).toEqual({ host: 'a.com', mime_type: 'image/png', data: 'AAA' });
    });
    expect(useAppStore.getState().faviconCache['a.com']).toEqual({
      mime_type: 'image/png',
      data: 'AAA',
    });
    expect(toastSuccess).toHaveBeenCalledWith('图标已获取');

    // Failure arm: nothing gets written to the cache
    fav.mockResolvedValueOnce({ success: false, data: undefined, error: '404' });
    await act(async () => {
      expect(await result.current.fetchFavicon('c1')).toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('404');
    expect(useAppStore.getState().faviconCache['a.com']).toBeDefined();

    // Throwing arm: a single toast for everything
    fav.mockRejectedValueOnce(new Error('ipc down'));
    await act(async () => {
      expect(await result.current.fetchFavicon('c1')).toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('获取图标失败');
  });

  it('getCredentialHistory returns entries on success and empty list on failure', async () => {
    mockUnlockedOnMount();
    const entries = [{ version: 1 }] as any[];
    jest.spyOn(personaAPI, 'getCredentialHistory').mockResolvedValue({
      success: true,
      data: entries,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getCredentialHistory('c1');
    });
    expect(out).toEqual(entries);

    jest.spyOn(personaAPI, 'getCredentialHistory').mockResolvedValue({
      success: false,
      error: 'no history',
    } as any);
    await act(async () => {
      out = await result.current.getCredentialHistory('c1');
    });
    expect(out).toEqual([]);
    expect(toastError).toHaveBeenCalledWith('no history');
  });

  it('getCredentialHistory survives an IPC rejection with empty list', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getCredentialHistory').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getCredentialHistory('c1');
    });
    expect(out).toEqual([]);
    expect(toastError).toHaveBeenCalled();
  });

  it('getCredentialCustomFields returns the array on success and null on failure', async () => {
    mockUnlockedOnMount();
    const fields = [{ label: 'k', value: 'v' }] as any[];
    jest.spyOn(personaAPI, 'getCredentialCustomFields').mockResolvedValue({
      success: true,
      data: fields,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getCredentialCustomFields('c1');
    });
    expect(out).toEqual(fields);

    // Non-array data (a broken backend state) -> null, so the panel shows an error row rather than an empty state
    jest.spyOn(personaAPI, 'getCredentialCustomFields').mockResolvedValue({
      success: true,
      data: null,
      error: undefined,
    } as any);
    await act(async () => {
      out = await result.current.getCredentialCustomFields('c1');
    });
    expect(out).toBeNull();
  });

  it('getCredentialCustomFields survives an IPC rejection and returns null', async () => {
    mockUnlockedOnMount();
    jest
      .spyOn(personaAPI, 'getCredentialCustomFields')
      .mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getCredentialCustomFields('c1');
    });
    expect(out).toBeNull();
  });

  it('generatePassword survives an IPC rejection with empty string', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'generatePassword').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: string | undefined;
    await act(async () => {
      out = await result.current.generatePassword();
    });
    expect(out).toBe('');
    expect(toastError).toHaveBeenCalled();
  });

  it('getCredentialData survives an IPC rejection with null', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getCredentialData').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getCredentialData('c1');
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
  });

  it('getTotpCode survives an IPC rejection with null', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getTotpCode').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.getTotpCode('c1');
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
  });
});
