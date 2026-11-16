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


  const makeCredential = (id: string) =>
    ({
      id,
      identity_id: 'id-1',
      title: 'cred',
      username: null,
      password: null,
      url: null,
      notes: null,
      totp_secret: null,
      credential_type: 'Login',
      tags: [],
      is_favorite: false,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
    }) as any;

  /** 每个 action 测试的公共前置：mount 时的 status 轮询 mock 成已解锁。 */

  const mockUnlockedOnMount = () => {
    jest.spyOn(personaAPI, 'isServiceUnlocked').mockResolvedValue({
      success: true,
      data: false,
      error: undefined,
    });
  };

  it('loadCredentialsForIdentity clears pending selection when loading fails', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({
      pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
    });

    // success: false 路径
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'db busy',
    });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.loadCredentialsForIdentity('i1');
    });
    // 凭据没加载出来 pending 永远不会被注入；清掉防下次进该身份突然选中
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    expect(useAppStore.getState().error).toBe('db busy');

    // throw 路径同样清理
    useAppStore.setState({
      pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
    });
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockRejectedValueOnce(
      new Error('ipc gone'),
    );
    await act(async () => {
      await result.current.loadCredentialsForIdentity('i1');
    });
    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
  });

  it('drops a stale credential load that resolves after a newer switch (JS-5)', async () => {
    mockUnlockedOnMount();
    const identityA = makeIdentity('id-a');
    const identityB = makeIdentity('id-b');
    jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    } as any);

    // A 的凭据加载慢（手动控制 resolve），B 的即时返回
    let resolveA: (v: unknown) => void = () => {};
    const slowA = new Promise((r) => {
      resolveA = r;
    });
    const getCreds = jest.spyOn(personaAPI, 'getCredentialsForIdentity');
    getCreds.mockImplementationOnce(() => slowA as any); // 第一次调用 = A（慢）
    getCreds.mockResolvedValueOnce({
      success: true,
      data: [makeCredential('b-cred')],
      error: undefined,
    } as any); // B

    const { result } = renderHook(() => usePersonaService());

    let pA: Promise<boolean> = Promise.resolve(false);
    act(() => {
      pA = result.current.switchIdentity(identityA, { silent: true });
    });
    // 先让 A 完成 setActiveIdentity 并进入慢凭据加载（A 此刻是 currentIdentity）
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    // B 切换完整落地（currentIdentity + credentials 都是 B）
    await act(async () => {
      await result.current.switchIdentity(identityB, { silent: true });
    });
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');
    expect(useAppStore.getState().credentials).toHaveLength(1);
    expect(useAppStore.getState().credentials[0].id).toBe('b-cred');

    // A 的慢凭据响应后到：序号守卫丢弃，不得覆盖 B 的凭据
    await act(async () => {
      resolveA({ success: true, data: [makeCredential('a-cred')], error: undefined });
      await pA;
    });
    expect(useAppStore.getState().credentials).toHaveLength(1);
    expect(useAppStore.getState().credentials[0].id).toBe('b-cred');
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');
  });

  it('createCredential reloads current identity credentials on success', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({ currentIdentity: makeIdentity('id-a') });
    jest.spyOn(personaAPI, 'createCredential').mockResolvedValue({
      success: true,
      data: makeCredential('c-new'),
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockResolvedValue({
      success: true,
      data: [makeCredential('c-new')],
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.createCredential({ identity_id: 'id-a' });
    });

    expect(out?.id).toBe('c-new');
    expect(useAppStore.getState().credentials).toHaveLength(1);
    expect(toastSuccess).toHaveBeenCalledWith('凭据创建成功');

    // 失败臂
    jest.spyOn(personaAPI, 'createCredential').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'validation',
    });
    await act(async () => {
      out = await result.current.createCredential({ identity_id: 'id-a' });
    });
    expect(toastError).toHaveBeenCalledWith('validation');
  });

  it('searchCredentials returns data or empty list on failure', async () => {
    mockUnlockedOnMount();
    const search = jest.spyOn(personaAPI, 'searchCredentials');

    search.mockResolvedValueOnce({
      success: true,
      data: [makeCredential('c1')],
      error: undefined,
    });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await expect(result.current.searchCredentials('q')).resolves.toHaveLength(1);
    });

    search.mockResolvedValueOnce({ success: false, data: undefined, error: 'busy' });
    await act(async () => {
      await expect(result.current.searchCredentials('q')).resolves.toEqual([]);
    });
    expect(toastError).toHaveBeenCalledWith('busy');

    search.mockRejectedValueOnce(new Error('x'));
    await act(async () => {
      await expect(result.current.searchCredentials('q')).resolves.toEqual([]);
    });
  });

  it('toggleCredentialFavorite swaps the credential in place with both toast variants', async () => {
    mockUnlockedOnMount();
    const c1 = makeCredential('c1');
    useAppStore.setState({ credentials: [c1] });

    const fav = jest.spyOn(personaAPI, 'toggleCredentialFavorite');
    const toggledOn = { ...c1, is_favorite: true };
    fav.mockResolvedValueOnce({ success: true, data: toggledOn, error: undefined });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.toggleCredentialFavorite('c1');
    });
    expect(useAppStore.getState().credentials[0].is_favorite).toBe(true);
    expect(toastSuccess).toHaveBeenCalledWith('已加入收藏');

    // 取消收藏臂
    const toggledOff = { ...c1, is_favorite: false };
    fav.mockResolvedValueOnce({ success: true, data: toggledOff, error: undefined });
    await act(async () => {
      await result.current.toggleCredentialFavorite('c1');
    });
    expect(toastSuccess).toHaveBeenLastCalledWith('已移出收藏');

    // 失败臂
    fav.mockResolvedValueOnce({ success: false, data: undefined, error: 'busy' });
    await act(async () => {
      await result.current.toggleCredentialFavorite('c1');
    });
    expect(toastError).toHaveBeenCalledWith('busy');
  });

  it('deleteCredential filters it out of the list and reports failures', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({ credentials: [makeCredential('c1'), makeCredential('c2')] });
    const del = jest.spyOn(personaAPI, 'deleteCredential');

    del.mockResolvedValueOnce({ success: true, data: true, error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await expect(result.current.deleteCredential('c1')).resolves.toBe(true);
    });
    expect(useAppStore.getState().credentials.map((c) => c.id)).toEqual(['c2']);

    del.mockResolvedValueOnce({ success: false, data: undefined, error: 'busy' });
    await act(async () => {
      await expect(result.current.deleteCredential('c1')).resolves.toBe(false);
    });
    expect(toastError).toHaveBeenCalledWith('busy');
  });

  it('createCredential survives an IPC rejection with error state', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({ currentIdentity: makeIdentity('id-1') });
    jest.spyOn(personaAPI, 'createCredential').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.createCredential({ title: 'x' });
    });

    expect(out).toBeUndefined();
    expect(useAppStore.getState().error).toBeTruthy();
    expect(toastError).toHaveBeenCalled();
  });

  // -- updateCredential / updateCredentialData ---------------------------

  it('updateCredential reloads credentials on success and returns the updated row', async () => {
    mockUnlockedOnMount();
    const updated = makeCredential('c1');
    useAppStore.setState({ currentIdentity: makeIdentity('id-1') });
    const getSpy = jest
      .spyOn(personaAPI, 'getCredentialsForIdentity')
      .mockResolvedValue({ success: true, data: [updated], error: undefined });
    jest.spyOn(personaAPI, 'updateCredential').mockResolvedValue({
      success: true,
      data: updated,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateCredential({ id: 'c1' } as any);
    });

    expect(out?.id).toBe('c1');
    expect(getSpy).toHaveBeenCalledWith('id-1');
    expect(useAppStore.getState().credentials[0]?.id).toBe('c1');
    expect(toastSuccess).toHaveBeenCalled();
  });

  it('updateCredential reports failure without reloading', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({ currentIdentity: makeIdentity('id-1') });
    const getSpy = jest
      .spyOn(personaAPI, 'getCredentialsForIdentity')
      .mockResolvedValue({ success: true, data: [], error: undefined });
    jest.spyOn(personaAPI, 'updateCredential').mockResolvedValue({
      success: false,
      error: 'name conflict',
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateCredential({ id: 'c1' } as any);
    });

    expect(out).toBeNull();
    expect(getSpy).not.toHaveBeenCalled();
    expect(toastError).toHaveBeenCalledWith('name conflict');
  });

  it('updateCredential survives an IPC rejection and returns null', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'updateCredential').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateCredential({ id: 'c1' } as any);
    });

    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
    expect(useAppStore.getState().isLoading).toBe(false);
  });

  it('updateCredentialData passes the raw response through untouched', async () => {
    mockUnlockedOnMount();
    const raw = { success: true, data: { version: 2 }, error: undefined } as any;
    const spy = jest.spyOn(personaAPI, 'updateCredentialData').mockResolvedValue(raw);

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateCredentialData({ id: 'c1' } as any);
    });

    expect(out).toBe(raw);
    expect(spy).toHaveBeenCalledWith({ id: 'c1' });
  });

  // -- 历史与恢复 ---------------------------------------------------------

  it('restoreCredentialVersion reloads on success and reports failure both ways', async () => {
    mockUnlockedOnMount();
    const updated = makeCredential('c1');
    useAppStore.setState({ currentIdentity: makeIdentity('id-1') });
    const getSpy = jest
      .spyOn(personaAPI, 'getCredentialsForIdentity')
      .mockResolvedValue({ success: true, data: [updated], error: undefined });
    jest.spyOn(personaAPI, 'restoreCredentialVersion').mockResolvedValue({
      success: true,
      data: updated,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.restoreCredentialVersion('c1', 3);
    });
    expect(out?.id).toBe('c1');
    expect(getSpy).toHaveBeenCalledWith('id-1');
    expect(toastSuccess).toHaveBeenCalled();

    jest.spyOn(personaAPI, 'restoreCredentialVersion').mockResolvedValue({
      success: false,
      error: 'version gone',
    } as any);
    await act(async () => {
      out = await result.current.restoreCredentialVersion('c1', 3);
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalledWith('version gone');
  });

  it('restoreCredentialVersion survives an IPC rejection and returns null', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'restoreCredentialVersion').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.restoreCredentialVersion('c1', 3);
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
  });

  // -- 附件四动作 ---------------------------------------------------------

  it('toggleCredentialFavorite survives an IPC rejection with null', async () => {
    mockUnlockedOnMount();
    jest
      .spyOn(personaAPI, 'toggleCredentialFavorite')
      .mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.toggleCredentialFavorite('c1');
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalled();
  });

  it('deleteCredential survives an IPC rejection with false', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'deleteCredential').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: boolean | undefined;
    await act(async () => {
      out = await result.current.deleteCredential('c1');
    });
    expect(out).toBe(false);
    expect(toastError).toHaveBeenCalled();
  });
});
