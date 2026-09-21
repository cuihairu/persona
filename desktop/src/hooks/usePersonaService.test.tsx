import { act, renderHook, waitFor } from '@testing-library/react';
import { usePersonaService } from './usePersonaService';
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

  it('lockService clears session state on success', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({
      isUnlocked: true,
      selectedCredentialId: 'c1',
      pendingCredentialSelection: { identityId: 'i1', credentialId: 'c1' },
      sidebarFilter: { kind: 'type', value: 'Password' },
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

  it('switchIdentity skips the toast when called with silent', async () => {
    mockUnlockedOnMount();
    const identity = makeIdentity('i-silent');
    jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    } as any);
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockResolvedValue({
      success: true,
      data: [],
      error: undefined,
    } as any);

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.switchIdentity(identity, { silent: true });
    });
    // 搜索跳转是手段不是用户动作，切换 toast 属噪声
    expect(toastSuccess).not.toHaveBeenCalled();
    expect(useAppStore.getState().currentIdentity?.id).toBe('i-silent');

    // 不传 silent 保持原行为
    await act(async () => {
      await result.current.switchIdentity(identity);
    });
    expect(toastSuccess).toHaveBeenCalledWith(`已切换到 ${identity.name}`);
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

  it('loadIdentities prefers workspace active identity match without rewriting it', async () => {
    mockUnlockedOnMount();
    const a = makeIdentity('id-a');
    const b = makeIdentity('id-b');
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [a, b],
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getActiveIdentity').mockResolvedValue({
      success: true,
      data: 'id-b',
      error: undefined,
    });
    const setActive = jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.loadIdentities();
    });

    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');
    expect(setActive).not.toHaveBeenCalled();
  });

  it('loadIdentities falls back to first identity and rewrites active when no match', async () => {
    mockUnlockedOnMount();
    const a = makeIdentity('id-a');
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [a],
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getActiveIdentity').mockResolvedValue({
      success: true,
      data: null,
      error: undefined,
    });
    const setActive = jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.loadIdentities();
    });

    expect(useAppStore.getState().currentIdentity?.id).toBe('id-a');
    expect(setActive).toHaveBeenCalledWith('id-a');
  });

  it('loadIdentities sets error on failure and on exception', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'db gone',
    });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.loadIdentities();
    });
    expect(useAppStore.getState().error).toBe('db gone');

    jest.spyOn(personaAPI, 'getIdentities').mockRejectedValueOnce(new Error('x'));
    await act(async () => {
      await result.current.loadIdentities();
    });
    expect(useAppStore.getState().error).toBe('加载身份失败');
  });

  it('createIdentity reloads, selects and activates the new identity', async () => {
    mockUnlockedOnMount();
    const created = makeIdentity('id-new', 'New');
    jest.spyOn(personaAPI, 'createIdentity').mockResolvedValue({
      success: true,
      data: created,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [created],
      error: undefined,
    });
    const setActive = jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.createIdentity('New', 'Personal');
    });

    expect(useAppStore.getState().currentIdentity?.id).toBe('id-new');
    expect(setActive).toHaveBeenCalledWith('id-new');
    expect(toastSuccess).toHaveBeenCalledWith('身份创建成功');
  });

  it('createIdentity keeps working when active write fails, but surfaces API failure', async () => {
    mockUnlockedOnMount();
    const created = makeIdentity('id-new', 'New');
    jest.spyOn(personaAPI, 'createIdentity').mockResolvedValueOnce({
      success: true,
      data: created,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [created],
      error: undefined,
    });
    // setActiveIdentity 抛异常 → 静默吞掉，创建流程不受影响
    jest.spyOn(personaAPI, 'setActiveIdentity').mockRejectedValueOnce(new Error('busy'));

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.createIdentity('New', 'Personal');
    });
    expect(toastSuccess).toHaveBeenCalledWith('身份创建成功');

    // 失败臂
    jest.spyOn(personaAPI, 'createIdentity').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'duplicate name',
    });
    await act(async () => {
      await result.current.createIdentity('New', 'Personal');
    });
    expect(toastError).toHaveBeenCalledWith('duplicate name');
    expect(useAppStore.getState().error).toBe('duplicate name');
  });

  it('updateIdentity refreshes list and returns updated identity', async () => {
    mockUnlockedOnMount();
    const updated = makeIdentity('id-a', 'Renamed');
    jest.spyOn(personaAPI, 'updateIdentity').mockResolvedValue({
      success: true,
      data: updated,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [updated],
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateIdentity(makeIdentity('id-a', 'Renamed'));
    });

    expect(out?.id).toBe('id-a');
    expect(useAppStore.getState().currentIdentity?.name).toBe('Renamed');
    expect(toastSuccess).toHaveBeenCalledWith('身份已更新');

    // 失败臂返回 null
    jest.spyOn(personaAPI, 'updateIdentity').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'nope',
    });
    await act(async () => {
      out = await result.current.updateIdentity(makeIdentity('id-a'));
    });
    expect(out).toBeNull();
    expect(toastError).toHaveBeenCalledWith('nope');
  });

  it('deleteIdentity clears current session when deleting the active identity', async () => {
    mockUnlockedOnMount();
    const current = makeIdentity('id-a');
    useAppStore.setState({ currentIdentity: current, credentials: [makeCredential('c1')] });
    jest.spyOn(personaAPI, 'deleteIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [],
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    let ok: boolean | undefined;
    await act(async () => {
      ok = await result.current.deleteIdentity('id-a');
    });

    expect(ok).toBe(true);
    expect(useAppStore.getState().currentIdentity).toBeNull();
    expect(useAppStore.getState().credentials).toEqual([]);
    expect(toastSuccess).toHaveBeenCalledWith('身份已删除');
  });

  it('deleteIdentity keeps session for non-current identity and reports failures', async () => {
    mockUnlockedOnMount();
    const current = makeIdentity('id-keep');
    useAppStore.setState({ currentIdentity: current });
    const del = jest.spyOn(personaAPI, 'deleteIdentity');

    // 非 current：不清 session
    del.mockResolvedValueOnce({ success: true, data: true, error: undefined });
    jest.spyOn(personaAPI, 'getIdentities').mockResolvedValue({
      success: true,
      data: [current],
      error: undefined,
    });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.deleteIdentity('id-gone');
    });
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-keep');

    // 失败臂
    del.mockResolvedValueOnce({ success: false, data: undefined, error: 'locked' });
    let ok: boolean | undefined;
    await act(async () => {
      ok = await result.current.deleteIdentity('id-gone');
    });
    expect(ok).toBe(false);
    expect(toastError).toHaveBeenCalledWith('locked');

    // 异常臂
    del.mockRejectedValueOnce(new Error('x'));
    await act(async () => {
      ok = await result.current.deleteIdentity('id-gone');
    });
    expect(ok).toBe(false);
    expect(toastError).toHaveBeenLastCalledWith('删除身份失败');
  });

  it('switchIdentity selects identity, loads its credentials and toasts', async () => {
    mockUnlockedOnMount();
    const target = makeIdentity('id-b', 'B');
    jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValue({
      success: true,
      data: true,
      error: undefined,
    });
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockResolvedValue({
      success: true,
      data: [makeCredential('c-b')],
      error: undefined,
    });

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.switchIdentity(target);
    });

    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');
    expect(useAppStore.getState().credentials).toHaveLength(1);
    expect(toastSuccess).toHaveBeenCalledWith('已切换到 B');
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

    // 失败臂：不写缓存
    fav.mockResolvedValueOnce({ success: false, data: undefined, error: '404' });
    await act(async () => {
      expect(await result.current.fetchFavicon('c1')).toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('404');
    expect(useAppStore.getState().faviconCache['a.com']).toBeDefined();

    // 抛错臂：统一 toast
    fav.mockRejectedValueOnce(new Error('ipc down'));
    await act(async () => {
      expect(await result.current.fetchFavicon('c1')).toBeNull();
    });
    expect(toastError).toHaveBeenCalledWith('获取图标失败');
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

  it('ssh agent trio: refresh status, start, stop and load keys', async () => {
    mockUnlockedOnMount();
    const status = jest.spyOn(personaAPI, 'getSshAgentStatus');

    status.mockResolvedValueOnce({ success: true, data: { running: true } as any, error: undefined });
    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.refreshSshAgentStatus();
    });
    expect(useAppStore.getState().sshAgentStatus).toEqual({ running: true });

    // data 为空时归一为 null（Rust 实际下发 null；类型收窄为 undefined，
    // hook 侧 `?? null` 统一归一）
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
    expect(toastError).toHaveBeenLastCalledWith('启动 SSH Agent 失败');

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
});
