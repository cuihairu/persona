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

  it('drops a stale identity switch whose activate resolves after a newer one', async () => {
    mockUnlockedOnMount();
    const identityA = makeIdentity('id-a');
    const identityB = makeIdentity('id-b');
    let resolveActivateA: (v: unknown) => void = () => {};
    const slowActivateA = new Promise((r) => {
      resolveActivateA = r;
    });
    const setActive = jest.spyOn(personaAPI, 'setActiveIdentity');
    setActive.mockImplementationOnce(() => slowActivateA as any); // A 慢
    setActive.mockResolvedValueOnce({
      success: true,
      data: true,
      error: undefined,
    } as any); // B 快
    jest.spyOn(personaAPI, 'getCredentialsForIdentity').mockResolvedValue({
      success: true,
      data: [],
      error: undefined,
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let pA: Promise<boolean> = Promise.resolve(false);
    act(() => {
      pA = result.current.switchIdentity(identityA, { silent: true });
    });
    await act(async () => {
      await result.current.switchIdentity(identityB, { silent: true });
    });
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');

    // A 的 activate 后到：switchSeq 守卫丢弃，不得把 currentIdentity 拉回 A
    await act(async () => {
      resolveActivateA({ success: true, data: true, error: undefined });
      await pA;
    });
    expect(useAppStore.getState().currentIdentity?.id).toBe('id-b');
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

  it('switchIdentity keeps the original identity and reports errors when the active write fails', async () => {
    mockUnlockedOnMount();
    // 原身份不得被成功的切换覆盖：后端拒绝时界面必须停在原地
    useAppStore.setState({ currentIdentity: makeIdentity('i-keep') });

    const setActive = jest.spyOn(personaAPI, 'setActiveIdentity');
    const loadCreds = jest.spyOn(personaAPI, 'getCredentialsForIdentity');

    // success:false 臂：置错 + 报错 + 不弹成功，且不拉取目标身份凭据
    setActive.mockResolvedValueOnce({ success: false, data: undefined, error: 'db busy' });
    const { result } = renderHook(() => usePersonaService());
    let ok: boolean | undefined;
    await act(async () => {
      ok = await result.current.switchIdentity(makeIdentity('i-new', 'New'));
    });
    expect(ok).toBe(false);
    expect(useAppStore.getState().currentIdentity?.id).toBe('i-keep');
    expect(useAppStore.getState().error).toBe('db busy');
    expect(toastError).toHaveBeenCalledWith('db busy');
    expect(toastSuccess).not.toHaveBeenCalled();
    expect(loadCreds).not.toHaveBeenCalled();

    // 抛异常臂：同样保留原身份并透出底层错误
    setActive.mockRejectedValueOnce(new Error('ipc down'));
    await act(async () => {
      ok = await result.current.switchIdentity(makeIdentity('i-new', 'New'));
    });
    expect(ok).toBe(false);
    expect(useAppStore.getState().currentIdentity?.id).toBe('i-keep');
    expect(useAppStore.getState().error).toBe('ipc down');
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('switchIdentity silent still surfaces the failure (silent only mutes the success toast)', async () => {
    mockUnlockedOnMount();
    useAppStore.setState({ currentIdentity: makeIdentity('i-keep') });
    // 无后端消息：走本地化兜底，静默成功在此是身份上下文可信性问题
    jest.spyOn(personaAPI, 'setActiveIdentity').mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: undefined,
    } as any);

    const { result } = renderHook(() => usePersonaService());
    let ok: boolean | undefined;
    await act(async () => {
      ok = await result.current.switchIdentity(makeIdentity('i-new', 'New'), { silent: true });
    });
    expect(ok).toBe(false);
    expect(useAppStore.getState().currentIdentity?.id).toBe('i-keep');
    expect(useAppStore.getState().error).toBe('切换身份失败');
    expect(toastError).toHaveBeenCalledWith('切换身份失败');
    expect(toastSuccess).not.toHaveBeenCalled();
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
    // setActiveIdentity 抛异常 → 创建流程不受影响，但激活失败必须可见
    // （workspace 活动身份仍指旧身份，静默成功会误导用户已全局切换）
    jest.spyOn(personaAPI, 'setActiveIdentity').mockRejectedValueOnce(new Error('busy'));

    const { result } = renderHook(() => usePersonaService());
    await act(async () => {
      await result.current.createIdentity('New', 'Personal');
    });
    expect(toastSuccess).toHaveBeenCalledWith('身份创建成功');
    expect(toastError).toHaveBeenCalledWith('身份已创建，但设为当前身份失败');

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

  it('createIdentity survives an IPC rejection with error state', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'createIdentity').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.createIdentity('Work', 'Work', undefined);
    });

    expect(out).toBeUndefined();
    expect(useAppStore.getState().error).toBeTruthy();
    expect(toastError).toHaveBeenCalled();
    expect(useAppStore.getState().isLoading).toBe(false);
  });

  it('updateIdentity survives an IPC rejection and returns null', async () => {
    mockUnlockedOnMount();
    jest.spyOn(personaAPI, 'updateIdentity').mockRejectedValue(new Error('ipc down'));

    const { result } = renderHook(() => usePersonaService());
    let out: any;
    await act(async () => {
      out = await result.current.updateIdentity(makeIdentity('id-1'));
    });

    expect(out).toBeNull();
    expect(useAppStore.getState().error).toBeTruthy();
    expect(toastError).toHaveBeenCalled();
  });
});
