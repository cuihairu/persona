import { renderHook, act, waitFor } from '@testing-library/react';
import toast from 'react-hot-toast';
import { usePasskeyApprovals, PASSKEY_APPROVAL_EVENT } from './usePasskeyApprovals';
import { personaAPI } from '@/utils/api';
import type { PasskeyApprovalRequest } from '@/types';

type ListenHandler = (event: { payload: PasskeyApprovalRequest }) => void;

const listenMock = jest.fn<
  Promise<(cb: ListenHandler) => void>,
  [string, ListenHandler]
>();
let capturedHandler: ListenHandler | null = null;

const sendNotificationMock = jest.fn();

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: ListenHandler) => listenMock(event, handler),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    passkeyApprovalRespond: jest.fn(),
  },
}));

jest.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: jest.fn().mockResolvedValue(true),
  requestPermission: jest.fn().mockResolvedValue(true),
  sendNotification: (...args: unknown[]) => sendNotificationMock(...args),
}));

const sampleRequest: PasskeyApprovalRequest = {
  request_id: 'passkey-1',
  operation: 'passkey_assert',
  rp_id: null,
  origin: 'https://github.com',
  user_name: null,
  item_id: 'item-uuid',
};

/** jsdom 的 document.hidden 是 getter，需要 defineProperty 覆盖 */
const setHidden = (hidden: boolean) => {
  Object.defineProperty(document, 'hidden', { value: hidden, configurable: true });
};

const toastError = toast.error as jest.Mock;

describe('hooks/usePasskeyApprovals', () => {
  beforeEach(() => {
    capturedHandler = null;
    setHidden(false);
    listenMock.mockReset().mockImplementation(async (_event, handler) => {
      capturedHandler = handler;
      return () => {};
    });
    (personaAPI.passkeyApprovalRespond as jest.Mock).mockReset().mockResolvedValue({
      success: true,
      data: true,
    });
    sendNotificationMock.mockReset();
    toastError.mockReset();
  });

  it('subscribes only when enabled', async () => {
    const { rerender } = renderHook(
      (enabled: boolean) => usePasskeyApprovals(enabled),
      { initialProps: false },
    );

    expect(listenMock).not.toHaveBeenCalled();

    rerender(true);
    await waitFor(() => expect(listenMock).toHaveBeenCalledWith(PASSKEY_APPROVAL_EVENT, expect.any(Function)));
  });

  it('queues incoming approval requests in arrival order', async () => {
    const { result } = renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
      handler({ payload: { ...sampleRequest, request_id: 'passkey-2', origin: 'https://gitlab.com' } });
    });

    expect(result.current.pending?.request_id).toBe('passkey-1');
    expect(result.current.pendingCount).toBe(2);
  });

  it('ignores duplicate request ids', async () => {
    const { result } = renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
      handler({ payload: sampleRequest });
    });

    expect(result.current.pendingCount).toBe(1);
  });

  it('respond removes the request from the queue and calls backend', async () => {
    const { result } = renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
    });

    await act(async () => {
      await result.current.respond('passkey-1', true);
    });

    expect(personaAPI.passkeyApprovalRespond).toHaveBeenCalledWith('passkey-1', true);
    expect(result.current.pending).toBeNull();
    expect(result.current.pendingCount).toBe(0);
  });

  it('keeps the request queued and toasts when the respond fails', async () => {
    const { result } = renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    act(() => {
      (capturedHandler as ListenHandler)({ payload: sampleRequest });
    });

    // 后端拒绝了应答：请求必须留在队列里（可重试）而不是静默消失，
    // 否则 Allow 丢失后浏览器请求会挂到 120s 超时
    (personaAPI.passkeyApprovalRespond as jest.Mock).mockResolvedValueOnce({
      success: false,
      data: undefined,
      error: 'expired',
    });
    await act(async () => {
      await result.current.respond('passkey-1', true);
    });
    expect(result.current.pendingCount).toBe(1);
    expect(result.current.pending?.request_id).toBe('passkey-1');
    expect(toastError).toHaveBeenCalledWith('expired');

    (personaAPI.passkeyApprovalRespond as jest.Mock).mockRejectedValueOnce(new Error('ipc gone'));
    await act(async () => {
      await result.current.respond('passkey-1', true);
    });
    expect(result.current.pendingCount).toBe(1);
    expect(toastError).toHaveBeenLastCalledWith('ipc gone');
  });

  it('clears queue when disabled', async () => {
    const { result, rerender } = renderHook(({ enabled }) => usePasskeyApprovals(enabled), {
      initialProps: { enabled: true },
    });

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;
    act(() => {
      handler({ payload: sampleRequest });
    });
    expect(result.current.pendingCount).toBe(1);

    rerender({ enabled: false });
    expect(result.current.pending).toBeNull();
    expect(result.current.pendingCount).toBe(0);
  });

  it('notifies with a creation-specific title while hidden', async () => {
    setHidden(true);
    renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: { ...sampleRequest, operation: 'passkey_create', rp_id: 'github.com', user_name: 'alice' } });
    });

    await waitFor(() => expect(sendNotificationMock).toHaveBeenCalled());
    expect(sendNotificationMock).toHaveBeenCalledWith({
      title: '通行密钥创建请求',
      body: 'https://github.com —— 打开 Persona 批准或拒绝',
    });
  });

  it('notifies with a sign-in title for assert requests while hidden', async () => {
    setHidden(true);
    renderHook(() => usePasskeyApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
    });

    await waitFor(() => expect(sendNotificationMock).toHaveBeenCalled());
    expect(sendNotificationMock).toHaveBeenCalledWith({
      title: '通行密钥登录请求',
      body: 'https://github.com —— 打开 Persona 批准或拒绝',
    });
  });
});
