import { renderHook, act, waitFor } from '@testing-library/react';
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
      title: 'Passkey creation request',
      body: 'https://github.com — open Persona to approve or deny',
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
      title: 'Passkey sign-in request',
      body: 'https://github.com — open Persona to approve or deny',
    });
  });
});
