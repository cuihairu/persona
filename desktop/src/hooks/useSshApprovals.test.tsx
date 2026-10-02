import { renderHook, act, waitFor } from '@testing-library/react';
import { useSshApprovals, SSH_APPROVAL_EVENT } from './useSshApprovals';
import { personaAPI } from '@/utils/api';
import type { SshApprovalRequest } from '@/types';

type ListenHandler = (event: { payload: SshApprovalRequest }) => void;

const listenMock = jest.fn<
  Promise<(cb: ListenHandler) => void>,
  [string, ListenHandler]
>();
let capturedHandler: ListenHandler | null = null;

jest.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: ListenHandler) => listenMock(event, handler),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    sshApprovalRespond: jest.fn(),
  },
}));

jest.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: jest.fn().mockResolvedValue(true),
  requestPermission: jest.fn().mockResolvedValue(true),
  sendNotification: jest.fn(),
}));

const sampleRequest: SshApprovalRequest = {
  request_id: 'ssh-1',
  key_id: 'key-uuid',
  fingerprint: 'SHA256:abcd1234',
  operation: 'sign',
  peer: 'github.com',
  reason: 'policy',
};

describe('hooks/useSshApprovals', () => {
  beforeEach(() => {
    capturedHandler = null;
    listenMock.mockReset().mockImplementation(async (_event, handler) => {
      capturedHandler = handler;
      return () => {};
    });
    (personaAPI.sshApprovalRespond as jest.Mock).mockReset().mockResolvedValue({
      success: true,
      data: true,
    });
  });

  it('subscribes only when enabled', async () => {
    const { rerender } = renderHook(
      (enabled: boolean) => useSshApprovals(enabled),
      { initialProps: false },
    );

    expect(listenMock).not.toHaveBeenCalled();

    rerender(true);
    await waitFor(() => expect(listenMock).toHaveBeenCalledWith(SSH_APPROVAL_EVENT, expect.any(Function)));
  });

  it('queues incoming approval requests in arrival order', async () => {
    const { result } = renderHook(() => useSshApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
      handler({ payload: { ...sampleRequest, request_id: 'ssh-2', peer: 'gitlab.com' } });
    });

    expect(result.current.pending?.request_id).toBe('ssh-1');
    expect(result.current.pendingCount).toBe(2);
  });

  it('ignores duplicate request ids', async () => {
    const { result } = renderHook(() => useSshApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
      handler({ payload: sampleRequest });
    });

    expect(result.current.pendingCount).toBe(1);
  });

  it('respond removes the request from the queue and calls backend', async () => {
    const { result } = renderHook(() => useSshApprovals(true));

    await waitFor(() => expect(capturedHandler).not.toBeNull());
    const handler = capturedHandler as ListenHandler;

    act(() => {
      handler({ payload: sampleRequest });
    });

    await act(async () => {
      await result.current.respond('ssh-1', true);
    });

    expect(personaAPI.sshApprovalRespond).toHaveBeenCalledWith('ssh-1', true);
    expect(result.current.pending).toBeNull();
    expect(result.current.pendingCount).toBe(0);
  });

  it('clears queue when disabled', async () => {
    const { result, rerender } = renderHook(({ enabled }) => useSshApprovals(enabled), {
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
});
