import { render, waitFor } from '@testing-library/react';
import { useQuickAccessBridge } from './useQuickAccessBridge';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type { Identity, QuickAccessOpenCredential } from '@/types';

jest.mock('@tauri-apps/api/event', () => ({
  listen: jest.fn(),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: { setActiveIdentity: jest.fn() },
}));

const mockListen = jest.requireMock('@tauri-apps/api/event').listen as jest.Mock;
const mockSetActive = personaAPI.setActiveIdentity as jest.Mock;

const identity = (id: string, name: string): Identity =>
  ({
    id,
    name,
    identity_type: 'Personal',
    tags: [],
    is_active: true,
    travel_marked: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }) as unknown as Identity;

/** 挂载 hook 并返回它收到的 open-credential 回调 */
const mount = async () => {
  const Probe = () => {
    useQuickAccessBridge();
    return null;
  };
  render(<Probe />);
  await waitFor(() => expect(mockListen).toHaveBeenCalled());
  const call = mockListen.mock.calls.find(([event]) => event === 'persona://quick-access-open-credential');
  return call?.[1] as (event: { payload: QuickAccessOpenCredential }) => void | Promise<void>;
};

beforeEach(() => {
  jest.clearAllMocks();
  mockListen.mockResolvedValue(() => {});
  (mockSetActive as jest.Mock).mockResolvedValue({ success: true, data: true });
  useAppStore.setState({
    identities: [identity('i1', 'Personal'), identity('i2', 'Work')],
    currentIdentity: identity('i1', 'Personal'),
    // 上一个用例写入的跳转目标必须复位，否则"忽略未知身份"会读到残留
    pendingCredentialSelection: null,
  });
});

describe('hooks/useQuickAccessBridge', () => {
  it('subscribes to the cross-window open event and unsubscribes on unmount', async () => {
    const unlisten = jest.fn();
    mockListen.mockResolvedValue(unlisten);
    const Probe = () => {
      useQuickAccessBridge();
      return null;
    };
    const view = render(<Probe />);
    await waitFor(() => expect(mockListen).toHaveBeenCalledWith(
      'persona://quick-access-open-credential',
      expect.any(Function),
    ));
    view.unmount();
    await waitFor(() => expect(unlisten).toHaveBeenCalled());
  });

  it('stays on the current identity and only injects the selection', async () => {
    const handler = await mount();
    await handler({ payload: { identity_id: 'i1', credential_id: 'c1' } });

    await waitFor(() => {
      expect(useAppStore.getState().pendingCredentialSelection).toEqual({
        identityId: 'i1',
        credentialId: 'c1',
      });
    });
    expect(mockSetActive).not.toHaveBeenCalled();
  });

  it('switches identity for a cross-identity jump and persists the active id', async () => {
    const handler = await mount();
    await handler({ payload: { identity_id: 'i2', credential_id: 'c9' } });

    await waitFor(() => {
      expect(useAppStore.getState().pendingCredentialSelection).toEqual({
        identityId: 'i2',
        credentialId: 'c9',
      });
    });
    expect(useAppStore.getState().currentIdentity?.id).toBe('i2');
    expect(mockSetActive).toHaveBeenCalledWith('i2');
  });

  it('ignores an unknown identity instead of jumping into an empty state', async () => {
    const handler = await mount();
    await handler({ payload: { identity_id: 'missing', credential_id: 'c1' } });

    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    expect(mockSetActive).not.toHaveBeenCalled();
  });
});
