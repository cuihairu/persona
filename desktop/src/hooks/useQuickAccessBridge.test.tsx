import { render, waitFor } from '@testing-library/react';
import toast from 'react-hot-toast';
import { useQuickAccessBridge } from './useQuickAccessBridge';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type { Identity, QuickAccessOpenCredential } from '@/types';

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock('@tauri-apps/api/event', () => ({
  listen: jest.fn(),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: { setActiveIdentity: jest.fn() },
}));

const mockListen = jest.requireMock('@tauri-apps/api/event').listen as jest.Mock;
const mockSetActive = personaAPI.setActiveIdentity as jest.Mock;
const toastError = toast.error as jest.Mock;

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

/** Mounts the hook and returns the open-credential callback it received */
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
    // The jump target written by a previous case must be reset, otherwise "ignore an unknown identity" would read a leftover
    pendingCredentialSelection: null,
    error: null,
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

  it('does not block the jump when the active write fails, but makes the failure visible', async () => {
    mockSetActive.mockRejectedValueOnce(new Error('db busy'));
    const handler = await mount();
    await handler({ payload: { identity_id: 'i2', credential_id: 'c9' } });

    // A persistence failure does not block the jump (the main UI keeps switching on its in-memory state)
    await waitFor(() => {
      expect(useAppStore.getState().currentIdentity?.id).toBe('i2');
    });
    // But the failure must be visible: the workspace's active identity still points at the old one, so a silent success would mislead the caller
    expect(toastError).toHaveBeenCalledWith('db busy');
    expect(useAppStore.getState().error).toBe('db busy');
  });

  it('ignores an unknown identity instead of jumping into an empty state', async () => {
    const handler = await mount();
    await handler({ payload: { identity_id: 'missing', credential_id: 'c1' } });

    expect(useAppStore.getState().pendingCredentialSelection).toBeNull();
    expect(mockSetActive).not.toHaveBeenCalled();
  });
});
