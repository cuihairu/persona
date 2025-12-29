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
});
