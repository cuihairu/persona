import { personaAPI } from './api';

const mockInvoke = jest.fn();
jest.mock('@tauri-apps/api/tauri', () => ({
  invoke: (...args: any[]) => mockInvoke(...args),
}));

describe('utils/api PersonaAPI', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it('walletList calls wallet_list with and without identity_id', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: { wallets: [] } });

    await personaAPI.walletList();
    expect(mockInvoke).toHaveBeenCalledWith('wallet_list');

    await personaAPI.walletList('id-1');
    expect(mockInvoke).toHaveBeenCalledWith('wallet_list', { identity_id: 'id-1' });
  });

  it('startSshAgent passes optional master_password', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: { running: true } });

    await personaAPI.startSshAgent();
    expect(mockInvoke).toHaveBeenCalledWith('start_ssh_agent', { request: { master_password: undefined } });

    await personaAPI.startSshAgent('pw');
    expect(mockInvoke).toHaveBeenCalledWith('start_ssh_agent', { request: { master_password: 'pw' } });
  });

  it('deleteIdentity uses identity_id argument', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: true });

    await personaAPI.deleteIdentity('abc');
    expect(mockInvoke).toHaveBeenCalledWith('delete_identity', { identity_id: 'abc' });
  });

  it('active identity commands map to tauri invokes', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: null });

    await personaAPI.getActiveIdentity();
    expect(mockInvoke).toHaveBeenCalledWith('get_active_identity');

    await personaAPI.setActiveIdentity('id-1');
    expect(mockInvoke).toHaveBeenCalledWith('set_active_identity', { identity_id: 'id-1' });

    await personaAPI.clearActiveIdentity();
    expect(mockInvoke).toHaveBeenCalledWith('clear_active_identity');
  });
});
