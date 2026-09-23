import { personaAPI } from './api';

const mockInvoke = jest.fn();
jest.mock('@tauri-apps/api/core', () => ({
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

  it('workspace settings methods map flags to flat snake_case args', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: null });

    await personaAPI.getWorkspaceSettings();
    expect(mockInvoke).toHaveBeenCalledWith('get_workspace_settings');

    await personaAPI.setFeatureFlags({
      ssh_agent: true,
      wallet: false,
      passkeys: true,
      fetch_favicons: false,
    });
    expect(mockInvoke).toHaveBeenCalledWith('set_feature_flags', {
      ssh_agent: true,
      wallet: false,
      passkeys: true,
      fetch_favicons: false,
    });
  });

  it('walletImport forwards wif import payloads unchanged', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: { id: 'wallet-1' } });

    await personaAPI.walletImport('id-1', {
      name: 'BTC WIF',
      network: 'Bitcoin',
      import_type: 'wif',
      data: 'L4xVnV1x...',
      password: 'password123',
    });

    expect(mockInvoke).toHaveBeenCalledWith('wallet_import', {
      identity_id: 'id-1',
      request: {
        name: 'BTC WIF',
        network: 'Bitcoin',
        import_type: 'wif',
        data: 'L4xVnV1x...',
        password: 'password123',
      },
    });
  });

  it('walletExport forwards wif export payloads unchanged', async () => {
    mockInvoke.mockResolvedValue({ success: true, data: 'L4xVnV1x...' });

    await personaAPI.walletExport({
      wallet_id: 'wallet-1',
      format: 'wif',
      include_private: false,
      password: 'password123',
    });

    expect(mockInvoke).toHaveBeenCalledWith('wallet_export', {
      request: {
        wallet_id: 'wallet-1',
        format: 'wif',
        include_private: false,
        password: 'password123',
      },
    });
  });
});

// ---------------------------------------------------------------------------
// 剩余命令映射补全：每个 personaAPI 方法对应一个 tauri invoke 及参数命名
// （camelCase → snake_case 映射是这里唯一的逻辑）。
// ---------------------------------------------------------------------------

describe('utils/api command mapping coverage', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue({ success: true, data: null });
  });

  it('service lifecycle methods', async () => {
    await personaAPI.initService({ master_password: 'pw', db_path: '/tmp/x.db' });
    expect(mockInvoke).toHaveBeenCalledWith('init_service', {
      request: { master_password: 'pw', db_path: '/tmp/x.db' },
    });

    await personaAPI.lockService();
    expect(mockInvoke).toHaveBeenCalledWith('lock_service');

    await personaAPI.isServiceUnlocked();
    expect(mockInvoke).toHaveBeenCalledWith('is_service_unlocked');
  });

  it('identity CRUD methods', async () => {
    // 可选描述字段缺省即可（serde Option 缺键即 None）
    await personaAPI.createIdentity({
      name: 'n',
      identity_type: 'personal',
    });
    expect(mockInvoke).toHaveBeenCalledWith('create_identity', {
      request: { name: 'n', identity_type: 'personal' },
    });

    await personaAPI.updateIdentity({ id: 'i1', name: 'n2' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('update_identity', {
      request: { id: 'i1', name: 'n2' },
    });

    await personaAPI.getIdentities();
    expect(mockInvoke).toHaveBeenCalledWith('get_identities');

    await personaAPI.getIdentity('i1');
    expect(mockInvoke).toHaveBeenCalledWith('get_identity', { id: 'i1' });
  });

  it('credential methods', async () => {
    await personaAPI.createCredential({ identity_id: 'i1' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('create_credential', {
      request: { identity_id: 'i1' },
    });

    await personaAPI.getCredentialsForIdentity('i1');
    expect(mockInvoke).toHaveBeenCalledWith('get_credentials_for_identity', { identity_id: 'i1' });

    await personaAPI.getCredentialData('c1');
    expect(mockInvoke).toHaveBeenCalledWith('get_credential_data', { credential_id: 'c1' });

    await personaAPI.getTotpCode('c1');
    expect(mockInvoke).toHaveBeenCalledWith('get_totp_code', { credential_id: 'c1' });

    await personaAPI.searchCredentials('git');
    expect(mockInvoke).toHaveBeenCalledWith('search_credentials', { query: 'git' });

    await personaAPI.generatePassword(20, false);
    expect(mockInvoke).toHaveBeenCalledWith('generate_password', { length: 20, include_symbols: false });

    await personaAPI.getStatistics();
    expect(mockInvoke).toHaveBeenCalledWith('get_statistics');

    await personaAPI.toggleCredentialFavorite('c1');
    expect(mockInvoke).toHaveBeenCalledWith('toggle_credential_favorite', { credential_id: 'c1' });

    await personaAPI.fetchCredentialFavicon('c1');
    expect(mockInvoke).toHaveBeenCalledWith('fetch_credential_favicon', { credential_id: 'c1' });

    await personaAPI.getFavicons(['a.com', 'b.com']);
    expect(mockInvoke).toHaveBeenCalledWith('get_favicons', { hosts: ['a.com', 'b.com'] });

    await personaAPI.getCredentialHistory('c1');
    expect(mockInvoke).toHaveBeenCalledWith('get_credential_history', { credential_id: 'c1' });

    await personaAPI.restoreCredentialVersion('c1', 3);
    expect(mockInvoke).toHaveBeenCalledWith('restore_credential_version', {
      credential_id: 'c1',
      version: 3,
    });

    await personaAPI.listAttachments('c1');
    expect(mockInvoke).toHaveBeenCalledWith('list_attachments', { credential_id: 'c1' });

    await personaAPI.attachFileToCredential('c1', '/tmp/f.bin', true);
    expect(mockInvoke).toHaveBeenCalledWith('attach_file_to_credential', {
      credential_id: 'c1',
      file_path: '/tmp/f.bin',
      encrypt: true,
    });

    await personaAPI.saveAttachmentToFile('a1', '/tmp/out.bin');
    expect(mockInvoke).toHaveBeenCalledWith('save_attachment_to_file', {
      attachment_id: 'a1',
      output_path: '/tmp/out.bin',
    });

    await personaAPI.deleteAttachment('a1');
    expect(mockInvoke).toHaveBeenCalledWith('delete_attachment', { attachment_id: 'a1' });

    await personaAPI.deleteCredential('c1');
    expect(mockInvoke).toHaveBeenCalledWith('delete_credential', { credential_id: 'c1' });
  });

  it('ssh agent methods', async () => {
    await personaAPI.getSshAgentStatus();
    expect(mockInvoke).toHaveBeenCalledWith('get_ssh_agent_status');

    await personaAPI.stopSshAgent();
    expect(mockInvoke).toHaveBeenCalledWith('stop_ssh_agent');

    await personaAPI.getSshKeys();
    expect(mockInvoke).toHaveBeenCalledWith('get_ssh_keys');
  });

  it('wallet address and lifecycle methods', async () => {
    await personaAPI.walletListAddresses('w1');
    expect(mockInvoke).toHaveBeenCalledWith('wallet_list_addresses', { wallet_id: 'w1' });

    await personaAPI.walletGenerate('i1', { name: 'g', network: 'Ethereum', wallet_type: 'hd' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('wallet_generate', {
      identity_id: 'i1',
      request: { name: 'g', network: 'Ethereum', wallet_type: 'hd' },
    });

    await personaAPI.walletAddAddress('w1', 'wallet-pass');
    expect(mockInvoke).toHaveBeenCalledWith('wallet_add_address', { wallet_id: 'w1', password: 'wallet-pass' });

    await personaAPI.walletDelete('w1');
    expect(mockInvoke).toHaveBeenCalledWith('wallet_delete', { wallet_id: 'w1' });

    await personaAPI.walletExport({ wallet_id: 'w1', format: 'json', include_private: false } as any);
    expect(mockInvoke).toHaveBeenCalledWith('wallet_export', {
      request: { wallet_id: 'w1', format: 'json', include_private: false },
    });
  });

  it('auto-lock methods', async () => {
    await personaAPI.configureAutoLock({ inactivity_timeout_secs: 300 } as any);
    expect(mockInvoke).toHaveBeenCalledWith('configure_auto_lock', {
      request: { inactivity_timeout_secs: 300 },
    });

    await personaAPI.getAutoLockStatus();
    expect(mockInvoke).toHaveBeenCalledWith('get_auto_lock_status');

    await personaAPI.touchActivity();
    expect(mockInvoke).toHaveBeenCalledWith('touch_activity');

    await personaAPI.startAutoLockMonitoring();
    expect(mockInvoke).toHaveBeenCalledWith('start_auto_lock_monitoring');

    await personaAPI.stopAutoLockMonitoring();
    expect(mockInvoke).toHaveBeenCalledWith('stop_auto_lock_monitoring');
  });

  it('audit methods', async () => {
    await personaAPI.auditQuery({ limit: 10 } as any);
    expect(mockInvoke).toHaveBeenCalledWith('audit_query', { request: { limit: 10 } });

    await personaAPI.auditStatistics();
    expect(mockInvoke).toHaveBeenCalledWith('audit_statistics');

    await personaAPI.auditCleanup(30);
    expect(mockInvoke).toHaveBeenCalledWith('audit_cleanup', { retain_days: 30 });
  });

  it('health scan defaults empty request when omitted', async () => {
    await personaAPI.healthScan();
    expect(mockInvoke).toHaveBeenCalledWith('health_scan', { request: {} });

    await personaAPI.healthScan({ min_password_score: 2 });
    expect(mockInvoke).toHaveBeenCalledWith('health_scan', {
      request: { min_password_score: 2 },
    });
  });

  it('passkey methods', async () => {
    await personaAPI.passkeyList('i1');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_list', { identity_id: 'i1' });

    await personaAPI.passkeyListByRp('example.com');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_list_by_rp', { rp_id: 'example.com' });

    await personaAPI.passkeyGet('p1');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_get', { id: 'p1' });

    await personaAPI.passkeyDelete('p1');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_delete', { id: 'p1' });

    await personaAPI.passkeyCreate({ identity_id: 'i1' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('passkey_create', {
      request: { identity_id: 'i1' },
    });

    await personaAPI.passkeySelfTest('p1');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_self_test', { id: 'p1' });

    await personaAPI.passkeyExportPrivateKey('p1');
    expect(mockInvoke).toHaveBeenCalledWith('passkey_export_private_key', { id: 'p1' });
  });

  it('export / reveal / reauth methods', async () => {
    await personaAPI.exportIdentity('i1');
    expect(mockInvoke).toHaveBeenCalledWith('export_identity', { identity_id: 'i1' });

    await personaAPI.revealCredentialSecret('c1', 'password');
    expect(mockInvoke).toHaveBeenCalledWith('reveal_credential_secret', {
      request: { credential_id: 'c1', field: 'password' },
    });

    await personaAPI.reauthVerify('pw');
    expect(mockInvoke).toHaveBeenCalledWith('reauth_verify', {
      request: { master_password: 'pw' },
    });
  });

  it('biometric methods map with dbPath/null arg shapes', async () => {
    // status：顶层 dbPath 参数（命令签名单参，非 request 包装）
    await personaAPI.biometricStatus();
    expect(mockInvoke).toHaveBeenCalledWith('biometric_status', { dbPath: null });

    await personaAPI.biometricStatus('/tmp/x.db');
    expect(mockInvoke).toHaveBeenCalledWith('biometric_status', { dbPath: '/tmp/x.db' });

    // enable：密码只存在于 request 体内
    await personaAPI.biometricEnable('pw');
    expect(mockInvoke).toHaveBeenCalledWith('biometric_enable', {
      request: { master_password: 'pw' },
    });

    // disable：幂等删，无参数
    await personaAPI.biometricDisable();
    expect(mockInvoke).toHaveBeenCalledWith('biometric_disable');

    // unlock：db_path 走 request 体内（与 init_service 同形）
    await personaAPI.biometricUnlock();
    expect(mockInvoke).toHaveBeenCalledWith('biometric_unlock', {
      request: { db_path: null },
    });

    await personaAPI.biometricUnlock('/tmp/x.db');
    expect(mockInvoke).toHaveBeenCalledWith('biometric_unlock', {
      request: { db_path: '/tmp/x.db' },
    });
  });

  it('wallet transaction and approval methods', async () => {
    await personaAPI.walletCreateTransaction({ wallet_id: 'w1' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('wallet_create_transaction', {
      request: { wallet_id: 'w1' },
    });

    await personaAPI.walletPendingTransactions('w1');
    expect(mockInvoke).toHaveBeenCalledWith('wallet_pending_transactions', { wallet_id: 'w1' });

    await personaAPI.walletSignTransaction({ transaction_id: 't1' } as any);
    expect(mockInvoke).toHaveBeenCalledWith('wallet_sign_transaction', {
      request: { transaction_id: 't1' },
    });

    await personaAPI.sshApprovalRespond('r1', true);
    expect(mockInvoke).toHaveBeenCalledWith('ssh_approval_respond', {
      request: { request_id: 'r1', allow: true },
    });

    await personaAPI.passkeyApprovalRespond('r1', false);
    expect(mockInvoke).toHaveBeenCalledWith('passkey_approval_respond', {
      request: { request_id: 'r1', allow: false },
    });
  });

  it('propagates invoke rejections to callers', async () => {
    mockInvoke.mockReset();
    mockInvoke.mockRejectedValue(new Error('bridge down'));

    await expect(personaAPI.lockService()).rejects.toThrow('bridge down');
  });

  it('E2EE sync device and conflict methods map to tauri invokes', async () => {
    // 设备管理（3b）：status/join/leave/list 无参或单词参数
    await personaAPI.syncDeviceStatus();
    expect(mockInvoke).toHaveBeenCalledWith('sync_device_status');

    await personaAPI.syncJoin('laptop');
    expect(mockInvoke).toHaveBeenCalledWith('sync_join', { deviceName: 'laptop' });

    await personaAPI.syncLeave();
    expect(mockInvoke).toHaveBeenCalledWith('sync_leave');

    await personaAPI.syncListDevices();
    expect(mockInvoke).toHaveBeenCalledWith('sync_list_devices');

    await personaAPI.syncAuthorize('d-2');
    expect(mockInvoke).toHaveBeenCalledWith('sync_authorize', { targetDeviceId: 'd-2' });

    await personaAPI.syncRevoke('d-2');
    expect(mockInvoke).toHaveBeenCalledWith('sync_revoke', { targetDeviceId: 'd-2' });

    // 同步周期与冲突裁决（3c）：sync_now 无参，裁决带 itemId + adoptOpId
    await personaAPI.syncNow();
    expect(mockInvoke).toHaveBeenCalledWith('sync_now');

    // 组密钥轮换（3d）：无参
    await personaAPI.syncRotate();
    expect(mockInvoke).toHaveBeenCalledWith('sync_rotate');

    await personaAPI.syncConflictsList();
    expect(mockInvoke).toHaveBeenCalledWith('sync_conflicts_list');

    await personaAPI.syncConflictResolve('item-1', 'op-9');
    expect(mockInvoke).toHaveBeenCalledWith('sync_conflict_resolve', {
      itemId: 'item-1',
      adoptOpId: 'op-9',
    });
  });
});
