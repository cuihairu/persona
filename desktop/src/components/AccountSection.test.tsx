import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import AccountSection from './AccountSection';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    getWorkspaceSettings: jest.fn(),
    accountRegister: jest.fn(),
    accountSrpRegisterWithPassword: jest.fn(),
    accountSrpLogin: jest.fn(),
    accountExchangeSession: jest.fn(),
    accountSetBinding: jest.fn(),
    accountSignOut: jest.fn(),
    accountListDevices: jest.fn(),
    accountRevokeDevice: jest.fn(),
    accountGenerateRecoveryCodes: jest.fn(),
  },
}));

const mockGetSettings = personaAPI.getWorkspaceSettings as jest.Mock;
const mockRegister = personaAPI.accountRegister as jest.Mock;
const mockSrpRegister = personaAPI.accountSrpRegisterWithPassword as jest.Mock;
const mockSrpLogin = personaAPI.accountSrpLogin as jest.Mock;
const mockExchange = personaAPI.accountExchangeSession as jest.Mock;
const mockSetBinding = personaAPI.accountSetBinding as jest.Mock;
const mockSignOut = personaAPI.accountSignOut as jest.Mock;
const mockListDevices = personaAPI.accountListDevices as jest.Mock;
const mockRevokeDevice = personaAPI.accountRevokeDevice as jest.Mock;
const mockGenerateRecovery = personaAPI.accountGenerateRecoveryCodes as jest.Mock;

const unbound = { success: true, data: { account: null } };
const boundSettings = {
  success: true,
  data: {
    account: {
      account_id: 'acct-1',
      username: 'alice@example.com',
      device_name: 'laptop',
    },
  },
};

const ok = <T,>(data: T) => ({ success: true, data });

/** Full-green register wizard: the four-step orchestration and the binding write all succeed */
const seedRegisterFlow = () => {
  mockRegister.mockResolvedValue(
    ok({ account_id: 'acct-1', username: 'alice@example.com' })
  );
  mockSrpRegister.mockResolvedValue(ok({ device_name: 'laptop' }));
  mockSrpLogin.mockResolvedValue(
    ok({ expires_in_secs: 900, session_key_fingerprint: 'ab12' })
  );
  mockExchange.mockResolvedValue(ok({ expires_in_secs: 86400 }));
  mockSetBinding.mockResolvedValue(boundSettings);
};

describe('components/AccountSection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('取消披露面不放行：不注册、不登录、无任何账号网络调用', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    seedRegisterFlow();

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    fireEvent.change(screen.getByTestId('account-username-input'), {
      target: { value: 'alice@example.com' },
    });
    fireEvent.change(screen.getByTestId('account-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-device-name-input'), {
      target: { value: 'laptop' },
    });
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );

    // Cancel = no pass-through
    fireEvent.click(screen.getByTestId('data-scope-cancel'));
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();
    expect(mockRegister).not.toHaveBeenCalled();
    expect(mockSrpRegister).not.toHaveBeenCalled();
    expect(mockSrpLogin).not.toHaveBeenCalled();
    expect(mockExchange).not.toHaveBeenCalled();
    expect(mockSetBinding).not.toHaveBeenCalled();

    // Re-submit and the Esc semantics (paths other than clicking confirm) are handled
    // inside the modal too; here we verify that confirming passes through
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );
  });

  it('组件加载零网络请求（红线：未开启前不会有任何网络调用）', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    expect(mockRegister).not.toHaveBeenCalled();
    expect(mockSrpRegister).not.toHaveBeenCalled();
    expect(mockSrpLogin).not.toHaveBeenCalled();
    expect(mockExchange).not.toHaveBeenCalled();
    expect(mockSetBinding).not.toHaveBeenCalled();
    expect(mockListDevices).not.toHaveBeenCalled();
    expect(mockSignOut).not.toHaveBeenCalled();
  });

  it('未绑定时显示向导，注册流按序编排四步并写入绑定', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    seedRegisterFlow();

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );

    fireEvent.change(screen.getByTestId('account-username-input'), {
      target: { value: 'alice@example.com' },
    });
    fireEvent.change(screen.getByTestId('account-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-device-name-input'), {
      target: { value: 'laptop' },
    });
    fireEvent.click(screen.getByTestId('account-register-submit'));

    // Privacy red line: submit goes to the disclosure surface first; zero orchestration calls before confirmation
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toHaveAttribute(
        'data-scope',
        'account'
      )
    );
    expect(mockRegister).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('data-scope-confirm'));

    await waitFor(() =>
      expect(mockSetBinding).toHaveBeenCalledWith({
        account_id: 'acct-1',
        username: 'alice@example.com',
        device_name: 'laptop',
      })
    );
    // Orchestration order: register → credentials → login → exchange
    expect(mockRegister).toHaveBeenCalledWith({ username: 'alice@example.com' });
    expect(mockSrpRegister).toHaveBeenCalledWith('acct-1', {
      device_name: 'laptop',
      password: 'pw',
    });
    expect(mockSrpLogin).toHaveBeenCalledWith('acct-1', {
      device_name: 'laptop',
      password: 'pw',
    });
    expect(mockExchange).toHaveBeenCalledWith('acct-1');
    // Switch to the bound view once the binding lands
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );
  });

  it('注册流中途失败（SRP 凭证被拒）时显示错误且不写绑定', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    mockRegister.mockResolvedValue(
      ok({ account_id: 'acct-1', username: 'alice@example.com' })
    );
    mockSrpRegister.mockResolvedValue({ success: false, error: 'HTTP 409' });

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    fireEvent.change(screen.getByTestId('account-username-input'), {
      target: { value: 'alice@example.com' },
    });
    fireEvent.change(screen.getByTestId('account-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-device-name-input'), {
      target: { value: 'laptop' },
    });
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));

    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 409')
    );
    expect(mockSrpLogin).not.toHaveBeenCalled();
    expect(mockExchange).not.toHaveBeenCalled();
    expect(mockSetBinding).not.toHaveBeenCalled();
  });

  it('登录向导：切到登录 tab、字段不全校验、确认披露后按 account_id 绑定', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    mockSrpLogin.mockResolvedValue(
      ok({ expires_in_secs: 900, session_key_fingerprint: 'ab12' })
    );
    mockExchange.mockResolvedValue(ok({ expires_in_secs: 86400 }));
    mockSetBinding.mockResolvedValue(boundSettings);

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );

    // Switch to login mode
    fireEvent.click(screen.getAllByRole('tab')[1]);
    await waitFor(() =>
      expect(screen.getByTestId('account-login-form')).toBeInTheDocument()
    );

    // Any of the three fields empty → submit reports incomplete directly, no disclosure modal
    fireEvent.click(screen.getByTestId('account-login-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('请填写完整表单')
    );
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();

    // Fill in the fields → disclosure → confirm → login + exchange + binding (username slot uses account_id)
    fireEvent.change(screen.getByTestId('account-id-input'), {
      target: { value: 'acct-9' },
    });
    fireEvent.change(screen.getByTestId('account-login-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-login-device-name-input'), {
      target: { value: 'tablet' },
    });
    fireEvent.click(screen.getByTestId('account-login-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() =>
      expect(mockSetBinding).toHaveBeenCalledWith({
        account_id: 'acct-9',
        username: 'acct-9',
        device_name: 'tablet',
      })
    );
    expect(mockSrpLogin).toHaveBeenCalledWith('acct-9', {
      device_name: 'tablet',
      password: 'pw',
    });
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );
  });

  it('登录路径失败面：SRP 拒绝与会话兑换失败都显示错误且不写绑定', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    mockSrpLogin.mockResolvedValue({ success: false, error: 'bad credentials' });
    mockExchange.mockResolvedValue({ success: false, error: 'HTTP 503' });
    mockSetBinding.mockResolvedValue(boundSettings);

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    fireEvent.click(screen.getAllByRole('tab')[1]);
    await waitFor(() =>
      expect(screen.getByTestId('account-login-form')).toBeInTheDocument()
    );
    fireEvent.change(screen.getByTestId('account-id-input'), {
      target: { value: 'acct-9' },
    });
    fireEvent.change(screen.getByTestId('account-login-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-login-device-name-input'), {
      target: { value: 'tablet' },
    });
    fireEvent.click(screen.getByTestId('account-login-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));

    // SRP login rejected → error shown, neither exchange nor binding happens
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('bad credentials')
    );
    expect(mockExchange).not.toHaveBeenCalled();
    expect(mockSetBinding).not.toHaveBeenCalled();

    // SRP passes but the exchange fails → abort the same way, no binding write
    mockSrpLogin.mockResolvedValue(
      ok({ expires_in_secs: 900, session_key_fingerprint: 'ab12' })
    );
    fireEvent.click(screen.getByTestId('account-login-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 503')
    );
    expect(mockSetBinding).not.toHaveBeenCalled();
    expect(screen.getByTestId('account-wizard')).toBeInTheDocument();
  });

  it('注册编排失败面：注册接口拒绝与绑定写入失败都中止', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    mockRegister.mockResolvedValue({ success: false, error: 'username taken' });
    mockSrpLogin.mockResolvedValue(
      ok({ expires_in_secs: 900, session_key_fingerprint: 'ab12' })
    );
    mockExchange.mockResolvedValue(ok({ expires_in_secs: 86400 }));

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    fireEvent.change(screen.getByTestId('account-username-input'), {
      target: { value: 'alice' },
    });
    fireEvent.change(screen.getByTestId('account-password-input'), {
      target: { value: 'pw' },
    });
    fireEvent.change(screen.getByTestId('account-device-name-input'), {
      target: { value: 'laptop' },
    });

    // Register endpoint rejects → error on the first step, the rest of the orchestration never runs
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('username taken')
    );
    expect(mockSrpRegister).not.toHaveBeenCalled();
    expect(mockSetBinding).not.toHaveBeenCalled();

    // Orchestration passes but the binding write fails → error and no switch to the bound view
    mockRegister.mockResolvedValue(
      ok({ account_id: 'acct-1', username: 'alice' })
    );
    mockSrpRegister.mockResolvedValue(ok({ device_name: 'laptop' }));
    mockSetBinding.mockResolvedValue({ success: false, error: 'HTTP 500' });
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('data-scope-modal')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('data-scope-confirm'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 500')
    );
    expect(screen.getByTestId('account-wizard')).toBeInTheDocument();
  });

  it('注册表单不完整提交直接报错，不弹披露面', async () => {
    mockGetSettings.mockResolvedValue(unbound);
    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('account-register-submit'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('请填写完整表单')
    );
    expect(screen.queryByTestId('data-scope-modal')).not.toBeInTheDocument();
    expect(mockRegister).not.toHaveBeenCalled();
  });

  it('恢复码：生成成功展示列表，接口失败显示错误', async () => {
    mockGetSettings.mockResolvedValue(boundSettings);
    mockGenerateRecovery.mockResolvedValue(
      ok({ codes: ['AAAA-BBBB', 'CCCC-DDDD'] })
    );

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );

    fireEvent.click(screen.getByTestId('account-recovery-button'));
    await waitFor(() =>
      expect(screen.getByTestId('account-recovery-codes')).toBeInTheDocument()
    );
    expect(screen.getByText('AAAA-BBBB')).toBeInTheDocument();
    expect(screen.getByText('CCCC-DDDD')).toBeInTheDocument();

    // Endpoint failure → error shown, the list keeps the last successful result
    mockGenerateRecovery.mockResolvedValue({ success: false, error: 'HTTP 429' });
    fireEvent.click(screen.getByTestId('account-recovery-button'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 429')
    );
    expect(screen.getByTestId('account-recovery-codes')).toBeInTheDocument();
  });

  it('设备管理失败面：拉取失败与吊销失败都显示错误', async () => {
    mockGetSettings.mockResolvedValue(boundSettings);
    mockListDevices.mockResolvedValue({ success: false, error: 'HTTP 502' });
    mockRevokeDevice.mockResolvedValue({ success: false, error: 'HTTP 403' });

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );

    fireEvent.click(screen.getByTestId('account-devices-button'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 502')
    );
    expect(screen.queryByTestId('account-devices-list')).not.toBeInTheDocument();

    // Fetch succeeds then revoke fails → error shown, list kept
    mockListDevices.mockResolvedValue(
      ok({
        devices: [
          {
            id: 'row-1',
            device_id: 'dev-1',
            device_name: 'phone',
            public_key: 'pk',
            status: 'authorized',
          },
        ],
      })
    );
    fireEvent.click(screen.getByTestId('account-devices-button'));
    await waitFor(() =>
      expect(screen.getByTestId('account-devices-list')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('account-revoke-device-dev-1'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 403')
    );
    expect(
      screen.getByTestId('account-revoke-device-dev-1')
    ).toBeInTheDocument();
  });

  it('退出失败面：吊销失败与解绑失败都停留在已绑定视图', async () => {
    mockGetSettings.mockResolvedValue(boundSettings);
    mockSignOut.mockResolvedValue({ success: false, error: 'HTTP 500' });
    mockSetBinding.mockResolvedValue(unbound);

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );

    // Token revocation fails → error, no unbinding
    fireEvent.click(screen.getByTestId('account-sign-out'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 500')
    );
    expect(mockSetBinding).not.toHaveBeenCalled();
    expect(screen.getByTestId('account-bound')).toBeInTheDocument();

    // Revocation succeeds but the unbinding write fails → error, still on the bound view
    mockSignOut.mockResolvedValue(ok({ revoked_on_server: true }));
    mockSetBinding.mockResolvedValue({ success: false, error: 'HTTP 409' });
    fireEvent.click(screen.getByTestId('account-sign-out'));
    await waitFor(() =>
      expect(screen.getByTestId('account-error')).toHaveTextContent('HTTP 409')
    );
    expect(screen.getByTestId('account-bound')).toBeInTheDocument();
  });

  it('已绑定视图展示账号卡：重新登录、设备管理与退出解绑', async () => {
    mockGetSettings.mockResolvedValue(boundSettings);
    mockSrpLogin.mockResolvedValue(
      ok({ expires_in_secs: 900, session_key_fingerprint: 'ab12' })
    );
    mockExchange.mockResolvedValue(ok({ expires_in_secs: 86400 }));
    mockListDevices.mockResolvedValue(
      ok({
        devices: [
          {
            id: 'row-1',
            device_id: 'dev-1',
            device_name: 'phone',
            public_key: 'pk',
            status: 'authorized',
          },
        ],
      })
    );
    mockRevokeDevice.mockResolvedValue(ok(true));
    mockSignOut.mockResolvedValue(ok({ revoked_on_server: true }));
    mockSetBinding.mockResolvedValue(unbound);

    render(<AccountSection />);
    await waitFor(() =>
      expect(screen.getByTestId('account-bound')).toBeInTheDocument()
    );
    expect(screen.getByTestId('account-bound')).toHaveTextContent(
      'alice@example.com'
    );

    // Re-login: SRP + exchange only, binding untouched
    fireEvent.change(screen.getByTestId('account-relogin-password'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByTestId('account-relogin-submit'));
    await waitFor(() => expect(mockExchange).toHaveBeenCalledWith('acct-1'));
    expect(mockSetBinding).not.toHaveBeenCalled();

    // Device management: fetch the list + revoke
    fireEvent.click(screen.getByTestId('account-devices-button'));
    await waitFor(() =>
      expect(screen.getByTestId('account-devices-list')).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId('account-revoke-device-dev-1'));
    await waitFor(() =>
      expect(mockRevokeDevice).toHaveBeenCalledWith('acct-1', 'dev-1')
    );

    // Sign-out: revoke the token + unbind
    fireEvent.click(screen.getByTestId('account-sign-out'));
    await waitFor(() =>
      expect(mockSignOut).toHaveBeenCalledWith('acct-1')
    );
    await waitFor(() =>
      expect(mockSetBinding).toHaveBeenCalledWith(null)
    );
    await waitFor(() =>
      expect(screen.getByTestId('account-wizard')).toBeInTheDocument()
    );
  });
});
