import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CreateCredentialModal from './CreateCredentialModal';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { Identity } from '@/types';

const mockUsePersonaService = jest.fn();
const createCredential = jest.fn();
const generatePassword = jest.fn();

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: (...args: any[]) => mockUsePersonaService(...(args as [])),
}));

const identity = {
  id: 'id-1',
  name: 'Personal',
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
} as unknown as Identity;

/** 组件 label 未绑定 htmlFor，select 一律按值定位（Type 恒为表单里第一个 combobox）。 */
const getSelect = (value: string): HTMLSelectElement =>
  screen
    .getAllByRole('combobox')
    .find((el) => (el as HTMLSelectElement).value === value) as HTMLSelectElement;

const selectType = (type: string) => {
  fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: type } });
};

describe('components/CreateCredentialModal', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    createCredential.mockResolvedValue({ id: 'c-1' });
    generatePassword.mockResolvedValue('');
    mockUsePersonaService.mockReturnValue({
      currentIdentity: identity,
      createCredential,
      generatePassword,
      isLoading: false,
    });
  });

  const renderModal = (isOpen = true) =>
    render(<CreateCredentialModal isOpen={isOpen} onClose={onClose} />);

  it('renders nothing when closed or when no identity is selected', () => {
    const { container } = renderModal(false);
    expect(container).toBeEmptyDOMElement();

    mockUsePersonaService.mockReturnValue({
      currentIdentity: null,
      createCredential,
      generatePassword,
      isLoading: false,
    });
    const { container: empty } = render(<CreateCredentialModal isOpen onClose={onClose} />);
    expect(empty).toBeEmptyDOMElement();
  });

  it('generates a password into the password field and toggles visibility', async () => {
    generatePassword.mockResolvedValue('s3cret-generated');
    renderModal();

    const input = screen.getByPlaceholderText('Enter password') as HTMLInputElement;
    expect(input.type).toBe('password');

    fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
    await waitFor(() => {
      expect((screen.getByPlaceholderText('Enter password') as HTMLInputElement).value).toBe(
        's3cret-generated',
      );
    });

    // 密码框旁的眼睛按钮切换明文
    const eyeButton = input.parentElement!.querySelector('button')!;
    fireEvent.click(eyeButton);
    expect((screen.getByPlaceholderText('Enter password') as HTMLInputElement).type).toBe('text');
  });

  it('renders type-specific fields for every credential type', () => {
    renderModal();

    selectType('CryptoWallet');
    expect(screen.getByPlaceholderText('Bitcoin, Ethereum, etc.')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Wallet address')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('12-24 word recovery phrase')).toBeInTheDocument();
    expect(getSelect('mainnet')).toBeDefined();

    selectType('SshKey');
    expect(getSelect('rsa')).toBeDefined();
    expect(screen.getByPlaceholderText(/ssh-rsa/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/BEGIN OPENSSH PRIVATE KEY/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Key passphrase/)).toBeInTheDocument();

    selectType('ApiKey');
    expect(screen.getByPlaceholderText('API key or token')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('API secret (if any)')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('read, write, admin (comma-separated)')).toBeInTheDocument();

    selectType('TwoFactor');
    expect(screen.getByPlaceholderText(/otpauth:\/\//)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    // 其余类型（BankCard/ServerConfig/Certificate）走 Raw 分支
    selectType('BankCard');
    expect(screen.getByPlaceholderText('Enter credential data')).toBeInTheDocument();
  });

  it('switching type resets previously entered credential data', () => {
    renderModal();

    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'stale' },
    });
    selectType('CryptoWallet');
    selectType('Password');
    expect((screen.getByPlaceholderText('Enter password') as HTMLInputElement).value).toBe('');
  });

  it('parses a valid otpauth URI into the TwoFactor fields', () => {
    renderModal();
    selectType('TwoFactor');

    fireEvent.change(screen.getByPlaceholderText(/otpauth:\/\//), {
      target: {
        value:
          'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DP&issuer=Ignored&digits=8&period=60',
      },
    });

    expect((screen.getByPlaceholderText('JBSWY3DPEHPK3PXP') as HTMLInputElement).value).toBe(
      'JBSWY3DP',
    );
    expect((getSelect('SHA1') as HTMLSelectElement).value).toBe('SHA1');
    expect(getSelect('8')).toBeDefined(); // digits 从 6 切到 8
    // query 参数 issuer 优先于 label 前缀
    expect(
      (screen.getByPlaceholderText('GitHub') as HTMLInputElement).value,
    ).toBe('Ignored');
    expect(
      (screen.getByPlaceholderText('user@example.com') as HTMLInputElement).value,
    ).toBe('alice@example.com');
    expect(
      (screen.getByPlaceholderText(/otpauth:\/\//) as HTMLInputElement).value,
    ).toContain('digits=8');
    // period input（number）取到解析出的 60
    const period = screen.getByDisplayValue(60) as HTMLInputElement;
    expect(period.type).toBe('number');
  });

  it('keeps raw text in the URI field when it is not a valid otpauth URI', () => {
    renderModal();
    selectType('TwoFactor');

    fireEvent.change(screen.getByPlaceholderText(/otpauth:\/\//), {
      target: { value: 'https://example.com/not-otp' },
    });

    expect((screen.getByPlaceholderText('JBSWY3DPEHPK3PXP') as HTMLInputElement).value).toBe('');
    expect(screen.getByPlaceholderText(/otpauth:\/\//)).toHaveValue(
      'https://example.com/not-otp',
    );
  });

  it('submits a Password credential with deduplicated tags and closes', async () => {
    renderModal();

    fireEvent.change(screen.getByPlaceholderText(/Gmail Account/), {
      target: { value: 'Gmail' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'pw-123' },
    });
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'me@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/e.g. work, github, prod/), {
      target: { value: 'work, personal , work, ' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create Credential' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledTimes(1);
    });
    expect(createCredential).toHaveBeenCalledWith(
      expect.objectContaining({
        identity_id: 'id-1',
        name: 'Gmail',
        credential_type: 'Password',
        security_level: 'High',
        tags: ['work', 'personal'],
        credential_data: expect.objectContaining({
          type: 'Password',
          password: 'pw-123',
          email: 'me@example.com',
        }),
      }),
    );
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('stays open when createCredential returns nothing', async () => {
    createCredential.mockResolvedValue(null);
    renderModal();

    fireEvent.change(screen.getByPlaceholderText(/Gmail Account/), {
      target: { value: 'Gmail' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Credential' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalled();
    });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('disables submit without a name and while loading', () => {
    renderModal();
    expect(screen.getByRole('button', { name: 'Create Credential' })).toBeDisabled();

    mockUsePersonaService.mockReturnValue({
      currentIdentity: identity,
      createCredential,
      generatePassword,
      isLoading: true,
    });
    render(<CreateCredentialModal isOpen onClose={onClose} />);
    expect(screen.getByRole('button', { name: 'Creating...' })).toBeDisabled();
  });

  it('submits an ApiKey credential with parsed permissions', async () => {
    renderModal();
    selectType('ApiKey');

    fireEvent.change(screen.getByPlaceholderText(/Gmail Account/), {
      target: { value: 'CI token' },
    });
    fireEvent.change(screen.getByPlaceholderText('API key or token'), {
      target: { value: 'key-xyz' },
    });
    fireEvent.change(screen.getByPlaceholderText('read, write, admin (comma-separated)'), {
      target: { value: 'read, write' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create Credential' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'ApiKey',
          credential_data: expect.objectContaining({
            type: 'ApiKey',
            api_key: 'key-xyz',
            permissions: ['read', 'write'],
          }),
        }),
      );
    });
  });
});
