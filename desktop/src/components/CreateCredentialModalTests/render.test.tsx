import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CreateCredentialModal from '../CreateCredentialModal';
import {
  mockUsePersonaService,
  createCredential,
  generatePassword,
  walletValidateMnemonic,
  walletGenerateMnemonic,
  getCredentialCustomFields,
  setCredentialCustomFields,
  mockReauth,
  pinDefaultMocks,
  identity,
  getSelect,
  selectType,
} from './shared';

// jsdom does not inject TextEncoder (native in a browser environment); the Raw branch submission needs it
if (typeof globalThis.TextEncoder === 'undefined') {
  (globalThis as any).TextEncoder = jest.requireActual('util').TextEncoder;
}

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: (...args: any[]) => mockUsePersonaService(...(args as [])),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    walletValidateMnemonic: (...args: any[]) => walletValidateMnemonic(...(args as [])),
    walletGenerateMnemonic: (...args: any[]) => walletGenerateMnemonic(...(args as [])),
    getCredentialCustomFields: (...args: any[]) => getCredentialCustomFields(...(args as [])),
    setCredentialCustomFields: (...args: any[]) => setCredentialCustomFields(...(args as [])),
  },
}));

jest.mock('@/hooks/useReauth', () => ({
  useReauth: () => mockReauth,
}));


describe('components/CreateCredentialModal', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    pinDefaultMocks();
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

    const input = screen.getByPlaceholderText('输入密码') as HTMLInputElement;
    expect(input.type).toBe('password');

    fireEvent.click(screen.getByRole('button', { name: '生成' }));
    await waitFor(() => {
      expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).value).toBe(
        's3cret-generated',
      );
    });

    // The eye button next to the password field toggles plaintext
    const eyeButton = input.parentElement!.querySelector('button')!;
    fireEvent.click(eyeButton);
    expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).type).toBe('text');
  });

  it('renders type-specific fields for every credential type', () => {
    renderModal();

    selectType('CryptoWallet');
    expect(screen.getByPlaceholderText('Bitcoin、Ethereum 等')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('钱包地址')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toBeInTheDocument();
    expect(getSelect('mainnet')).toBeDefined();

    selectType('SshKey');
    expect(getSelect('rsa')).toBeDefined();
    expect(screen.getByPlaceholderText(/ssh-rsa/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/BEGIN OPENSSH PRIVATE KEY/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/密钥口令/)).toBeInTheDocument();

    selectType('ApiKey');
    expect(screen.getByPlaceholderText('API 密钥或令牌')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('API 机密（如有）')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('read、write、admin（逗号分隔）')).toBeInTheDocument();

    selectType('TwoFactor');
    expect(screen.getByPlaceholderText(/otpauth:\/\//)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    // The remaining types (BankCard/ServerConfig/Certificate) take the Raw branch
    selectType('BankCard');
    expect(screen.getByPlaceholderText('输入凭据数据')).toBeInTheDocument();
  });

  it('switching type resets previously entered credential data', () => {
    renderModal();

    fireEvent.change(screen.getByPlaceholderText('输入密码'), {
      target: { value: 'stale' },
    });
    selectType('CryptoWallet');
    selectType('Password');
    expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).value).toBe('');
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
    expect(getSelect('8')).toBeDefined(); // digits switched from 6 to 8
    // the issuer query parameter takes precedence over the label prefix
    expect(
      (screen.getByPlaceholderText('GitHub') as HTMLInputElement).value,
    ).toBe('Ignored');
    expect(
      (screen.getByPlaceholderText('user@example.com') as HTMLInputElement).value,
    ).toBe('alice@example.com');
    expect(
      (screen.getByPlaceholderText(/otpauth:\/\//) as HTMLInputElement).value,
    ).toContain('digits=8');
    // the period input (number) picks up the parsed 60
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

  it('disables submit without a name and while loading', () => {
    renderModal();
    expect(screen.getByRole('button', { name: '创建凭据' })).toBeDisabled();

    mockUsePersonaService.mockReturnValue({
      currentIdentity: identity,
      createCredential,
      generatePassword,
      isLoading: true,
    });
    render(<CreateCredentialModal isOpen onClose={onClose} />);
    expect(screen.getByRole('button', { name: '创建中…' })).toBeDisabled();
  });

  it('generates a mnemonic into the textarea and shows validation feedback', async () => {
    renderModal();
    selectType('CryptoWallet');

    fireEvent.click(screen.getByRole('button', { name: '生成' }));

    await waitFor(() => {
      expect(walletGenerateMnemonic).toHaveBeenCalledWith(24);
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue(
        'abandon ability able about above absent absorb abstract absurd abuse access accident',
      );
    });

    // Filling in the generated value triggers the debounced live validation feedback
    await waitFor(
      () => {
        expect(screen.getByText(/BIP-39 校验通过/)).toBeInTheDocument();
      },
      { timeout: 1500 },
    );
    expect(walletValidateMnemonic).toHaveBeenCalledWith(
      'abandon ability able about above absent absorb abstract absurd abuse access accident',
    );
  });

  it('renders game token fields and hints at vendor-bound providers', () => {
    renderModal();
    selectType('GameToken');

    expect(screen.getByPlaceholderText(/tencent_security/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('steam_guard 必填；其他提供商可选')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Steam, Tencent, NetEase…')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('qq_123456')).toBeInTheDocument();
  });

  it('renders the secure note textarea with the encryption hint', () => {
    renderModal();
    selectType('SecureNote');

    expect(
      screen.getByPlaceholderText(/加密笔记内容/),
    ).toBeInTheDocument();
    // The difference from the notes field of the other types (a plaintext column) must be spelled out in the form
    expect(screen.getByText(/per-item key/)).toBeInTheDocument();
  });

  it('keeps raw text when the value is not even parseable as a URL', () => {
    renderModal();
    selectType('TwoFactor');

    fireEvent.change(screen.getByPlaceholderText(/otpauth:\/\//), {
      target: { value: 'definitely not a url' },
    });

    // new URL throwing falls into the catch: no field is filled at all
    expect((screen.getByPlaceholderText('JBSWY3DPEHPK3PXP') as HTMLInputElement).value).toBe('');
    expect(screen.getByPlaceholderText(/otpauth:\/\//)).toHaveValue('definitely not a url');
  });
});
