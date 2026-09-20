import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CreateCredentialModal from './CreateCredentialModal';
import type { Identity } from '@/types';

// jsdom 未注入 TextEncoder（浏览器环境原生可用），Raw 分支提交需要
if (typeof globalThis.TextEncoder === 'undefined') {
  (globalThis as any).TextEncoder = jest.requireActual('util').TextEncoder;
}

const mockUsePersonaService = jest.fn();
const createCredential = jest.fn();
const generatePassword = jest.fn();
const updateCredential = jest.fn();
const updateCredentialData = jest.fn();

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: (...args: any[]) => mockUsePersonaService(...(args as [])),
}));

// modal 接 useReauth 处理 payload 保存的 REAUTH_REQUIRED；
// 默认"取消"语义（resolve false → 不自动重试），REAUTH 用例断言编排
const mockReauth = {
  isOpen: false,
  error: null as string | null,
  isVerifying: false,
  requestReauth: jest.fn().mockResolvedValue(false),
  submit: jest.fn(),
  cancel: jest.fn(),
};
jest.mock('@/hooks/useReauth', () => ({
  useReauth: () => mockReauth,
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
    updateCredential.mockResolvedValue({ id: 'c-9' });
    updateCredentialData.mockResolvedValue({ success: true, data: { id: 'c-9' } });
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

    const input = screen.getByPlaceholderText('输入密码') as HTMLInputElement;
    expect(input.type).toBe('password');

    fireEvent.click(screen.getByRole('button', { name: '生成' }));
    await waitFor(() => {
      expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).value).toBe(
        's3cret-generated',
      );
    });

    // 密码框旁的眼睛按钮切换明文
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

    // 其余类型（BankCard/ServerConfig/Certificate）走 Raw 分支
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

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Gmail' },
    });
    fireEvent.change(screen.getByPlaceholderText('输入密码'), {
      target: { value: 'pw-123' },
    });
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'me@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/work, github, prod/), {
      target: { value: 'work, personal , work, ' },
    });

    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

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

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Gmail' },
    });
    fireEvent.change(screen.getByPlaceholderText('输入密码'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalled();
    });
    expect(onClose).not.toHaveBeenCalled();
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

  it('submits an ApiKey credential with parsed permissions', async () => {
    renderModal();
    selectType('ApiKey');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'CI token' },
    });
    fireEvent.change(screen.getByPlaceholderText('API 密钥或令牌'), {
      target: { value: 'key-xyz' },
    });
    fireEvent.change(screen.getByPlaceholderText('read、write、admin（逗号分隔）'), {
      target: { value: 'read, write' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

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

  it('submits a CryptoWallet credential with network and optional seed material', async () => {
    renderModal();
    selectType('CryptoWallet');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Cold storage' },
    });
    fireEvent.change(screen.getByPlaceholderText('Bitcoin、Ethereum 等'), {
      target: { value: 'Ethereum' },
    });
    fireEvent.change(screen.getByPlaceholderText('钱包地址'), {
      target: { value: '0xabc' },
    });
    fireEvent.change(screen.getByPlaceholderText('12-24 个词的恢复短语'), {
      target: { value: 'word1 word2' },
    });
    fireEvent.change(getSelect('mainnet'), { target: { value: 'testnet' } });
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), {
      target: { value: 'https://eth.io' },
    });
    fireEvent.change(screen.getByPlaceholderText('用户名或账户标识'), {
      target: { value: 'vitalik' },
    });
    fireEvent.change(screen.getByPlaceholderText('补充备注或信息'), {
      target: { value: 'hardware backup' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Cold storage',
          credential_type: 'CryptoWallet',
          url: 'https://eth.io',
          username: 'vitalik',
          notes: 'hardware backup',
          credential_data: {
            type: 'CryptoWallet',
            wallet_type: 'Ethereum',
            mnemonic_phrase: 'word1 word2',
            private_key: undefined,
            public_key: '',
            address: '0xabc',
            network: 'testnet',
          },
        }),
      );
    });
  });

  it('submits an SshKey credential with key type and passphrase', async () => {
    renderModal();
    selectType('SshKey');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Build server' },
    });
    fireEvent.change(getSelect('rsa'), { target: { value: 'ed25519' } });
    fireEvent.change(screen.getByPlaceholderText(/ssh-rsa/), {
      target: { value: 'ssh-ed25519 AAA' },
    });
    fireEvent.change(screen.getByPlaceholderText(/BEGIN OPENSSH PRIVATE KEY/), {
      target: { value: '-----BEGIN-----' },
    });
    fireEvent.change(screen.getByPlaceholderText(/密钥口令/), {
      target: { value: 'phrase' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'SshKey',
          credential_data: {
            type: 'SshKey',
            private_key: '-----BEGIN-----',
            public_key: 'ssh-ed25519 AAA',
            key_type: 'ed25519',
            passphrase: 'phrase',
          },
        }),
      );
    });
  });

  it('renders game token fields and hints at vendor-bound providers', () => {
    renderModal();
    selectType('GameToken');

    expect(screen.getByPlaceholderText(/tencent_security/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('steam_guard 必填；其他提供商可选')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Steam, Tencent, NetEase…')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('qq_123456')).toBeInTheDocument();
  });

  it('submits a GameToken credential with normalized provider and url', async () => {
    renderModal();
    selectType('GameToken');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Steam' },
    });
    fireEvent.change(screen.getByPlaceholderText(/tencent_security/), {
      target: { value: 'STEAM_GUARD' },
    });
    fireEvent.change(screen.getByPlaceholderText('steam_guard 必填；其他提供商可选'), {
      target: { value: '  aGVsbG8=  ' },
    });
    fireEvent.change(screen.getByPlaceholderText('Steam, Tencent, NetEase…'), {
      target: { value: 'Steam' },
    });
    fireEvent.change(screen.getByPlaceholderText('qq_123456'), {
      target: { value: 'alice_steam' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), {
      target: { value: 'https://store.steampowered.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'TwoFactor',
          credential_data: {
            type: 'GameToken',
            provider: 'steam_guard',
            secret_key: 'aGVsbG8=',
            issuer: 'Steam',
            account_name: 'alice_steam',
            url: 'https://store.steampowered.com',
          },
        }),
      );
    });
  });

  it('renders the secure note textarea with the encryption hint', () => {
    renderModal();
    selectType('SecureNote');

    expect(
      screen.getByPlaceholderText(/加密笔记内容/),
    ).toBeInTheDocument();
    // 与其他类型 notes 字段（明文列）的差别必须在表单里说清楚
    expect(screen.getByText(/per-item key/)).toBeInTheDocument();
  });

  it('submits a SecureNote credential with the note passed through verbatim', async () => {
    renderModal();
    selectType('SecureNote');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Recovery codes' },
    });
    fireEvent.change(screen.getByPlaceholderText(/加密笔记内容/), {
      target: { value: '1111-2222\n3333-4444' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          // SecureNote 是真实 credential_type 变体，不走 GameToken 的 TwoFactor 映射
          credential_type: 'SecureNote',
          credential_data: {
            type: 'SecureNote',
            note: '1111-2222\n3333-4444',
          },
        }),
      );
    });
  });

  it('submits an Identity credential with names and document numbers', async () => {
    renderModal();
    selectType('Identity');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Passport (main)' },
    });
    fireEvent.change(screen.getByLabelText(/名 */), {
      target: { value: 'Alice' },
    });
    fireEvent.change(screen.getByLabelText(/姓 */), {
      target: { value: 'Zhang' },
    });
    fireEvent.change(screen.getByLabelText('邮箱'), {
      target: { value: 'alice@example.com' },
    });
    fireEvent.change(screen.getByLabelText(/证件号码/), {
      target: { value: '110101199001310011' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'Identity',
          credential_data: expect.objectContaining({
            type: 'Identity',
            first_name: 'Alice',
            last_name: 'Zhang',
            email: 'alice@example.com',
            id_number: '110101199001310011',
            // 未填的可选字段不进请求体
            passport_number: undefined,
          }),
        }),
      );
    });
  });

  it('submits a SoftwareLicense credential with the key and seat count', async () => {
    renderModal();
    selectType('SoftwareLicense');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'JetBrains All Products' },
    });
    fireEvent.change(screen.getByPlaceholderText('AAAA-BBBB-CCCC-DDDD'), {
      target: { value: 'AAAA-BBBB-CCCC-DDDD' },
    });
    fireEvent.change(screen.getByLabelText('版本'), {
      target: { value: '2024.2' },
    });
    fireEvent.change(screen.getByLabelText('席位'), {
      target: { value: '3' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'SoftwareLicense',
          credential_data: expect.objectContaining({
            type: 'SoftwareLicense',
            license_key: 'AAAA-BBBB-CCCC-DDDD',
            version: '2024.2',
            seats: 3,
          }),
        }),
      );
    });
  });

  it('submits a TwoFactor credential with manually adjusted TOTP parameters', async () => {
    renderModal();
    selectType('TwoFactor');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: '2FA' },
    });
    fireEvent.change(screen.getByPlaceholderText('JBSWY3DPEHPK3PXP'), {
      target: { value: 'SECRET' },
    });
    fireEvent.change(screen.getByPlaceholderText('GitHub'), {
      target: { value: 'GitLab' },
    });
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'acct' },
    });
    fireEvent.change(getSelect('SHA1'), { target: { value: 'SHA256' } });
    fireEvent.change(getSelect('6'), { target: { value: '8' } });
    fireEvent.change(screen.getByDisplayValue(30), { target: { value: '45' } });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'TwoFactor',
          credential_data: {
            type: 'TwoFactor',
            secret_key: 'SECRET',
            issuer: 'GitLab',
            account_name: 'acct',
            algorithm: 'SHA256',
            digits: 8,
            period: 45,
          },
        }),
      );
    });
  });

  it('submits raw bytes for uncategorized types', async () => {
    renderModal();
    selectType('BankCard');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Misc' },
    });
    fireEvent.change(screen.getByPlaceholderText('输入凭据数据'), {
      target: { value: 'héllo' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_type: 'BankCard',
          credential_data: {
            type: 'Raw',
            // TextEncoder 字节数组（'é' 为 UTF-8 双字节）
            data: Array.from(new TextEncoder().encode('héllo')),
          },
        }),
      );
    });
  });

  it('keeps raw text when the value is not even parseable as a URL', () => {
    renderModal();
    selectType('TwoFactor');

    fireEvent.change(screen.getByPlaceholderText(/otpauth:\/\//), {
      target: { value: 'definitely not a url' },
    });

    // new URL 抛错走 catch：任何字段都不填充
    expect((screen.getByPlaceholderText('JBSWY3DPEHPK3PXP') as HTMLInputElement).value).toBe('');
    expect(screen.getByPlaceholderText(/otpauth:\/\//)).toHaveValue('definitely not a url');
  });

  it('submits the selected security level', async () => {
    renderModal();

    fireEvent.change(getSelect('High'), { target: { value: 'Critical' } });
    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'Root CA' },
    });
    fireEvent.change(screen.getByPlaceholderText('输入密码'), {
      target: { value: 'pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({ security_level: 'Critical' }),
      );
    });
  });

  // ------------------------------------------------------------------
  // 编辑模式（editCredential prop）：预填 + 元数据/payload 双保存
  // ------------------------------------------------------------------
  describe('edit mode', () => {
    const editCred = {
      id: 'c-9',
      identity_id: 'id-1',
      name: 'Old Name',
      credential_type: 'Password',
      security_level: 'Medium',
      url: 'https://old.example.com',
      username: 'olduser',
      notes: 'old note',
      tags: ['work', 'prod'],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
      is_favorite: false,
    } as any;

    const renderEditModal = (payload: any = { credential_type: 'Password', data: { password: 'old-pw' } }) => {
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        isLoading: false,
      });
      return render(
        <CreateCredentialModal
          isOpen
          onClose={onClose}
          editCredential={{ credential: editCred, data: payload }}
        />,
      );
    };

    it('prefills metadata and payload, locks the type selector, titles as Edit', () => {
      renderEditModal();

      expect(screen.getByTestId('credential-modal-title')).toHaveTextContent('编辑条目');
      expect(screen.getByPlaceholderText(/Gmail 账户/)).toHaveValue('Old Name');
      expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).value).toBe('old-pw');
      expect(screen.getByDisplayValue('olduser')).toBeInTheDocument();
      // 类型不可变（1Password 语义）
      expect(screen.getByTestId('credential-type-select')).toBeDisabled();
      expect(screen.getByText("条目类型不可更改")).toBeInTheDocument();
    });

    it('saves metadata then payload and closes (create never invoked)', async () => {
      renderEditModal();

      fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
        target: { value: 'New Name' },
      });
      fireEvent.change(screen.getByPlaceholderText('输入密码'), {
        target: { value: 'new-pw' },
      });
      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      await waitFor(() => expect(onClose).toHaveBeenCalled());

      // 元数据：全字段提交（空串交给后端 trim 清空）
      expect(updateCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'c-9',
          name: 'New Name',
          security_level: 'Medium',
          url: 'https://old.example.com',
          username: 'olduser',
          notes: 'old note',
        }),
      );
      // payload：复用原 item key 重封（REAUTH 由后端门禁控制）
      expect(updateCredentialData).toHaveBeenCalledWith({
        credential_id: 'c-9',
        credential_data: expect.objectContaining({
          type: 'Password',
          password: 'new-pw',
        }),
      });
      expect(createCredential).not.toHaveBeenCalled();
    });

    it('edits metadata only for types without dedicated payload fields', async () => {
      const bankCard = { ...editCred, credential_type: 'BankCard' };
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        isLoading: false,
      });
      render(
        <CreateCredentialModal
          isOpen
          onClose={onClose}
          editCredential={{ credential: bankCard, data: null }}
        />,
      );

      fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
        target: { value: 'Renamed Card' },
      });
      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(updateCredential).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'c-9', name: 'Renamed Card' }),
      );
      // 无专属字段类型绝不提交空 payload（会盲目覆盖既有密文）
      expect(updateCredentialData).not.toHaveBeenCalled();
    });

    it('stays open when payload save hits REAUTH_REQUIRED and reauth is declined', async () => {
      updateCredentialData.mockResolvedValueOnce({
        success: false,
        error_code: 'REAUTH_REQUIRED',
        error: 're-auth required',
      });
      renderEditModal();

      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      await waitFor(() => expect(mockReauth.requestReauth).toHaveBeenCalled());
      // 拒绝重认证：不重试、不关弹窗（元数据已存，密文可重试）
      expect(updateCredentialData).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();
    });
  });
});
