import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CreateCredentialModal from '../CreateCredentialModal';
import {
  mockUsePersonaService,
  createCredential,
  walletValidateMnemonic,
  walletGenerateMnemonic,
  getCredentialCustomFields,
  setCredentialCustomFields,
  mockReauth,
  pinDefaultMocks,
  getSelect,
  selectType,
} from './shared';

// jsdom 未注入 TextEncoder（浏览器环境原生可用），Raw 分支提交需要
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
            bip39_passphrase: undefined,
          },
        }),
      );
    });
  });

  it('submits wallet passphrase and private key when filled', async () => {
    renderModal();
    selectType('CryptoWallet');

    fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
      target: { value: 'With 25th word' },
    });
    fireEvent.change(screen.getByPlaceholderText('Bitcoin、Ethereum 等'), {
      target: { value: 'Ethereum' },
    });
    fireEvent.change(screen.getByPlaceholderText('钱包地址'), {
      target: { value: '0xdef' },
    });
    fireEvent.change(screen.getByPlaceholderText('12-24 个词的恢复短语'), {
      target: { value: 'legal winner thank year wave sausage worth useful legal winner thank yellow' },
    });
    fireEvent.change(screen.getByPlaceholderText('附加口令（可选）'), {
      target: { value: 'tungsten' },
    });
    fireEvent.change(screen.getByPlaceholderText('WIF / hex 私钥'), {
      target: { value: '0xpriv' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

    await waitFor(() => {
      expect(createCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          credential_data: expect.objectContaining({
            type: 'CryptoWallet',
            bip39_passphrase: 'tungsten',
            private_key: '0xpriv',
          }),
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
});
