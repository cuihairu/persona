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
});
