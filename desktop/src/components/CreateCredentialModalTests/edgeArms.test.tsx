import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import CreateCredentialModal from '../CreateCredentialModal';
import {
  mockUsePersonaService,
  createCredential,
  generatePassword,
  updateCredential,
  updateCredentialData,
  walletValidateMnemonic,
  walletGenerateMnemonic,
  getCredentialCustomFields,
  setCredentialCustomFields,
  mockReauth,
  pinDefaultMocks,
  identity,
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

  // -------------------------------------------------------------------------
  // 覆盖边界分支：失败/异常/次要字段变更都要有可观察行为，不能只测主路径
  // -------------------------------------------------------------------------

  describe('coverage edge arms', () => {
    const editCred = {
      id: 'c-9',
      identity_id: 'id-1',
      name: 'Old Name',
      credential_type: 'Password',
      security_level: 'Medium',
      url: 'https://old.example.com',
      username: 'olduser',
      notes: 'old note',
      tags: ['work'],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
      is_favorite: false,
    } as any;

    const renderEdit = (credential: any = editCred, payload: any = { credential_type: 'Password', data: { password: 'old-pw' } }) => {
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
          editCredential={{ credential, data: payload }}
        />,
      );
    };

    it('keeps the phrase on mnemonic validation failure and reports generate failures', async () => {
      renderModal();
      selectType('CryptoWallet');

      // 生成失败响应（142）：短语不回填
      (walletGenerateMnemonic as jest.Mock).mockResolvedValueOnce({
        success: false,
        error: 'nope',
      });
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await act(async () => {});
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue('');

      // 生成 IPC 异常（145）
      (walletGenerateMnemonic as jest.Mock).mockRejectedValueOnce(new Error('gone'));
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await act(async () => {});
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue('');

      // 校验防抖 catch（130）：命令抛错静默清反馈，不崩不卡
      (walletValidateMnemonic as jest.Mock).mockRejectedValueOnce(new Error('gone'));
      fireEvent.change(screen.getByPlaceholderText('12-24 个词的恢复短语'), {
        target: { value: 'abandon abandon abandon abandon' },
      });
      await act(async () => {
        await new Promise((r) => setTimeout(r, 450));
      });
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue(
        'abandon abandon abandon abandon',
      );
    });

    it('edits every crypto wallet field and re-derives the mnemonic word count', async () => {
      renderModal();
      selectType('CryptoWallet');

      // 词数下拉（619）：改 12 → 生成用新词数
      fireEvent.change(screen.getByLabelText('词'), { target: { value: '12' } });
      (walletGenerateMnemonic as jest.Mock).mockResolvedValueOnce({
        success: true,
        data: 'abandon x',
      });
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await waitFor(() => {
        expect(walletGenerateMnemonic).toHaveBeenCalledWith(12);
      });

      // BIP39 附加口令显隐（670）
      const bip39 = screen.getByPlaceholderText('附加口令（可选）') as HTMLInputElement;
      expect(bip39.type).toBe('password');
      fireEvent.click(bip39.parentElement!.querySelector('button')!);
      expect((screen.getByPlaceholderText('附加口令（可选）') as HTMLInputElement).type).toBe('text');

      // 私钥显隐（695）
      const priv = screen.getByPlaceholderText('WIF / hex 私钥') as HTMLInputElement;
      expect(priv.type).toBe('password');
      fireEvent.click(priv.parentElement!.querySelector('button')!);
      expect((screen.getByPlaceholderText('WIF / hex 私钥') as HTMLInputElement).type).toBe('text');

      // 公钥（710）
      fireEvent.change(screen.getByPlaceholderText('hex / base58 公钥'), {
        target: { value: 'pubkey-hex' },
      });
      expect(screen.getByPlaceholderText('hex / base58 公钥')).toHaveValue('pubkey-hex');
    });

    it('captures api secret, identity and license fields into the payload', async () => {
      renderModal();

      selectType('ApiKey');
      fireEvent.change(screen.getByPlaceholderText('API 机密（如有）'), {
        target: { value: 'sec-1' },
      });
      expect(screen.getByPlaceholderText('API 机密（如有）')).toHaveValue('sec-1');

      selectType('Identity');
      fireEvent.change(screen.getByLabelText('电话'), { target: { value: '13800000000' } });
      fireEvent.change(screen.getByText('地址', { selector: 'label' }).parentElement!.querySelector('textarea')!, {
        target: { value: 'addr-1' },
      });
      fireEvent.change(screen.getByLabelText('护照号'), { target: { value: 'P123' } });
      expect(screen.getByLabelText('电话')).toHaveValue('13800000000');

      selectType('SoftwareLicense');
      fireEvent.change(screen.getByLabelText('发行方'), { target: { value: 'Acme' } });
      fireEvent.change(screen.getByLabelText('有效期至'), { target: { value: '2027-05-01' } });
      expect(screen.getByLabelText('发行方')).toHaveValue('Acme');
    });

    it('restores the GameToken form from a TwoFactor payload in edit mode', () => {
      const twoFactorCred = { ...editCred, credential_type: 'TwoFactor' };
      renderEdit(twoFactorCred, {
        credential_type: 'GameToken',
        type: 'GameToken',
        data: { provider: 'steam_guard' },
      });
      // 挂载后 setFormData 按 payload 变体把表单类型还原成 GameToken
      expect(
        screen.getByPlaceholderText('steam_guard, tencent_security, netease_dashen, mihoyo'),
      ).toBeInTheDocument();
    });

    it('adds, edits and removes custom field rows', async () => {
      renderModal();
      fireEvent.click(screen.getByTestId('custom-field-add'));

      // label 编辑（1313）
      fireEvent.change(screen.getByTestId('custom-field-label-tmp-1'), {
        target: { value: '备注1' },
      });
      expect(screen.getByTestId('custom-field-label-tmp-1')).toHaveValue('备注1');

      // remove（1327/281-282）
      fireEvent.click(screen.getByTestId('custom-field-remove-tmp-1'));
      expect(screen.queryByTestId('custom-field-label-tmp-1')).not.toBeInTheDocument();
    });

    it('keeps the edit modal open when custom fields persistence fails', async () => {
      // 编辑提交路径：字段落库失败 → return 保持弹窗可重试（310-311/478）
      // 创建路径不同：条目已建，字段失败只 toast 不回滚（531）
      setCredentialCustomFields.mockResolvedValueOnce({ success: false, error: 'locked' });
      renderEdit();
      fireEvent.click(screen.getByTestId('custom-field-add'));

      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(setCredentialCustomFields).toHaveBeenCalled());
      // 元数据与密文都已保存，仅字段失败：弹窗保持打开
      expect(updateCredential).toHaveBeenCalled();
      expect(updateCredentialData).toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });

    it('retries payload save once when reauth is granted, and reports lock/generic errors', async () => {
      // REAUTH 通过 → 自动重放一次并关窗（492-493）
      mockReauth.requestReauth.mockResolvedValue(true);
      updateCredentialData
        .mockResolvedValueOnce({ success: false, error_code: 'REAUTH_REQUIRED', error: 're-auth' })
        .mockResolvedValueOnce({ success: true, data: { id: 'c-9' } });
      renderEdit();
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(updateCredentialData).toHaveBeenCalledTimes(2);

      // SERVICE_LOCKED（497-498）
      cleanup();
      mockReauth.requestReauth.mockResolvedValue(false);
      updateCredentialData.mockReset().mockResolvedValueOnce({
        success: false,
        error_code: 'SERVICE_LOCKED',
        error: 'locked',
      });
      onClose.mockClear();
      renderEdit();
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(updateCredentialData).toHaveBeenCalled());
      expect(onClose).not.toHaveBeenCalled();

      // 通用失败（500-502）
      cleanup();
      updateCredentialData.mockReset().mockResolvedValueOnce({
        success: false,
        error: 'boom',
      });
      onClose.mockClear();
      renderEdit();
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(updateCredentialData).toHaveBeenCalled());
      expect(onClose).not.toHaveBeenCalled();
    });

    it('closes on backdrop click when no reauth is pending', () => {
      const { container } = render(<CreateCredentialModal isOpen onClose={onClose} />);
      fireEvent.mouseDown(container.firstChild as Element);
      expect(onClose).toHaveBeenCalled();
    });
  });
});
