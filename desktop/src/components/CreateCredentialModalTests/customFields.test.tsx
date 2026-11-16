import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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

  describe('custom fields editor', () => {
    const baseCred = {
      id: 'c-9',
      identity_id: 'id-1',
      name: 'Old Name',
      credential_type: 'Password',
      security_level: 'Medium',
      url: '',
      username: '',
      notes: '',
      tags: [],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
      is_favorite: false,
    } as any;

    const renderWithCredential = (credential: any, data: any) =>
      render(
        <CreateCredentialModal
          isOpen
          onClose={onClose}
          editCredential={{ credential, data }}
        />,
      );

    it('loads existing fields in edit mode, masks concealed values, skips save when untouched', async () => {
      getCredentialCustomFields.mockResolvedValue({
        success: true,
        data: [
          { id: 'f-1', label: 'Recovery Code', value: '1234-5678', type: 'text', section: null },
          { id: 'f-2', label: 'PIN', value: '999999', type: 'concealed', section: 'Bank' },
        ],
      });
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        isLoading: false,
      });
      renderWithCredential(baseCred, {
        credential_type: 'Password',
        data: { password: 'old-pw' },
      });

      await waitFor(() =>
        expect(screen.getByTestId('custom-field-value-f-1')).toHaveValue('1234-5678'),
      );
      // concealed 打码（password 输入框），揭示按钮切回明文
      expect(screen.getByTestId('custom-field-value-f-2')).toHaveAttribute('type', 'password');
      fireEvent.click(screen.getByTestId('custom-field-reveal-f-2'));
      expect(screen.getByTestId('custom-field-value-f-2')).toHaveAttribute('type', 'text');

      // 未动过的表不白写：保存只走元数据+payload 两步
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(setCredentialCustomFields).not.toHaveBeenCalled();
    });

    it('persists an added field after payload save with server-generated id', async () => {
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        isLoading: false,
      });
      renderWithCredential(baseCred, {
        credential_type: 'Password',
        data: { password: 'old-pw' },
      });

      await waitFor(() => expect(screen.getByTestId('custom-field-add')).toBeEnabled());
      fireEvent.click(screen.getByTestId('custom-field-add'));
      fireEvent.change(screen.getByTestId('custom-field-label-tmp-1'), {
        target: { value: 'OTP 备用码' },
      });
      fireEvent.change(screen.getByTestId('custom-field-value-tmp-1'), {
        target: { value: 'abc123' },
      });
      fireEvent.change(screen.getByTestId('custom-field-section-tmp-1'), {
        target: { value: ' 分组 ' },
      });
      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      // 新行 id 空串由后端生成；label/section trim
      await waitFor(() => expect(setCredentialCustomFields).toHaveBeenCalledTimes(1));
      expect(setCredentialCustomFields).toHaveBeenCalledWith('c-9', [
        { id: '', label: 'OTP 备用码', value: 'abc123', type: 'text', section: '分组' },
      ]);
      expect(onClose).toHaveBeenCalled();
    });

    it('persists fields for metadata-only types without touching payload', async () => {
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        getCredentialData: jest.fn().mockResolvedValue(null),
        isLoading: false,
      });
      renderWithCredential(
        { ...baseCred, credential_type: 'BankCard' },
        null,
      );

      // data:null 触发按 id 兜底补载（补不到也只存元数据）
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '保存' })).toBeEnabled(),
      );
      fireEvent.click(screen.getByTestId('custom-field-add'));
      fireEvent.change(screen.getByTestId('custom-field-label-tmp-1'), {
        target: { value: '卡片备注' },
      });
      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      await waitFor(() => expect(setCredentialCustomFields).toHaveBeenCalledTimes(1));
      // 无专属字段类型绝不提交空 payload（会盲目覆盖既有密文）
      expect(updateCredentialData).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalled();
    });

    it('shows load failure, hides editor, and never wipes unreadable fields', async () => {
      getCredentialCustomFields.mockResolvedValue({
        success: false,
        error: 'vault locked',
      });
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        isLoading: false,
      });
      renderWithCredential(baseCred, {
        credential_type: 'Password',
        data: { password: 'old-pw' },
      });

      await waitFor(() =>
        expect(screen.getByTestId('custom-fields-editor-error')).toHaveTextContent(
          'vault locked',
        ),
      );
      // 整表替换语义下读不到旧表就不能提供编辑
      expect(screen.queryByTestId('custom-field-add')).not.toBeInTheDocument();

      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(setCredentialCustomFields).not.toHaveBeenCalled();
    });

    it('persists added fields after creating the credential', async () => {
      renderModal();

      fireEvent.change(screen.getByPlaceholderText(/Gmail 账户/), {
        target: { value: 'New Item' },
      });
      // Password 类型的 required 密码不填，jsdom 约束校验会拦下 submit
      fireEvent.change(screen.getByPlaceholderText('输入密码'), {
        target: { value: 'pw-123' },
      });
      fireEvent.click(screen.getByTestId('custom-field-add'));
      fireEvent.change(screen.getByTestId('custom-field-label-tmp-1'), {
        target: { value: '备注2' },
      });
      fireEvent.change(screen.getByTestId('custom-field-value-tmp-1'), {
        target: { value: 'v2' },
      });
      fireEvent.click(screen.getByRole('button', { name: '创建凭据' }));

      await waitFor(() => expect(setCredentialCustomFields).toHaveBeenCalledTimes(1));
      expect(setCredentialCustomFields).toHaveBeenCalledWith('c-1', [
        { id: '', label: '备注2', value: 'v2', type: 'text', section: null },
      ]);
      expect(onClose).toHaveBeenCalled();
    });
  });
});
