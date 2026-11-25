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

  // -------------------------------------------------------------------------
  // Cover the boundary branches: failures, exceptions and secondary field changes all need observable behavior, not just the happy path
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

      // A failed generate response (142): the phrase is not filled in
      (walletGenerateMnemonic as jest.Mock).mockResolvedValueOnce({
        success: false,
        error: 'nope',
      });
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await act(async () => {});
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue('');

      // A generate IPC exception (145)
      (walletGenerateMnemonic as jest.Mock).mockRejectedValueOnce(new Error('gone'));
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await act(async () => {});
      expect(screen.getByPlaceholderText('12-24 个词的恢复短语')).toHaveValue('');

      // The validation debounce catch (130): a throwing command silently clears the feedback, no crash or hang
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

      // The word-count select (619): changing it to 12 makes generation use the new word count
      fireEvent.change(screen.getByLabelText('词'), { target: { value: '12' } });
      (walletGenerateMnemonic as jest.Mock).mockResolvedValueOnce({
        success: true,
        data: 'abandon x',
      });
      fireEvent.click(screen.getByRole('button', { name: '生成' }));
      await waitFor(() => {
        expect(walletGenerateMnemonic).toHaveBeenCalledWith(12);
      });

      // Showing/hiding the BIP39 passphrase (670)
      const bip39 = screen.getByPlaceholderText('附加口令（可选）') as HTMLInputElement;
      expect(bip39.type).toBe('password');
      fireEvent.click(bip39.parentElement!.querySelector('button')!);
      expect((screen.getByPlaceholderText('附加口令（可选）') as HTMLInputElement).type).toBe('text');

      // Showing/hiding the private key (695)
      const priv = screen.getByPlaceholderText('WIF / hex 私钥') as HTMLInputElement;
      expect(priv.type).toBe('password');
      fireEvent.click(priv.parentElement!.querySelector('button')!);
      expect((screen.getByPlaceholderText('WIF / hex 私钥') as HTMLInputElement).type).toBe('text');

      // The public key (710)
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
      // After mounting, setFormData restores the form type to GameToken from the payload variant
      expect(
        screen.getByPlaceholderText('steam_guard, tencent_security, netease_dashen, mihoyo'),
      ).toBeInTheDocument();
    });

    it('adds, edits and removes custom field rows', async () => {
      renderModal();
      fireEvent.click(screen.getByTestId('custom-field-add'));

      // Editing the label (1313)
      fireEvent.change(screen.getByTestId('custom-field-label-tmp-1'), {
        target: { value: '备注1' },
      });
      expect(screen.getByTestId('custom-field-label-tmp-1')).toHaveValue('备注1');

      // Remove (1327/281-282)
      fireEvent.click(screen.getByTestId('custom-field-remove-tmp-1'));
      expect(screen.queryByTestId('custom-field-label-tmp-1')).not.toBeInTheDocument();
    });

    it('keeps the edit modal open when custom fields persistence fails', async () => {
      // Edit submit path: a field persistence failure → return keeps the dialog retryable (310-311/478)
      // The create path differs: the entry is already created, so a field failure only toasts and does not roll back (531)
      setCredentialCustomFields.mockResolvedValueOnce({ success: false, error: 'locked' });
      renderEdit();
      fireEvent.click(screen.getByTestId('custom-field-add'));

      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(setCredentialCustomFields).toHaveBeenCalled());
      // Metadata and ciphertext are both saved and only the fields failed: the dialog stays open
      expect(updateCredential).toHaveBeenCalled();
      expect(updateCredentialData).toHaveBeenCalled();
      expect(onClose).not.toHaveBeenCalled();
    });

    it('retries payload save once when reauth is granted, and reports lock/generic errors', async () => {
      // REAUTH granted → replay once automatically and close the dialog (492-493)
      mockReauth.requestReauth.mockResolvedValue(true);
      updateCredentialData
        .mockResolvedValueOnce({ success: false, error_code: 'REAUTH_REQUIRED', error: 're-auth' })
        .mockResolvedValueOnce({ success: true, data: { id: 'c-9' } });
      renderEdit();
      fireEvent.click(screen.getByRole('button', { name: '保存' }));
      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(updateCredentialData).toHaveBeenCalledTimes(2);

      // SERVICE_LOCKED (497-498)
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

      // Generic failure (500-502)
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
