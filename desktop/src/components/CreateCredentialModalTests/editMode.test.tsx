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

    it('backfills payload by id when opened without data, and blocks save while hydrating', async () => {
      let resolveFetch: (v: unknown) => void = () => {};
      const getCredentialData = jest.fn(
        () =>
          new Promise((resolve) => {
            resolveFetch = resolve;
          }),
      );
      mockUsePersonaService.mockReturnValue({
        currentIdentity: identity,
        createCredential,
        generatePassword,
        updateCredential,
        updateCredentialData,
        getCredentialData,
        isLoading: false,
      });
      render(
        <CreateCredentialModal
          isOpen
          onClose={onClose}
          editCredential={{ credential: editCred, data: null }}
        />,
      );

      // Metadata is echoed back first; the payload is fetched by id
      expect(getCredentialData).toHaveBeenCalledWith('c-9');
      expect(screen.getByPlaceholderText(/Gmail 账户/)).toHaveValue('Old Name');

      // Until the fetch finishes, saving is disabled (to stop an empty payload from clobbering the existing ciphertext)
      expect(screen.getByRole('button', { name: '保存' })).toBeDisabled();

      resolveFetch({
        credential_type: 'Password',
        data: { password: 'fetched-pw', email: 'old@mail.com' },
      });
      await waitFor(() =>
        expect(screen.getByPlaceholderText('输入密码')).toHaveValue('fetched-pw'),
      );
      expect(screen.getByRole('button', { name: '保存' })).toBeEnabled();
    });

    it('prefills metadata and payload, locks the type selector, titles as Edit', () => {
      renderEditModal();

      expect(screen.getByTestId('credential-modal-title')).toHaveTextContent('编辑条目');
      expect(screen.getByPlaceholderText(/Gmail 账户/)).toHaveValue('Old Name');
      expect((screen.getByPlaceholderText('输入密码') as HTMLInputElement).value).toBe('old-pw');
      expect(screen.getByDisplayValue('olduser')).toBeInTheDocument();
      // The type is immutable (1Password semantics)
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

      // Metadata: all fields are submitted (empty strings are trimmed away by the backend)
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
      // Payload: re-seal with the original item key (REAUTH is gated by the backend)
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
        // Opening with data:null triggers the by-id fallback fetch; here it cannot fetch anything (null),
        // and types that only edit metadata are unaffected
        getCredentialData: jest.fn().mockResolvedValue(null),
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
      // The fetch is an async microtask: wait for it to flush (the save button goes from disabled to enabled) before clicking save
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '保存' })).toBeEnabled(),
      );
      fireEvent.click(screen.getByRole('button', { name: '保存' }));

      await waitFor(() => expect(onClose).toHaveBeenCalled());
      expect(updateCredential).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'c-9', name: 'Renamed Card' }),
      );
      // Types without dedicated fields never submit an empty payload (it would blindly clobber the existing ciphertext)
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
      // Refusing re-authentication: no retry and the dialog stays open (metadata is already saved, the ciphertext can be retried)
      expect(updateCredentialData).toHaveBeenCalledTimes(1);
      expect(onClose).not.toHaveBeenCalled();
    });
  });
});
