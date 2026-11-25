// Shared helpers for the CreateCredentialModal tests: module-level mocks, pinned defaults, fixtures and locating utilities
// Each test file brings its own jest.mock factory pointing at the instances here (the single instance guarantees that re-pinning in beforeEach takes effect globally)
import { fireEvent, screen } from '@testing-library/react';
import type { Identity } from '@/types';

export const mockUsePersonaService = jest.fn();
export const createCredential = jest.fn();
export const generatePassword = jest.fn();
export const updateCredential = jest.fn();
export const updateCredentialData = jest.fn();

// Pure computation commands that the wallet form calls on personaAPI directly (generate/validate a mnemonic; no DB access)
export const walletValidateMnemonic = jest.fn().mockResolvedValue({
  success: true,
  data: { valid: true, word_count: 2, error: null },
});
export const walletGenerateMnemonic = jest.fn().mockResolvedValue({
  success: true,
  data: 'abandon ability able about above absent absorb abstract absurd abuse access accident',
});

// Whole-table read/write of custom fields (the add/remove/edit UI of the edit form); defaults to a successful empty table, each case overrides it
export const getCredentialCustomFields = jest
  .fn()
  .mockResolvedValue({ success: true, data: [] });
export const setCredentialCustomFields = jest
  .fn()
  .mockResolvedValue({ success: true, data: [] });


// The modal wires useReauth to handle REAUTH_REQUIRED for the payload save;
// the default is the "cancel" semantics (resolves false → no automatic retry); the REAUTH cases assert the orchestration
export const mockReauth = {
  isOpen: false,
  error: null as string | null,
  isVerifying: false,
  requestReauth: jest.fn().mockResolvedValue(false),
  submit: jest.fn(),
  cancel: jest.fn(),
};

/** Resets and re-pins the defaults before each case (clearAllMocks does not clear mockResolvedValue, preventing bleed between cases). */
export const pinDefaultMocks = (): void => {
  jest.clearAllMocks();
  createCredential.mockResolvedValue({ id: 'c-1' });
  generatePassword.mockResolvedValue('');
  updateCredential.mockResolvedValue({ id: 'c-9' });
  updateCredentialData.mockResolvedValue({ success: true, data: { id: 'c-9' } });
  // Re-pin the defaults (clearAllMocks does not clear mockResolvedValue, preventing bleed between cases)
  getCredentialCustomFields.mockResolvedValue({ success: true, data: [] });
  setCredentialCustomFields.mockResolvedValue({ success: true, data: [] });
  mockUsePersonaService.mockReturnValue({
    currentIdentity: identity,
    createCredential,
    generatePassword,
    isLoading: false,
  });
};

export const identity = {
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

/** The component labels do not bind htmlFor, so selects are located by value (Type is always the first combobox in the form). */
export const getSelect = (value: string): HTMLSelectElement =>
  screen
    .getAllByRole('combobox')

    .find((el) => (el as HTMLSelectElement).value === value) as HTMLSelectElement;

export const selectType = (type: string) => {
  fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: type } });
};
