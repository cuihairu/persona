import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react';
import CredentialList from './CredentialList';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
}));

describe('components/CredentialList', () => {
  it('renders placeholder when no identity selected', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: null,
      getCredentialData: jest.fn(),
    });

    const { getByText } = render(<CredentialList onCreateCredential={() => {}} />);
    expect(getByText('Select an identity to view credentials')).toBeInTheDocument();
  });

  it('shows empty state and calls onCreateCredential', () => {
    const onCreateCredential = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
      getCredentialData: jest.fn(),
    });

    const { getByText } = render(<CredentialList onCreateCredential={onCreateCredential} />);
    fireEvent.click(getByText('Add Your First Credential'));
    expect(onCreateCredential).toHaveBeenCalledTimes(1);
  });

  it('opens credential modal and toggles favorite', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: { email: 'a@b.com', password: 'secret' },
    });
    const toggleCredentialFavorite = jest.fn().mockResolvedValue({ is_favorite: true });

    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [
        {
          id: 'c1',
          identity_id: 'i1',
          name: 'Example',
          credential_type: 'Password',
          security_level: 'High',
          url: 'https://example.com',
          username: 'user',
          tags: [],
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
          is_active: true,
          is_favorite: false,
        },
      ],
      currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
      getCredentialData,
      toggleCredentialFavorite,
      deleteCredential: jest.fn(),
      getTotpCode: jest.fn(),
    });

    const { getByText, getByTitle } = render(<CredentialList onCreateCredential={() => {}} />);
    fireEvent.click(getByText('Example'));

    await waitFor(() => expect(getCredentialData).toHaveBeenCalledWith('c1'));

    await waitFor(() => expect(getByTitle('Favorite')).toBeInTheDocument());

    fireEvent.click(getByTitle('Favorite'));
    await waitFor(() => expect(toggleCredentialFavorite).toHaveBeenCalledWith('c1'));
    expect(toggleCredentialFavorite).toHaveBeenCalledWith('c1');
  });
});
