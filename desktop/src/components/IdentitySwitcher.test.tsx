import React from 'react';
import { fireEvent, render } from '@testing-library/react';
import { IdentitySwitcher } from './IdentitySwitcher';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

describe('components/IdentitySwitcher', () => {
  it('renders placeholder when no current identity', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      switchIdentity: jest.fn(),
    });

    const { getByText } = render(<IdentitySwitcher onCreateIdentity={() => {}} />);
    expect(getByText('Select an identity')).toBeInTheDocument();
  });

  it('opens options and calls onCreateIdentity', () => {
    const onCreateIdentity = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [
        { id: '1', name: 'Personal', identity_type: 'Personal', tags: [] },
        { id: '2', name: 'Work', identity_type: 'Work', tags: [] },
      ],
      currentIdentity: { id: '1', name: 'Personal', identity_type: 'Personal', tags: [] },
      switchIdentity: jest.fn(),
    });

    const { getByRole, getByText } = render(
      <IdentitySwitcher onCreateIdentity={onCreateIdentity} />,
    );

    fireEvent.click(getByRole('button'));
    fireEvent.click(getByText('Create new identity'));
    expect(onCreateIdentity).toHaveBeenCalledTimes(1);
  });
});

