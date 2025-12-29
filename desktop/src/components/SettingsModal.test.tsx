import React from 'react';
import { fireEvent, render } from '@testing-library/react';
import SettingsModal from './SettingsModal';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

describe('components/SettingsModal', () => {
  it('renders nothing when closed', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    const { container } = render(<SettingsModal isOpen={false} onClose={() => {}} />);
    expect(container.firstChild).toBeNull();
  });

  it('shows empty state when no identities', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    const { getByText } = render(<SettingsModal isOpen={true} onClose={() => {}} />);
    expect(getByText('No identities yet.')).toBeInTheDocument();
  });

  it('edits and saves identity', async () => {
    const updateIdentity = jest.fn().mockResolvedValue({ id: '1' });
    const identity = {
      id: '1',
      name: 'Old',
      identity_type: 'Personal',
      description: '',
      email: '',
      phone: '',
      tags: ['a', 'b'],
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      is_active: true,
    } as any;

    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: identity,
      updateIdentity,
      deleteIdentity: jest.fn(),
      isLoading: false,
    });

    const { container, getByTitle, getAllByText } = render(
      <SettingsModal isOpen={true} onClose={() => {}} />,
    );

    fireEvent.click(getByTitle('Edit'));

    const inputs = container.querySelectorAll('input.input');
    // order: name, email, phone, tags
    fireEvent.change(inputs[0], { target: { value: ' New Name ' } });
    fireEvent.change(inputs[3], { target: { value: 'a, b, c, c' } });

    fireEvent.click(getAllByText('Save')[0]);

    await Promise.resolve();
    await Promise.resolve();

    expect(updateIdentity).toHaveBeenCalledWith(
      expect.objectContaining({
        id: '1',
        name: 'New Name',
        tags: expect.arrayContaining(['a', 'b', 'c']),
      }),
    );
  });

  it('deletes identity after confirm', async () => {
    const deleteIdentity = jest.fn().mockResolvedValue(true);
    const identity = { id: '1', name: 'ToDelete', identity_type: 'Personal', tags: [] } as any;

    (usePersonaService as jest.Mock).mockReturnValue({
      identities: [identity],
      currentIdentity: null,
      updateIdentity: jest.fn(),
      deleteIdentity,
      isLoading: false,
    });

    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);

    const { getByTitle } = render(<SettingsModal isOpen={true} onClose={() => {}} />);
    fireEvent.click(getByTitle('Delete'));

    await Promise.resolve();
    await Promise.resolve();

    expect(deleteIdentity).toHaveBeenCalledWith('1');
    confirmSpy.mockRestore();
  });
});
