import React from 'react';
import { fireEvent, render } from '@testing-library/react';
import UnlockScreen from './UnlockScreen';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

describe('components/UnlockScreen', () => {
  it('disables submit when password empty', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService: jest.fn(),
      isLoading: false,
      error: null,
    });

    const { getByRole } = render(<UnlockScreen onUnlock={() => {}} />);
    expect(getByRole('button', { name: 'Unlock Persona' })).toBeDisabled();
  });

  it('submits master password and calls onUnlock on success', async () => {
    const initializeService = jest.fn().mockResolvedValue(true);
    const onUnlock = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService,
      isLoading: false,
      error: null,
    });

    const { getByLabelText, getByRole } = render(<UnlockScreen onUnlock={onUnlock} />);
    fireEvent.change(getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(getByRole('button', { name: 'Unlock Persona' }));

    // Let the submit promise resolve
    await Promise.resolve();
    await Promise.resolve();

    expect(initializeService).toHaveBeenCalledWith('pw', undefined);
    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it('passes custom db path when enabled', async () => {
    const initializeService = jest.fn().mockResolvedValue(true);
    const onUnlock = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService,
      isLoading: false,
      error: null,
    });

    const { getByLabelText, getByRole } = render(<UnlockScreen onUnlock={onUnlock} />);
    fireEvent.change(getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(getByLabelText('Use custom database path'));
    fireEvent.change(getByLabelText('Database Path'), { target: { value: '/tmp/persona.db' } });

    fireEvent.click(getByRole('button', { name: 'Unlock Persona' }));

    await Promise.resolve();
    await Promise.resolve();

    expect(initializeService).toHaveBeenCalledWith('pw', '/tmp/persona.db');
    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it('toggles password visibility', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService: jest.fn(),
      isLoading: false,
      error: null,
    });

    const { container, getByLabelText } = render(<UnlockScreen onUnlock={() => {}} />);
    const input = getByLabelText('Master Password') as HTMLInputElement;
    expect(input.type).toBe('password');

    const toggle = container.querySelector('button[type="button"]') as HTMLButtonElement;
    fireEvent.click(toggle);
    expect(input.type).toBe('text');
  });
});

