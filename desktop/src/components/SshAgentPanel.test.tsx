import React from 'react';
import { fireEvent, render } from '@testing-library/react';
import SshAgentPanel from './SshAgentPanel';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

describe('components/SshAgentPanel', () => {
  it('calls refreshSshAgentStatus and loadSshKeys on mount', async () => {
    const refreshSshAgentStatus = jest.fn();
    const loadSshKeys = jest.fn();

    (usePersonaService as jest.Mock).mockReturnValue({
      sshAgentStatus: { running: false, socket_path: null, key_count: 0 },
      sshKeys: [],
      refreshSshAgentStatus,
      startSshAgent: jest.fn(),
      stopSshAgent: jest.fn(),
      loadSshKeys,
    });

    render(<SshAgentPanel />);
    await Promise.resolve();
    expect(refreshSshAgentStatus).toHaveBeenCalled();
    expect(loadSshKeys).toHaveBeenCalled();
  });

  it('starts agent with optional master password', async () => {
    const startSshAgent = jest.fn().mockResolvedValue(undefined);
    const refreshSshAgentStatus = jest.fn().mockResolvedValue(undefined);

    (usePersonaService as jest.Mock).mockReturnValue({
      sshAgentStatus: { running: false, socket_path: null, key_count: 0 },
      sshKeys: [],
      refreshSshAgentStatus,
      startSshAgent,
      stopSshAgent: jest.fn(),
      loadSshKeys: jest.fn(),
    });

    const { getByPlaceholderText, getByText } = render(<SshAgentPanel />);
    fireEvent.change(getByPlaceholderText('Master password (optional)'), { target: { value: 'pw' } });
    fireEvent.click(getByText('Start'));

    await Promise.resolve();
    await Promise.resolve();

    expect(startSshAgent).toHaveBeenCalledWith('pw');
    expect(refreshSshAgentStatus).toHaveBeenCalled();
  });
});

