import { fireEvent, render, screen } from '@testing-library/react';
import SshApprovalModal from './SshApprovalModal';
import type { SshApprovalRequest } from '@/types';

jest.mock('@tauri-apps/api/event', () => ({
  listen: jest.fn().mockResolvedValue(() => {}),
}));

const request: SshApprovalRequest = {
  request_id: 'ssh-1',
  key_id: 'key-uuid',
  fingerprint: 'SHA256:abcd1234',
  operation: 'sign',
  peer: 'github.com',
  timestamp: '2024-01-01T00:00:00Z',
  reason: 'policy: confirm required',
};

describe('components/SshApprovalModal', () => {
  it('renders nothing when there is no pending request', () => {
    render(<SshApprovalModal request={null} onRespond={jest.fn()} />);
    expect(screen.queryByTestId('ssh-approval-modal')).toBeNull();
  });

  it('shows fingerprint, peer, operation and reason', () => {
    render(<SshApprovalModal request={request} onRespond={jest.fn()} />);

    expect(screen.getByTestId('approval-peer')).toHaveTextContent('github.com');
    expect(screen.getByTestId('approval-fingerprint')).toHaveTextContent('SHA256:abcd1234');
    expect(screen.getByTestId('approval-operation')).toHaveTextContent('sign');
    expect(screen.getByTestId('approval-reason')).toHaveTextContent('policy: confirm required');
  });

  it('responds allow on Allow click', () => {
    const onRespond = jest.fn();
    render(<SshApprovalModal request={request} onRespond={onRespond} />);

    fireEvent.click(screen.getByTestId('approval-allow'));
    expect(onRespond).toHaveBeenCalledWith('ssh-1', true);
  });

  it('responds deny on Deny click', () => {
    const onRespond = jest.fn();
    render(<SshApprovalModal request={request} onRespond={onRespond} />);

    fireEvent.click(screen.getByTestId('approval-deny'));
    expect(onRespond).toHaveBeenCalledWith('ssh-1', false);
  });

  it('responds deny on Escape (safe default)', () => {
    const onRespond = jest.fn();
    render(<SshApprovalModal request={request} onRespond={onRespond} />);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onRespond).toHaveBeenCalledWith('ssh-1', false);
  });

  it('shows queued-request count when more requests wait', () => {
    render(
      <SshApprovalModal request={request} pendingCount={3} onRespond={jest.fn()} />,
    );

    expect(screen.getByTestId('approval-queue-count')).toHaveTextContent('2 more requests');
  });
});
