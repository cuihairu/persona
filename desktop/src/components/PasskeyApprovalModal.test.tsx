import { fireEvent, render, screen } from '@testing-library/react';
import PasskeyApprovalModal from './PasskeyApprovalModal';
import type { PasskeyApprovalRequest } from '@/types';

jest.mock('@tauri-apps/api/event', () => ({
  listen: jest.fn().mockResolvedValue(() => {}),
}));

const createRequest: PasskeyApprovalRequest = {
  request_id: 'passkey-1',
  operation: 'passkey_create',
  rp_id: 'github.com',
  origin: 'https://github.com',
  user_name: 'alice',
  item_id: null,
};

const assertRequest: PasskeyApprovalRequest = {
  request_id: 'passkey-2',
  operation: 'passkey_assert',
  rp_id: null,
  origin: 'https://github.com',
  user_name: null,
  item_id: 'item-uuid',
};

describe('components/PasskeyApprovalModal', () => {
  it('renders nothing when there is no pending request', () => {
    render(<PasskeyApprovalModal request={null} onRespond={jest.fn()} />);
    expect(screen.queryByTestId('passkey-approval-modal')).toBeNull();
  });

  it('shows creation title with origin, rp_id and account', () => {
    render(<PasskeyApprovalModal request={createRequest} onRespond={jest.fn()} />);

    expect(screen.getByText('创建通行密钥？')).toBeInTheDocument();
    expect(screen.getByTestId('approval-origin')).toHaveTextContent('https://github.com');
    expect(screen.getByTestId('approval-rp-id')).toHaveTextContent('github.com');
    expect(screen.getByTestId('approval-user')).toHaveTextContent('alice');
    expect(screen.getByTestId('approval-operation')).toHaveTextContent('passkey_create');
  });

  it('hides rp_id/account rows for assert requests', () => {
    render(<PasskeyApprovalModal request={assertRequest} onRespond={jest.fn()} />);

    expect(screen.getByText('通行密钥登录请求')).toBeInTheDocument();
    expect(screen.queryByTestId('approval-rp-id')).toBeNull();
    expect(screen.queryByTestId('approval-user')).toBeNull();
  });

  it('warns when rp_id differs from the origin hostname', () => {
    const crossDomain: PasskeyApprovalRequest = {
      ...createRequest,
      rp_id: 'evil.example',
    };
    render(<PasskeyApprovalModal request={crossDomain} onRespond={jest.fn()} />);

    expect(screen.getByTestId('approval-warning')).toHaveTextContent(
      '为另一个域 evil.example 请求通行密钥',
    );
  });

  it('shows no warning when rp_id matches the origin hostname', () => {
    render(<PasskeyApprovalModal request={createRequest} onRespond={jest.fn()} />);
    expect(screen.queryByTestId('approval-warning')).toBeNull();
  });

  it('responds allow on Allow click', () => {
    const onRespond = jest.fn();
    render(<PasskeyApprovalModal request={assertRequest} onRespond={onRespond} />);

    fireEvent.click(screen.getByTestId('approval-allow'));
    expect(onRespond).toHaveBeenCalledWith('passkey-2', true);
  });

  it('responds deny on Deny click', () => {
    const onRespond = jest.fn();
    render(<PasskeyApprovalModal request={assertRequest} onRespond={onRespond} />);

    fireEvent.click(screen.getByTestId('approval-deny'));
    expect(onRespond).toHaveBeenCalledWith('passkey-2', false);
  });

  it('responds deny on Escape (safe default)', () => {
    const onRespond = jest.fn();
    render(<PasskeyApprovalModal request={assertRequest} onRespond={onRespond} />);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onRespond).toHaveBeenCalledWith('passkey-2', false);
  });

  it('shows queued-request count when more requests wait', () => {
    render(
      <PasskeyApprovalModal request={assertRequest} pendingCount={3} onRespond={jest.fn()} />,
    );

    expect(screen.getByTestId('approval-queue-count')).toHaveTextContent('还有 2 个请求等待中');
  });
});
