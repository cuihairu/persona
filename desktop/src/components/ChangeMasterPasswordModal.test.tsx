import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import ChangeMasterPasswordModal from './ChangeMasterPasswordModal';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    changeMasterPassword: jest.fn(),
  },
}));

const mockChange = personaAPI.changeMasterPassword as jest.Mock;

describe('components/ChangeMasterPasswordModal', () => {
  const onDone = jest.fn();
  const onCancel = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockChange.mockResolvedValue({ success: true, data: true });
  });

  const renderModal = (
    props: Partial<React.ComponentProps<typeof ChangeMasterPasswordModal>> = {},
  ) =>
    render(
      <ChangeMasterPasswordModal isOpen onDone={onDone} onCancel={onCancel} {...props} />,
    );

  const fill = (oldPw: string, newPw: string, confirm: string) => {
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: oldPw } });
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: newPw } });
    fireEvent.change(screen.getByLabelText('Confirm new password'), {
      target: { value: confirm },
    });
  };

  it('renders nothing when closed', () => {
    const { container } = render(
      <ChangeMasterPasswordModal isOpen={false} onDone={onDone} onCancel={onCancel} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('blocks submission while any field is empty', () => {
    renderModal();

    // 提交按钮在任一字段为空时禁用
    expect(screen.getByRole('button', { name: 'Change password' })).toBeDisabled();

    fill('old', 'new', '');
    expect(screen.getByRole('button', { name: 'Change password' })).toBeDisabled();
    expect(mockChange).not.toHaveBeenCalled();
  });

  it('rejects mismatched confirmation without calling the API', () => {
    renderModal();
    fill('old-pw', 'new-pw', 'typo-pw');
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    expect(screen.getByTestId('change-password-error')).toHaveTextContent(
      'New passwords do not match.',
    );
    expect(mockChange).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
  });

  it('rejects a new password equal to the current one', () => {
    renderModal();
    fill('same-pw', 'same-pw', 'same-pw');
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    expect(screen.getByTestId('change-password-error')).toHaveTextContent(
      'New password must be different from the current password.',
    );
    expect(mockChange).not.toHaveBeenCalled();
  });

  it('submits the payload and hands the new password to onDone', async () => {
    renderModal({ dbPath: '/tmp/vault.db' });
    fill('old-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    await waitFor(() => {
      expect(mockChange).toHaveBeenCalledWith('old-pw', 'new-pw', '/tmp/vault.db');
    });
    await waitFor(() => {
      expect(onDone).toHaveBeenCalledWith('new-pw');
    });
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('passes undefined dbPath when unset', async () => {
    renderModal();
    fill('old-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    await waitFor(() => {
      expect(mockChange).toHaveBeenCalledWith('old-pw', 'new-pw', undefined);
    });
  });

  it('shows the API error inline and stays open', async () => {
    mockChange.mockResolvedValue({ success: false, error: 'Invalid current master password' });
    renderModal();
    fill('wrong-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }));

    await waitFor(() => {
      expect(screen.getByTestId('change-password-error')).toHaveTextContent(
        'Invalid current master password',
      );
    });
    expect(onDone).not.toHaveBeenCalled();

    // 失败后按钮恢复可用（isSubmitting 复位）
    expect(screen.getByRole('button', { name: 'Change password' })).toBeEnabled();
  });

  it('prefills the old password when initialOldPassword is given', () => {
    renderModal({ initialOldPassword: 'typed-old-pw' });

    expect(screen.getByLabelText('Current password') as HTMLInputElement).toHaveValue(
      'typed-old-pw',
    );
  });

  it('offers cancel/close/Escape only outside forced mode', () => {
    const { rerender } = renderModal();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();

    // forced：无 Cancel、无 Close，Esc 不触发 onCancel
    rerender(
      <ChangeMasterPasswordModal
        isOpen
        forced
        onDone={onDone}
        onCancel={onCancel}
      />,
    );
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change and unlock' })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).not.toHaveBeenCalled();

    // 非 forced：Esc 关闭
    rerender(<ChangeMasterPasswordModal isOpen onDone={onDone} onCancel={onCancel} />);
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('resets the fields each time it reopens', () => {
    const { rerender } = renderModal({ initialOldPassword: 'pre' });
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'stale' } });
    expect(screen.getByLabelText('New password') as HTMLInputElement).toHaveValue('stale');

    rerender(
      <ChangeMasterPasswordModal
        isOpen={false}
        onDone={onDone}
        onCancel={onCancel}
      />,
    );
    rerender(
      <ChangeMasterPasswordModal
        isOpen
        initialOldPassword="pre"
        onDone={onDone}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByLabelText('New password') as HTMLInputElement).toHaveValue('');
    // initialOldPassword 仍在（解锁屏 forced 流重开时旧密不变）
    expect(screen.getByLabelText('Current password') as HTMLInputElement).toHaveValue('pre');
  });
});
