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
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: oldPw } });
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: newPw } });
    fireEvent.change(screen.getByLabelText('确认新密码'), {
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

    // The submit button is disabled while any field is empty
    expect(screen.getByRole('button', { name: '修改密码' })).toBeDisabled();

    fill('old', 'new', '');
    expect(screen.getByRole('button', { name: '修改密码' })).toBeDisabled();
    expect(mockChange).not.toHaveBeenCalled();
  });

  it('rejects mismatched confirmation without calling the API', () => {
    renderModal();
    fill('old-pw', 'new-pw', 'typo-pw');
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

    expect(screen.getByTestId('change-password-error')).toHaveTextContent(
      '两次输入的新密码不一致。',
    );
    expect(mockChange).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
  });

  it('rejects a new password equal to the current one', () => {
    renderModal();
    fill('same-pw', 'same-pw', 'same-pw');
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

    expect(screen.getByTestId('change-password-error')).toHaveTextContent(
      '新密码必须与当前密码不同。',
    );
    expect(mockChange).not.toHaveBeenCalled();
  });

  it('submits the payload and hands the new password to onDone', async () => {
    renderModal({ dbPath: '/tmp/vault.db' });
    fill('old-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

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
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

    await waitFor(() => {
      expect(mockChange).toHaveBeenCalledWith('old-pw', 'new-pw', undefined);
    });
  });

  it('shows the API error inline and stays open', async () => {
    mockChange.mockResolvedValue({ success: false, error: 'Invalid current master password' });
    renderModal();
    fill('wrong-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

    await waitFor(() => {
      expect(screen.getByTestId('change-password-error')).toHaveTextContent(
        'Invalid current master password',
      );
    });
    expect(onDone).not.toHaveBeenCalled();

    // After failure the button becomes usable again (isSubmitting reset)
    expect(screen.getByRole('button', { name: '修改密码' })).toBeEnabled();
  });

  it('maps the TRAVEL_MODE_ACTIVE code to the exit-travel-mode hint', async () => {
    mockChange.mockResolvedValue({
      success: false,
      error: 'Travel mode is active',
      error_code: 'TRAVEL_MODE_ACTIVE',
    });
    renderModal();
    fill('old-pw', 'new-pw', 'new-pw');
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }));

    // The error code drives dedicated copy (guides toward exiting travel mode) instead of passing the backend text through
    await waitFor(() => {
      expect(screen.getByTestId('change-password-error')).toHaveTextContent(
        '旅行模式进行中',
      );
    });
    expect(onDone).not.toHaveBeenCalled();

    // After failure the button becomes usable again (retry in place after exiting travel mode)
    expect(screen.getByRole('button', { name: '修改密码' })).toBeEnabled();
  });

  it('prefills the old password when initialOldPassword is given', () => {
    renderModal({ initialOldPassword: 'typed-old-pw' });

    expect(screen.getByLabelText('当前密码') as HTMLInputElement).toHaveValue(
      'typed-old-pw',
    );
  });

  it('offers cancel/close/Escape only outside forced mode', () => {
    const { rerender } = renderModal();
    expect(screen.getByRole('button', { name: '取消' })).toBeInTheDocument();

    // forced: no Cancel, no Close, and Esc doesn't trigger onCancel
    rerender(
      <ChangeMasterPasswordModal
        isOpen
        forced
        onDone={onDone}
        onCancel={onCancel}
      />,
    );
    expect(screen.queryByRole('button', { name: '取消' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '关闭' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '修改并解锁' })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).not.toHaveBeenCalled();

    // Not forced: Esc closes
    rerender(<ChangeMasterPasswordModal isOpen onDone={onDone} onCancel={onCancel} />);
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('resets the fields each time it reopens', () => {
    const { rerender } = renderModal({ initialOldPassword: 'pre' });
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'stale' } });
    expect(screen.getByLabelText('新密码') as HTMLInputElement).toHaveValue('stale');

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
    expect(screen.getByLabelText('新密码') as HTMLInputElement).toHaveValue('');
    // initialOldPassword persists (the lock screen's forced flow reopens with the old password intact)
    expect(screen.getByLabelText('当前密码') as HTMLInputElement).toHaveValue('pre');
  });
});
