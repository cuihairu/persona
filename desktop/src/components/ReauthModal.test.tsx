import { fireEvent, render, screen } from '@testing-library/react';
import ReauthModal from './ReauthModal';

describe('components/ReauthModal', () => {
  const onSubmit = jest.fn();
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  const renderModal = (
    props: Partial<React.ComponentProps<typeof ReauthModal>> = {},
  ) => render(<ReauthModal isOpen onClose={onClose} onSubmit={onSubmit} {...props} />);

  it('renders nothing when closed', () => {
    const { container } = renderModal({ isOpen: false });
    expect(container).toBeEmptyDOMElement();
  });

  it('submits the typed master password', () => {
    renderModal();

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(onSubmit).toHaveBeenCalledWith('master-pw');
  });

  it('submits on Enter (form submit) and blocks empty or verifying submissions', () => {
    // 空密码不触发提交
    const first = renderModal();
    fireEvent.submit(first.container.querySelector('form')!);
    expect(onSubmit).not.toHaveBeenCalled();
    first.unmount();

    // verifying 中按钮禁用
    const second = renderModal({ isVerifying: true });
    expect(screen.getByRole('button', { name: 'Verifying…' })).toBeDisabled();
    second.unmount();

    // 输入密码后回车提交
    renderModal();
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'pw' },
    });
    fireEvent.submit(screen.getByRole('button', { name: 'Confirm' }).closest('form')!);
    expect(onSubmit).toHaveBeenCalledWith('pw');
  });

  it('shows the API error inside the dialog', () => {
    renderModal({ error: 'Invalid master password' });
    expect(screen.getByTestId('reauth-error')).toHaveTextContent('Invalid master password');
  });

  it('closes via cancel, close button and Escape', () => {
    const { rerender } = renderModal();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);

    // 关闭后不再监听 Escape
    rerender(<ReauthModal isOpen={false} onClose={onClose} onSubmit={onSubmit} />);
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);
  });

  it('clears the password each time it reopens', () => {
    const { rerender } = renderModal();
    const input = () => screen.getByPlaceholderText('Master password') as HTMLInputElement;

    fireEvent.change(input(), { target: { value: 'stale' } });
    expect(input().value).toBe('stale');

    rerender(<ReauthModal isOpen={false} onClose={onClose} onSubmit={onSubmit} />);
    rerender(<ReauthModal isOpen onClose={onClose} onSubmit={onSubmit} />);
    expect(input().value).toBe('');
  });
});
