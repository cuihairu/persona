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

  it('closes on backdrop mousedown (click lands on the overlay itself)', () => {
    renderModal();

    // Backdrop mousedown = close: the event is dispatched on the overlay itself → target === currentTarget
    fireEvent.mouseDown(screen.getByTestId('reauth-modal'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('submits the typed master password', () => {
    renderModal();

    fireEvent.change(screen.getByPlaceholderText('主密码'), {
      target: { value: 'master-pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: '确认' }));

    expect(onSubmit).toHaveBeenCalledWith('master-pw');
  });

  it('submits on Enter (form submit) and blocks empty or verifying submissions', () => {
    // An empty password does not submit
    const first = renderModal();
    fireEvent.submit(first.container.querySelector('form')!);
    expect(onSubmit).not.toHaveBeenCalled();
    first.unmount();

    // While verifying, the button is disabled
    const second = renderModal({ isVerifying: true });
    expect(screen.getByRole('button', { name: '验证中…' })).toBeDisabled();
    second.unmount();

    // Enter after typing the password submits
    renderModal();
    fireEvent.change(screen.getByPlaceholderText('主密码'), {
      target: { value: 'pw' },
    });
    fireEvent.submit(screen.getByRole('button', { name: '确认' }).closest('form')!);
    expect(onSubmit).toHaveBeenCalledWith('pw');
  });

  it('shows the API error inside the dialog', () => {
    renderModal({ error: 'Invalid master password' });
    expect(screen.getByTestId('reauth-error')).toHaveTextContent('Invalid master password');
  });

  it('closes via cancel, close button and Escape', () => {
    const { rerender } = renderModal();

    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(onClose).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    expect(onClose).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);

    // Escape is no longer watched once closed
    rerender(<ReauthModal isOpen={false} onClose={onClose} onSubmit={onSubmit} />);
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);
  });

  it('clears the password each time it reopens', () => {
    const { rerender } = renderModal();
    const input = () => screen.getByPlaceholderText('主密码') as HTMLInputElement;

    fireEvent.change(input(), { target: { value: 'stale' } });
    expect(input().value).toBe('stale');

    rerender(<ReauthModal isOpen={false} onClose={onClose} onSubmit={onSubmit} />);
    rerender(<ReauthModal isOpen onClose={onClose} onSubmit={onSubmit} />);
    expect(input().value).toBe('');
  });
});
