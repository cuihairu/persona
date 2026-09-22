import { fireEvent, render, screen } from '@testing-library/react';
import TravelPassphraseModal from './TravelPassphraseModal';

describe('components/TravelPassphraseModal', () => {
  const onSubmit = jest.fn();
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  const renderModal = (
    props: Partial<React.ComponentProps<typeof TravelPassphraseModal>> = {},
  ) =>
    render(
      <TravelPassphraseModal
        isOpen
        mode="set"
        onClose={onClose}
        onSubmit={onSubmit}
        {...props}
      />,
    );

  const type = (testId: string, value: string) =>
    fireEvent.change(screen.getByTestId(testId), { target: { value } });

  it('renders nothing when closed', () => {
    const { container } = renderModal({ isOpen: false });
    expect(container).toBeEmptyDOMElement();
  });

  it("mode='set' shows a confirm field and blocks mismatched entries", () => {
    renderModal({ mode: 'set' });
    expect(screen.getByTestId('travel-passphrase-confirm-input')).toBeInTheDocument();

    type('travel-passphrase-input', 'travel-pw');
    type('travel-passphrase-confirm-input', 'different');

    fireEvent.submit(screen.getByTestId('travel-passphrase-submit').closest('form')!);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent(
      '两次输入的口令不一致',
    );

    // 修正后可提交
    type('travel-passphrase-confirm-input', 'travel-pw');
    fireEvent.submit(screen.getByTestId('travel-passphrase-submit').closest('form')!);
    expect(onSubmit).toHaveBeenCalledWith('travel-pw');
  });

  it("mode='enter' has a single field and submits directly", () => {
    renderModal({ mode: 'enter' });
    expect(screen.queryByTestId('travel-passphrase-confirm-input')).not.toBeInTheDocument();

    type('travel-passphrase-input', 'travel-pw');
    fireEvent.submit(screen.getByTestId('travel-passphrase-submit').closest('form')!);
    expect(onSubmit).toHaveBeenCalledWith('travel-pw');
  });

  it('shows the API error inside the dialog', () => {
    renderModal({ mode: 'enter', error: 'passphrase is wrong' });
    expect(screen.getByTestId('travel-passphrase-error')).toHaveTextContent(
      'passphrase is wrong',
    );
  });

  it('warns that there is no master-password fallback when setting', () => {
    renderModal({ mode: 'set' });
    expect(screen.getByText('主密码无法恢复旅行数据——口令丢失即数据丢失。')).toBeInTheDocument();
  });

  it('blocks empty or busy submissions', () => {
    const first = renderModal({ mode: 'enter' });
    fireEvent.submit(screen.getByTestId('travel-passphrase-submit').closest('form')!);
    expect(onSubmit).not.toHaveBeenCalled();
    first.unmount();

    renderModal({ mode: 'enter', isBusy: true });
    type('travel-passphrase-input', 'pw');
    expect(screen.getByTestId('travel-passphrase-submit')).toBeDisabled();
  });

  it('clears both fields each time it reopens', () => {
    const { rerender } = renderModal({ mode: 'set' });
    type('travel-passphrase-input', 'stale');
    type('travel-passphrase-confirm-input', 'stale');

    rerender(
      <TravelPassphraseModal isOpen={false} mode="set" onClose={onClose} onSubmit={onSubmit} />,
    );
    rerender(
      <TravelPassphraseModal isOpen mode="set" onClose={onClose} onSubmit={onSubmit} />,
    );
    expect((screen.getByTestId('travel-passphrase-input') as HTMLInputElement).value).toBe('');
    expect(
      (screen.getByTestId('travel-passphrase-confirm-input') as HTMLInputElement).value,
    ).toBe('');
  });

  it('closes via cancel, close button and Escape', () => {
    renderModal({ mode: 'set' });

    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(onClose).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    expect(onClose).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(3);
  });
});
