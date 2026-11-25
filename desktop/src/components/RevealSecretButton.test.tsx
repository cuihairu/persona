import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import RevealSecretButton from './RevealSecretButton';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';

// Under jsdom the reauth modal opens outside act and fireEvent cannot interact with it (see the
// jsdom-act-outside-modal-testing lesson): mock useReauth and only test the button's retry
// orchestration; the modal itself is covered by ReauthModal.test.tsx.
const requestReauth = jest.fn();

jest.mock('@/hooks/useReauth', () => ({
  useReauth: () => ({
    isOpen: false,
    error: null,
    isVerifying: false,
    requestReauth: (...args: any[]) => requestReauth(...(args as [])),
    submit: jest.fn(),
    cancel: jest.fn(),
  }),
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    revealCredentialSecret: jest.fn(),
  },
}));

const reveal = personaAPI.revealCredentialSecret as jest.Mock;

const resolveOk = (value: string) => ({
  success: true,
  data: { value },
  error: undefined,
});

describe('components/RevealSecretButton', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (copyWithAutoClear as jest.Mock).mockClear().mockResolvedValue(true);
    requestReauth.mockResolvedValue(false);
  });

  it('reveals the secret, shows the countdown and hides again', async () => {
    jest.useFakeTimers();
    reveal.mockResolvedValue(resolveOk('s3cret'));

    render(<RevealSecretButton credentialId="c1" field="password" label="Password" autoHideSeconds={2} />);

    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await act(async () => {});
    expect(reveal).toHaveBeenCalledWith('c1', 'password', undefined);
    expect(screen.getByTestId('revealed-value').textContent).toBe('s3cret');
    expect(screen.getByTestId('reveal-countdown').textContent).toBe('2 秒后隐藏');

    // Decrements every second; auto-hides at zero and resets the retry flag
    await act(async () => {
      jest.advanceTimersByTime(1000);
    });
    expect(screen.getByTestId('reveal-countdown').textContent).toBe('1 秒后隐藏');
    await act(async () => {
      jest.advanceTimersByTime(1000);
    });
    await act(async () => {
      jest.advanceTimersByTime(1000);
    });
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument();

    jest.useRealTimers();
  });

  it('retries the reveal once after successful re-auth', async () => {
    reveal
      .mockResolvedValueOnce({ success: false, data: undefined, error_code: 'REAUTH_REQUIRED' })
      .mockResolvedValueOnce(resolveOk('after-reauth'));
    requestReauth.mockResolvedValue(true);

    render(<RevealSecretButton credentialId="c1" field="password" label="Password" />);

    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value').textContent).toBe('after-reauth');
    });
    expect(requestReauth).toHaveBeenCalledTimes(1);
    expect(reveal).toHaveBeenCalledTimes(2);
  });

  it('cancellation does not consume the retry; hide resets it', async () => {
    const REAUTH = { success: false, data: undefined, error_code: 'REAUTH_REQUIRED' };
    // reveal response queue: REAUTH_REQUIRED by default
    const queue: any[] = [];
    reveal.mockImplementation(() => Promise.resolve(queue.shift() ?? REAUTH));

    render(<RevealSecretButton credentialId="c1" field="password" label="Password" />);
    const trigger = () => screen.getByTestId('reveal-trigger');

    // Round 1: cancel → no retry, nothing shown
    requestReauth.mockResolvedValue(false);
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(requestReauth).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument();

    // Cancelling does not consume the retry: clicking again still opens the modal
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(requestReauth).toHaveBeenCalledTimes(2);
    });

    // Approve → automatic retry → shown
    requestReauth.mockResolvedValue(true);
    queue.push(REAUTH, resolveOk('shown'));
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value').textContent).toBe('shown');
    });
    expect(requestReauth).toHaveBeenCalledTimes(3);

    // A manual Hide resets the retry flag → only the next REAUTH_REQUIRED round opens the modal again
    fireEvent.click(screen.getByLabelText('隐藏Password'));
    queue.push(REAUTH, resolveOk('again'));
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value').textContent).toBe('again');
    });
    expect(requestReauth).toHaveBeenCalledTimes(4);
  });

  it('maps SERVICE_LOCKED to a friendly message and shows other API errors verbatim', async () => {
    reveal.mockResolvedValueOnce({
      success: false,
      data: undefined,
      error_code: 'SERVICE_LOCKED',
    });
    render(<RevealSecretButton credentialId="c1" field="password" label="Password" />);
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('reveal-error')).toHaveTextContent(
        '服务已锁定，解锁后重试。',
      );
    });

    reveal.mockResolvedValueOnce({ success: false, data: undefined, error: 'audit denied' });
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('reveal-error')).toHaveTextContent('audit denied');
    });
  });

  it('shows thrown errors as text', async () => {
    reveal.mockRejectedValueOnce(new Error('socket closed'));
    render(<RevealSecretButton credentialId="c1" field="password" label="Password" />);
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('reveal-error')).toHaveTextContent('socket closed');
    });
  });

  it('copies via the custom handler or the auto-clearing clipboard fallback', async () => {
    reveal.mockResolvedValue(resolveOk('copy-me'));
    const onCopy = jest.fn();

    render(<RevealSecretButton credentialId="c1" field="password" label="Password" onCopy={onCopy} />);
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByLabelText('复制Password'));
    expect(onCopy).toHaveBeenCalledWith('copy-me');
    expect(copyWithAutoClear).not.toHaveBeenCalled();

    // No custom handler → copyWithAutoClear (the first component already revealed, so there is no trigger)
    render(
      <RevealSecretButton credentialId="c2" field="ssh_private_key" label="Private Key" />,
    );
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getAllByTestId('revealed-value')).toHaveLength(2);
    });
    fireEvent.click(screen.getByLabelText('复制Private Key'));
    expect(copyWithAutoClear).toHaveBeenCalledWith('copy-me');
  });

  it('requires the item password for guarded wallet fields and retries with it', async () => {
    reveal
      .mockResolvedValueOnce({ success: false, data: undefined, error_code: 'ITEM_PASSWORD_REQUIRED' })
      .mockResolvedValueOnce(resolveOk('seed words'));

    render(<RevealSecretButton credentialId="c1" field="wallet_mnemonic" label="助记词" />);

    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('item-password-input')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument();
    expect(reveal).toHaveBeenLastCalledWith('c1', 'wallet_mnemonic', undefined);

    // Submit the item password → automatically retries with the second factor
    fireEvent.change(screen.getByTestId('item-password-input'), { target: { value: 'item-pass' } });
    fireEvent.click(screen.getByTestId('item-password-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value').textContent).toBe('seed words');
    });
    expect(reveal).toHaveBeenLastCalledWith('c1', 'wallet_mnemonic', 'item-pass');
    // The inline input collapses on success
    expect(screen.queryByTestId('item-password-input')).not.toBeInTheDocument();
  });

  it('shows an inline error on ITEM_PASSWORD_WRONG and keeps the input for retry', async () => {
    reveal
      .mockResolvedValueOnce({ success: false, data: undefined, error_code: 'ITEM_PASSWORD_REQUIRED' })
      .mockResolvedValue({ success: false, data: undefined, error_code: 'ITEM_PASSWORD_WRONG' });

    render(<RevealSecretButton credentialId="c1" field="wallet_private_key" label="私钥" />);
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getByTestId('item-password-input')).toBeInTheDocument();
    });
    fireEvent.change(screen.getByTestId('item-password-input'), { target: { value: 'nope' } });
    fireEvent.click(screen.getByTestId('item-password-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('reveal-error')).toHaveTextContent('条目密码不正确');
    });
    expect((screen.getByTestId('item-password-input') as HTMLInputElement).value).toBe('nope');
  });
});
