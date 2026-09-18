import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import RevealSecretButton from './RevealSecretButton';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';

// jsdom 下 reauth 弹窗在 act 外打开，无法 fireEvent 交互（见
// jsdom-act-outside-modal-testing 教训）：mock useReauth，只测按钮的
// 重试编排；弹窗本体由 ReauthModal.test.tsx 覆盖。
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
    expect(reveal).toHaveBeenCalledWith('c1', 'password');
    expect(screen.getByTestId('revealed-value').textContent).toBe('s3cret');
    expect(screen.getByTestId('reveal-countdown').textContent).toBe('hides in 2s');

    // 每秒递减，归零自动隐藏并复位重试标记
    await act(async () => {
      jest.advanceTimersByTime(1000);
    });
    expect(screen.getByTestId('reveal-countdown').textContent).toBe('hides in 1s');
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
    // reveal 响应队列：默认 REAUTH_REQUIRED
    const queue: any[] = [];
    reveal.mockImplementation(() => Promise.resolve(queue.shift() ?? REAUTH));

    render(<RevealSecretButton credentialId="c1" field="password" label="Password" />);
    const trigger = () => screen.getByTestId('reveal-trigger');

    // 第一轮：取消 → 不重试、不显示
    requestReauth.mockResolvedValue(false);
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(requestReauth).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument();

    // 取消没有消耗重试机会：再点仍会弹窗
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(requestReauth).toHaveBeenCalledTimes(2);
    });

    // 授权 → 自动重试 → 显示
    requestReauth.mockResolvedValue(true);
    queue.push(REAUTH, resolveOk('shown'));
    fireEvent.click(trigger());
    await waitFor(() => {
      expect(screen.getByTestId('revealed-value').textContent).toBe('shown');
    });
    expect(requestReauth).toHaveBeenCalledTimes(3);

    // 手动 Hide 复位重试标记 → 下一轮 REAUTH_REQUIRED 才会再弹
    fireEvent.click(screen.getByLabelText('Hide Password'));
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
        'Service is locked. Unlock and try again.',
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
    fireEvent.click(screen.getByLabelText('Copy Password'));
    expect(onCopy).toHaveBeenCalledWith('copy-me');
    expect(copyWithAutoClear).not.toHaveBeenCalled();

    // 无自定义 handler → copyWithAutoClear（第一个组件已 reveal，无 trigger）
    render(
      <RevealSecretButton credentialId="c2" field="private_key" label="Private Key" />,
    );
    fireEvent.click(screen.getByTestId('reveal-trigger'));
    await waitFor(() => {
      expect(screen.getAllByTestId('revealed-value')).toHaveLength(2);
    });
    fireEvent.click(screen.getByLabelText('Copy Private Key'));
    expect(copyWithAutoClear).toHaveBeenCalledWith('copy-me');
  });
});
