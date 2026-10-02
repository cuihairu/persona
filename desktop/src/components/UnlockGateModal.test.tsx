import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import UnlockGateModal from './UnlockGateModal';
import { usePersonaService } from '@/hooks/usePersonaService';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

describe('components/UnlockGateModal', () => {
  const initializeService = jest.fn();
  const onResolve = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    (usePersonaService as jest.Mock).mockReturnValue({ initializeService });
  });

  const renderModal = (isOpen = true) =>
    render(<UnlockGateModal isOpen={isOpen} onResolve={onResolve} />);

  const passwordInput = () => screen.getByTestId('unlock-gate-password') as HTMLInputElement;
  const submitButton = () => screen.getByTestId('unlock-gate-submit');
  const form = () => submitButton().closest('form')!;

  it('renders nothing when closed', () => {
    const { container } = renderModal(false);
    expect(container).toBeEmptyDOMElement();
    expect(onResolve).not.toHaveBeenCalled();
  });

  it('unlocks with the typed master password and resumes the pending operation', async () => {
    initializeService.mockResolvedValue(true);
    renderModal();

    expect(submitButton()).toBeDisabled();
    fireEvent.change(passwordInput(), { target: { value: 'master-pw' } });
    expect(submitButton()).toBeEnabled();

    fireEvent.click(submitButton());
    await waitFor(() => expect(onResolve).toHaveBeenCalledWith(true));
    expect(initializeService).toHaveBeenCalledWith('master-pw');
  });

  it('keeps the modal open when verification fails', async () => {
    initializeService.mockResolvedValue(false);
    renderModal();

    fireEvent.change(passwordInput(), { target: { value: 'wrong' } });
    fireEvent.click(submitButton());
    await waitFor(() => expect(initializeService).toHaveBeenCalledTimes(1));
    // 失败不关弹窗：submit 回到可用态等待重输
    await waitFor(() => expect(submitButton()).toBeEnabled());
    expect(onResolve).not.toHaveBeenCalled();
  });

  it('blocks empty submissions while the button is disabled', () => {
    renderModal();
    expect(submitButton()).toBeDisabled();
    fireEvent.submit(form());
    expect(initializeService).not.toHaveBeenCalled();
  });

  it('shows the verifying state and ignores repeat submissions while pending', async () => {
    let resolveInit!: (ok: boolean) => void;
    initializeService.mockReturnValue(
      new Promise<boolean>((resolve) => {
        resolveInit = resolve;
      }),
    );
    renderModal();

    fireEvent.change(passwordInput(), { target: { value: 'master-pw' } });
    fireEvent.click(submitButton());

    expect(submitButton()).toBeDisabled();
    expect(submitButton()).toHaveTextContent('解锁中…');
    // verifying 中重复提交（绕过 disabled 的表单提交路径）不再触发 initializeService
    fireEvent.submit(form());
    expect(initializeService).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveInit(true);
    });
    expect(onResolve).toHaveBeenCalledWith(true);
  });

  it('closes via cancel, close button, Escape and overlay click but not content clicks', () => {
    renderModal();

    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(onResolve).toHaveBeenLastCalledWith(false);

    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    expect(onResolve).toHaveBeenCalledTimes(2);

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onResolve).toHaveBeenCalledTimes(3);

    // 点内容区（输入框）不算点空白
    fireEvent.mouseDown(passwordInput());
    expect(onResolve).toHaveBeenCalledTimes(3);

    // 点遮罩空白 = 取消
    fireEvent.mouseDown(screen.getByTestId('unlock-gate-modal'));
    expect(onResolve).toHaveBeenCalledTimes(4);
    expect(onResolve).toHaveBeenLastCalledWith(false);
  });

  it('clears the password each time it reopens', () => {
    const { rerender } = renderModal();

    fireEvent.change(passwordInput(), { target: { value: 'stale' } });
    expect(passwordInput().value).toBe('stale');

    rerender(<UnlockGateModal isOpen={false} onResolve={onResolve} />);
    rerender(<UnlockGateModal isOpen onResolve={onResolve} />);
    expect(passwordInput().value).toBe('');
  });
});
