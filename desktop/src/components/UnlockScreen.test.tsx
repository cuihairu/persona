import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import UnlockScreen from './UnlockScreen';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    changeMasterPassword: jest.fn(),
  },
}));

const mockChange = personaAPI.changeMasterPassword as jest.Mock;

describe('components/UnlockScreen', () => {
  it('disables submit when password empty', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService: jest.fn(),
      isLoading: false,
      error: null,
    });

    const { getByRole } = render(<UnlockScreen onUnlock={() => {}} />);
    expect(getByRole('button', { name: 'Unlock Persona' })).toBeDisabled();
  });

  it('submits master password and calls onUnlock on success', async () => {
    const initializeService = jest.fn().mockResolvedValue(true);
    const onUnlock = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService,
      isLoading: false,
      error: null,
    });

    const { getByLabelText, getByRole } = render(<UnlockScreen onUnlock={onUnlock} />);
    fireEvent.change(getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(getByRole('button', { name: 'Unlock Persona' }));

    // Let the submit promise resolve
    await Promise.resolve();
    await Promise.resolve();

    expect(initializeService).toHaveBeenCalledWith('pw', undefined);
    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it('passes custom db path when enabled', async () => {
    const initializeService = jest.fn().mockResolvedValue(true);
    const onUnlock = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService,
      isLoading: false,
      error: null,
    });

    const { getByLabelText, getByRole } = render(<UnlockScreen onUnlock={onUnlock} />);
    fireEvent.change(getByLabelText('Master Password'), { target: { value: 'pw' } });
    fireEvent.click(getByLabelText('Use custom database path'));
    fireEvent.change(getByLabelText('Database Path'), { target: { value: '/tmp/persona.db' } });

    fireEvent.click(getByRole('button', { name: 'Unlock Persona' }));

    await Promise.resolve();
    await Promise.resolve();

    expect(initializeService).toHaveBeenCalledWith('pw', '/tmp/persona.db');
    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it('toggles password visibility', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService: jest.fn(),
      isLoading: false,
      error: null,
    });

    const { container, getByLabelText } = render(<UnlockScreen onUnlock={() => {}} />);
    const input = getByLabelText('Master Password') as HTMLInputElement;
    expect(input.type).toBe('password');

    const toggle = container.querySelector('button[type="button"]') as HTMLButtonElement;
    fireEvent.click(toggle);
    expect(input.type).toBe('text');
  });

  // -------------------------------------------------------------------------
  // 强制改密流（passwordChangeRequired 标志驱动）
  // -------------------------------------------------------------------------

  describe('forced password rotation', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      mockChange.mockResolvedValue({ success: true, data: true });
    });

    const mockForced = (initializeService: jest.Mock) => {
      (usePersonaService as jest.Mock).mockReturnValue({
        initializeService,
        isLoading: false,
        error: null,
        passwordChangeRequired: true,
      });
    };

    it('renders the forced modal without a cancel escape hatch', () => {
      mockForced(jest.fn());

      render(<UnlockScreen onUnlock={() => {}} />);

      expect(screen.getByTestId('change-password-modal')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
      expect(
        screen.getByRole('button', { name: 'Change and unlock' }),
      ).toBeDisabled();
    });

    it('keeps the plain unlock form hidden behind nothing — form still renders', () => {
      // 弹窗是覆盖层，解锁表单仍在（轮换成功后无需额外状态切换即可继续）
      mockForced(jest.fn());

      render(<UnlockScreen onUnlock={() => {}} />);
      expect(screen.getByLabelText('Master Password')).toBeInTheDocument();
    });

    it('rotates through the modal and re-initializes with the new password', async () => {
      // 本用例直接从 forced 态渲染起（不先走解锁失败），轮换后的
      // 重 init 是该 mock 的首次调用
      const initializeService = jest.fn().mockResolvedValue(true);
      const onUnlock = jest.fn();
      mockForced(initializeService);

      render(<UnlockScreen onUnlock={onUnlock} />);

      fireEvent.change(screen.getByLabelText('Current password'), {
        target: { value: 'old-pw' },
      });
      fireEvent.change(screen.getByLabelText('New password'), {
        target: { value: 'new-pw' },
      });
      fireEvent.change(screen.getByLabelText('Confirm new password'), {
        target: { value: 'new-pw' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Change and unlock' }));

      await waitFor(() => {
        expect(mockChange).toHaveBeenCalledWith('old-pw', 'new-pw', undefined);
      });
      await waitFor(() => {
        expect(initializeService).toHaveBeenLastCalledWith('new-pw', undefined);
      });
      await waitFor(() => {
        expect(onUnlock).toHaveBeenCalledTimes(1);
      });
    });

    it('prefills the old password from the failed unlock attempt', async () => {
      const initializeService = jest.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
      mockForced(initializeService);

      const { getByLabelText } = render(<UnlockScreen onUnlock={() => {}} />);

      // 模拟真实时序：先输旧密解锁失败（flag 置位），弹窗预填该密码
      fireEvent.change(getByLabelText('Master Password'), { target: { value: 'tried-pw' } });
      fireEvent.click(screen.getByRole('button', { name: 'Unlock Persona' }));
      await Promise.resolve();
      await Promise.resolve();

      await waitFor(() => {
        expect(screen.getByLabelText('Current password') as HTMLInputElement).toHaveValue(
          'tried-pw',
        );
      });
    });
  });
});

