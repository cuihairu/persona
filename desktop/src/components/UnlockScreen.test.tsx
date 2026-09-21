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
    biometricStatus: jest.fn(),
  },
}));

const mockChange = personaAPI.changeMasterPassword as jest.Mock;
const mockBiometricStatus = personaAPI.biometricStatus as jest.Mock;

describe('components/UnlockScreen', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // 默认未配置 biometric（fail-closed 静默降级：无指纹按钮）
    mockBiometricStatus.mockResolvedValue({
      success: true,
      data: { available: false, enabled: false, platform: 'linux-polkit' },
    });
  });

  it('disables submit when password empty', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      initializeService: jest.fn(),
      isLoading: false,
      error: null,
    });

    const { getByRole } = render(<UnlockScreen onUnlock={() => {}} />);
    expect(getByRole('button', { name: '解锁 Persona' })).toBeDisabled();
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
    fireEvent.change(getByLabelText('主密码'), { target: { value: 'pw' } });
    fireEvent.click(getByRole('button', { name: '解锁 Persona' }));

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
    fireEvent.change(getByLabelText('主密码'), { target: { value: 'pw' } });
    fireEvent.click(getByLabelText('使用自定义数据库路径'));
    fireEvent.change(getByLabelText('数据库路径'), { target: { value: '/tmp/persona.db' } });

    fireEvent.click(getByRole('button', { name: '解锁 Persona' }));

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
    const input = getByLabelText('主密码') as HTMLInputElement;
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
      expect(screen.queryByRole('button', { name: '取消' })).not.toBeInTheDocument();
      expect(
        screen.getByRole('button', { name: '修改并解锁' }),
      ).toBeDisabled();
    });

    it('keeps the plain unlock form hidden behind nothing — form still renders', () => {
      // 弹窗是覆盖层，解锁表单仍在（轮换成功后无需额外状态切换即可继续）
      mockForced(jest.fn());

      render(<UnlockScreen onUnlock={() => {}} />);
      expect(screen.getByLabelText('主密码')).toBeInTheDocument();
    });

    it('rotates through the modal and re-initializes with the new password', async () => {
      // 本用例直接从 forced 态渲染起（不先走解锁失败），轮换后的
      // 重 init 是该 mock 的首次调用
      const initializeService = jest.fn().mockResolvedValue(true);
      const onUnlock = jest.fn();
      mockForced(initializeService);

      render(<UnlockScreen onUnlock={onUnlock} />);

      fireEvent.change(screen.getByLabelText('当前密码'), {
        target: { value: 'old-pw' },
      });
      fireEvent.change(screen.getByLabelText('新密码'), {
        target: { value: 'new-pw' },
      });
      fireEvent.change(screen.getByLabelText('确认新密码'), {
        target: { value: 'new-pw' },
      });
      fireEvent.click(screen.getByRole('button', { name: '修改并解锁' }));

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
      fireEvent.change(getByLabelText('主密码'), { target: { value: 'tried-pw' } });
      fireEvent.click(screen.getByRole('button', { name: '解锁 Persona' }));
      await Promise.resolve();
      await Promise.resolve();

      await waitFor(() => {
        expect(screen.getByLabelText('当前密码') as HTMLInputElement).toHaveValue(
          'tried-pw',
        );
      });
    });
  });

  // -------------------------------------------------------------------------
  // biometric 指纹解锁按钮（status 防抖 200ms 后驱动显隐）
  // -------------------------------------------------------------------------

  describe('biometric unlock', () => {
    const enabledStatus = {
      success: true,
      data: { available: true, enabled: true, platform: 'linux-polkit' },
    };

    const mockHook = (unlockWithBiometric: jest.Mock) => {
      (usePersonaService as jest.Mock).mockReturnValue({
        initializeService: jest.fn(),
        unlockWithBiometric,
        isLoading: false,
        error: null,
      });
    };

    it('hides the fingerprint button when biometric is not configured', async () => {
      mockHook(jest.fn());
      mockBiometricStatus.mockResolvedValue({
        success: true,
        data: { available: false, enabled: false, platform: 'linux-polkit' },
      });

      render(<UnlockScreen onUnlock={() => {}} />);

      // 防抖 200ms 后仍无按钮
      await waitFor(
        () => {
          expect(mockBiometricStatus).toHaveBeenCalled();
        },
        { timeout: 3000 },
      );
      expect(screen.queryByTestId('biometric-unlock-button')).not.toBeInTheDocument();
    });

    it('unlocks via biometric when configured', async () => {
      const unlockWithBiometric = jest.fn().mockResolvedValue({ success: true, data: true });
      const onUnlock = jest.fn();
      mockHook(unlockWithBiometric);
      mockBiometricStatus.mockResolvedValue(enabledStatus);

      render(<UnlockScreen onUnlock={onUnlock} />);

      const button = await screen.findByTestId(
        'biometric-unlock-button',
        {},
        { timeout: 3000 },
      );
      fireEvent.click(button);

      await waitFor(() => {
        expect(unlockWithBiometric).toHaveBeenCalledWith(undefined);
      });
      await waitFor(() => {
        expect(onUnlock).toHaveBeenCalledTimes(1);
      });
    });

    it('passes the custom db path through to the biometric unlock', async () => {
      const unlockWithBiometric = jest.fn().mockResolvedValue({ success: true, data: true });
      mockHook(unlockWithBiometric);
      mockBiometricStatus.mockResolvedValue(enabledStatus);

      render(<UnlockScreen onUnlock={() => {}} />);
      fireEvent.click(screen.getByLabelText('使用自定义数据库路径'));
      fireEvent.change(screen.getByLabelText('数据库路径'), {
        target: { value: '/tmp/bio.db' },
      });

      const button = await screen.findByTestId(
        'biometric-unlock-button',
        {},
        { timeout: 3000 },
      );
      // 自定义路径变化触发 status 重查（防抖后），仍启用
      fireEvent.click(button);

      await waitFor(() => {
        expect(unlockWithBiometric).toHaveBeenCalledWith('/tmp/bio.db');
      });
    });

    it('hides the button after a stale keyring entry self-deletes (BIOMETRIC_RESET)', async () => {
      const unlockWithBiometric = jest
        .fn()
        .mockResolvedValue({ success: false, error_code: 'BIOMETRIC_RESET', error: 'reset' });
      const onUnlock = jest.fn();
      mockHook(unlockWithBiometric);
      mockBiometricStatus.mockResolvedValue(enabledStatus);

      render(<UnlockScreen onUnlock={onUnlock} />);

      const button = await screen.findByTestId(
        'biometric-unlock-button',
        {},
        { timeout: 3000 },
      );
      fireEvent.click(button);

      // 条目已被后端自删：按钮立即消失，且绝不能算解锁成功
      await waitFor(() => {
        expect(screen.queryByTestId('biometric-unlock-button')).not.toBeInTheDocument();
      });
      expect(onUnlock).not.toHaveBeenCalled();
    });
  });
});

