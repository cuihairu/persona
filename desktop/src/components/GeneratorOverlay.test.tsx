import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import GeneratorOverlay from './GeneratorOverlay';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    generatePasswordAdvanced: jest.fn(),
  },
}));

const hide = jest.fn().mockResolvedValue(undefined);

jest.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    hide: (...args: unknown[]) => hide(...args),
  }),
}));

const mockGenerate = personaAPI.generatePasswordAdvanced as jest.Mock;

beforeEach(() => {
  jest.clearAllMocks();
  mockGenerate.mockResolvedValue({
    success: true,
    data: { passwords: ['generated-secret-1'], entropy_bits: 100, pool_size: 94 },
  });
});

describe('components/GeneratorOverlay', () => {
  it('renders the shared GeneratorPanel and generates without unlocking', async () => {
    render(<GeneratorOverlay />);

    expect(screen.getByTestId('generator-overlay')).toBeInTheDocument();

    // 生成是纯计算（CSPRNG），锁定态也能用：直接点生成按钮即可出结果
    fireEvent.click(screen.getByTestId('generator-generate'));
    await waitFor(() => {
      expect(mockGenerate).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(screen.getByText('generated-secret-1')).toBeInTheDocument();
    });
  });

  it('hides the window on Escape (same instant-overlay semantics as Quick Access)', async () => {
    render(<GeneratorOverlay />);

    fireEvent.keyDown(window, { key: 'Escape' });

    await waitFor(() => {
      expect(hide).toHaveBeenCalledTimes(1);
    });
  });

  it('does not hide on unrelated keys', () => {
    render(<GeneratorOverlay />);

    fireEvent.keyDown(window, { key: 'a' });

    expect(hide).not.toHaveBeenCalled();
  });
});
