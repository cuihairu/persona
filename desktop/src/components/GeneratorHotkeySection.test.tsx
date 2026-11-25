import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import GeneratorHotkeySection from './GeneratorHotkeySection';
import { personaAPI } from '@/utils/api';
import type { GeneratorStatus } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    generatorStatus: jest.fn(),
    generatorSet: jest.fn(),
    generatorOpen: jest.fn(),
  },
}));

const mockStatus = personaAPI.generatorStatus as jest.Mock;
const mockSet = personaAPI.generatorSet as jest.Mock;
const mockOpen = personaAPI.generatorOpen as jest.Mock;

const status = (overrides: Partial<GeneratorStatus>): GeneratorStatus => ({
  enabled: true,
  configured_accelerator: 'Control+Shift+G',
  registered_accelerator: 'Control+Shift+G',
  error: null,
  ...overrides,
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe('components/GeneratorHotkeySection', () => {
  it('loads the status on mount and shows the active binding', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    render(<GeneratorHotkeySection />);

    await waitFor(() => {
      expect(screen.getByTestId('generator-hotkey-status')).toHaveTextContent('生效中');
    });
    expect(screen.getByTestId('generator-hotkey-toggle')).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByTestId('generator-hotkey')).toHaveValue('Control+Shift+G');
    expect(mockSet).not.toHaveBeenCalled();
  });

  it('surfaces a registration failure with the backend reason', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: status({
        registered_accelerator: null,
        error: 'Another process has already registered this shortcut',
      }),
    });
    render(<GeneratorHotkeySection />);

    await waitFor(() => {
      expect(screen.getByTestId('generator-hotkey-status')).toHaveTextContent('未生效');
    });
    // The reason passes through verbatim (the English is the OS/plugin's own text, not rewritten as "unknown error")
    expect(screen.getByTestId('generator-hotkey-status')).toHaveTextContent(
      'Another process has already registered this shortcut',
    );
  });

  it('disables the toggle while the status is still unknown', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    render(<GeneratorHotkeySection />);

    // On first render (status not yet back) the button is disabled, so an unloaded state can't change the config
    expect(screen.getByTestId('generator-hotkey-toggle')).toBeDisabled();
    await waitFor(() => {
      expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled();
    });
  });

  it('toggling off persists the disabled switch', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ enabled: false, registered_accelerator: null }),
    });
    render(<GeneratorHotkeySection />);
    // Wait until the status actually lands in state (mock called ≠ setState applied; the control is still disabled at this point)
    await waitFor(() => expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('generator-hotkey-toggle'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(false, 'Control+Shift+G');
    });
    await waitFor(() => {
      expect(screen.getByTestId('generator-hotkey-toggle')).toHaveAttribute('aria-checked', 'false');
    });
  });

  it('saving a new binding sends the trimmed accelerator', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Alt+P', registered_accelerator: 'Control+Alt+P' }),
    });
    render(<GeneratorHotkeySection />);
    // Wait until the status actually lands in state (mock called ≠ setState applied; the control is still disabled at this point)
    await waitFor(() => expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled());

    fireEvent.change(screen.getByTestId('generator-hotkey'), {
      target: { value: '  Control+Alt+P  ' },
    });
    fireEvent.click(screen.getByTestId('generator-hotkey-save'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(true, 'Control+Alt+P');
    });
  });

  it('reset sends null so the platform default applies again', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Alt+P' }),
    });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Shift+G' }),
    });
    render(<GeneratorHotkeySection />);
    // Wait until the status actually lands in state (mock called ≠ setState applied; the control is still disabled at this point)
    await waitFor(() => expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('generator-hotkey-reset'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(true, null);
    });
  });

  it('shows the inline error when the command rejects an invalid binding', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({ success: false, error: 'invalid accelerator: empty token' });
    render(<GeneratorHotkeySection />);
    // Wait until the status actually lands in state (mock called ≠ setState applied; the control is still disabled at this point)
    await waitFor(() => expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled());

    fireEvent.change(screen.getByTestId('generator-hotkey'), { target: { value: 'Ctrl+' } });
    fireEvent.click(screen.getByTestId('generator-hotkey-save'));

    await waitFor(() => {
      expect(screen.getByTestId('generator-hotkey-error')).toHaveTextContent(
        'invalid accelerator: empty token',
      );
    });
    // Backend rejection = config unchanged; flipping back to "not active" shouldn't happen (status keeps its value)
    expect(screen.getByTestId('generator-hotkey-status')).toHaveTextContent('生效中');
  });

  it('opens the overlay through the tray-parity button', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockOpen.mockResolvedValue({ success: true, data: true });
    render(<GeneratorHotkeySection />);
    await waitFor(() => expect(screen.getByTestId('generator-hotkey-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('generator-hotkey-open'));

    await waitFor(() => expect(mockOpen).toHaveBeenCalledTimes(1));
  });
});
