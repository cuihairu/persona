import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import QuickAccessSection from './QuickAccessSection';
import { personaAPI } from '@/utils/api';
import type { QuickAccessStatus } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    quickAccessStatus: jest.fn(),
    quickAccessSet: jest.fn(),
    quickAccessOpen: jest.fn(),
  },
}));

const mockStatus = personaAPI.quickAccessStatus as jest.Mock;
const mockSet = personaAPI.quickAccessSet as jest.Mock;
const mockOpen = personaAPI.quickAccessOpen as jest.Mock;

const status = (overrides: Partial<QuickAccessStatus>): QuickAccessStatus => ({
  enabled: true,
  configured_accelerator: 'Control+Shift+Space',
  registered_accelerator: 'Control+Shift+Space',
  error: null,
  ...overrides,
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe('components/QuickAccessSection', () => {
  it('loads the status on mount and shows the active binding', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    render(<QuickAccessSection />);

    await waitFor(() => {
      expect(screen.getByTestId('quick-access-status')).toHaveTextContent('生效中');
    });
    expect(screen.getByTestId('quick-access-toggle')).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByTestId('quick-access-hotkey')).toHaveValue('Control+Shift+Space');
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
    render(<QuickAccessSection />);

    await waitFor(() => {
      expect(screen.getByTestId('quick-access-status')).toHaveTextContent('未生效');
    });
    // The reason is surfaced verbatim (the English text is the OS/plugin original, not translated into a generic "unknown error")
    expect(screen.getByTestId('quick-access-status')).toHaveTextContent(
      'Another process has already registered this shortcut',
    );
  });

  it('disables the toggle while the status is still unknown', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    render(<QuickAccessSection />);

    // First render (status has not come back yet): the button is disabled, so the config is not mutated with an unloaded status
    expect(screen.getByTestId('quick-access-toggle')).toBeDisabled();
    await waitFor(() => {
      expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled();
    });
  });

  it('toggling off persists the disabled switch', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ enabled: false, registered_accelerator: null }),
    });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('quick-access-toggle'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(false, 'Control+Shift+Space');
    });
    await waitFor(() => {
      expect(screen.getByTestId('quick-access-toggle')).toHaveAttribute('aria-checked', 'false');
    });
  });

  it('saving a new binding sends the trimmed accelerator', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Alt+K', registered_accelerator: 'Control+Alt+K' }),
    });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.change(screen.getByTestId('quick-access-hotkey'), {
      target: { value: '  Control+Alt+K  ' },
    });
    fireEvent.click(screen.getByTestId('quick-access-save'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(true, 'Control+Alt+K');
    });
  });

  it('reset sends null so the platform default applies again', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Alt+K' }),
    });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Shift+Space' }),
    });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('quick-access-reset'));

    await waitFor(() => {
      expect(mockSet).toHaveBeenCalledWith(true, null);
    });
  });

  it('shows the inline error when the command rejects an invalid binding', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({ success: false, error: 'invalid accelerator: empty token' });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.change(screen.getByTestId('quick-access-hotkey'), { target: { value: 'Ctrl+' } });
    fireEvent.click(screen.getByTestId('quick-access-save'));

    await waitFor(() => {
      expect(screen.getByTestId('quick-access-error')).toHaveTextContent('empty token');
    });
  });

  it('warns when the binding saved but the OS did not accept it', async () => {
    mockStatus.mockResolvedValue({ success: true, data: status({}) });
    mockSet.mockResolvedValue({
      success: true,
      data: status({ configured_accelerator: 'Control+Alt+K', registered_accelerator: null, error: 'taken' }),
    });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.change(screen.getByTestId('quick-access-hotkey'), { target: { value: 'Control+Alt+K' } });
    fireEvent.click(screen.getByTestId('quick-access-save'));

    // A failed registration grab is not a command failure: the status surface updates with an inactive hint, and no error toast copy is shown
    await waitFor(() => {
      expect(screen.getByTestId('quick-access-status')).toHaveTextContent('未生效');
    });
    expect(screen.queryByTestId('quick-access-error')).not.toBeInTheDocument();
  });

  it('opens the overlay on demand even when the hotkey is unavailable', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: status({ registered_accelerator: null, error: 'unavailable' }),
    });
    mockOpen.mockResolvedValue({ success: true, data: true });
    render(<QuickAccessSection />);
    // Wait for the status to actually land in state (the mock being called is not the same as setState having taken effect; the control is still disabled at that point)
    await waitFor(() => expect(screen.getByTestId('quick-access-toggle')).not.toBeDisabled());

    fireEvent.click(screen.getByTestId('quick-access-open'));

    expect(mockOpen).toHaveBeenCalledTimes(1);
  });
});
