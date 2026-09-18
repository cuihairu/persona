import { fireEvent, render, screen } from '@testing-library/react';
import Sidebar from './Sidebar';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';

jest.mock('@/components/IdentitySwitcher', () => ({
  __esModule: true,
  IdentitySwitcher: (props: { onCreateIdentity: () => void }) => (
    <div data-testid="identity-switcher" onClick={props.onCreateIdentity} />
  ),
}));

const ALL_FLAGS_ON = { ssh_agent: true, wallet: true, passkeys: true };

type SidebarProps = Parameters<typeof Sidebar>[0];

const renderSidebar = (overrides: Partial<SidebarProps> = {}) => {
  const props: SidebarProps = {
    currentView: 'credentials',
    onNavigate: jest.fn(),
    onCreateIdentity: jest.fn(),
    onOpenSettings: jest.fn(),
    onLock: jest.fn(),
    ...overrides,
  };
  render(<Sidebar {...props} />);
  return props;
};

describe('components/Sidebar', () => {
  beforeEach(() => {
    useAppStore.setState({ featureFlags: { ...DEFAULT_FEATURE_FLAGS } });
  });

  it('renders always-on nav entries and hides flag-gated ones while flags are off', () => {
    renderSidebar();

    expect(screen.getByRole('button', { name: 'Credentials' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Statistics' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Watchtower' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'SSH Agent' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wallets' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Passkeys' })).not.toBeInTheDocument();
  });

  it('shows gated nav entries once their flags are on', () => {
    useAppStore.setState({ featureFlags: ALL_FLAGS_ON });
    renderSidebar();

    expect(screen.getByTestId('nav-credentials')).toBeInTheDocument();
    expect(screen.getByTestId('nav-statistics')).toBeInTheDocument();
    expect(screen.getByTestId('nav-sshAgent')).toBeInTheDocument();
    expect(screen.getByTestId('nav-wallets')).toBeInTheDocument();
    expect(screen.getByTestId('nav-watchtower')).toBeInTheDocument();
    expect(screen.getByTestId('nav-passkeys')).toBeInTheDocument();
  });

  it('marks the active view and reports navigation clicks', () => {
    const { onNavigate } = renderSidebar({ currentView: 'credentials' });

    expect(screen.getByTestId('nav-credentials')).toHaveAttribute('aria-current', 'page');
    expect(screen.getByTestId('nav-statistics')).not.toHaveAttribute('aria-current');

    fireEvent.click(screen.getByRole('button', { name: 'Statistics' }));
    expect(onNavigate).toHaveBeenCalledWith('statistics');
  });

  it('wires the identity switcher create action', () => {
    const { onCreateIdentity } = renderSidebar();

    fireEvent.click(screen.getByTestId('identity-switcher'));
    expect(onCreateIdentity).toHaveBeenCalledTimes(1);
  });

  it('calls settings and lock from the footer', () => {
    const { onOpenSettings, onLock } = renderSidebar();

    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    fireEvent.click(screen.getByRole('button', { name: 'Lock session' }));
    expect(onOpenSettings).toHaveBeenCalledTimes(1);
    expect(onLock).toHaveBeenCalledTimes(1);
  });
});
