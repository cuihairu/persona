import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import UpdateCheckSection from './UpdateCheckSection';
import type { UpdateCheckResult } from '@/utils/updateCheck';

jest.mock('@/utils/updateCheck', () => ({
  ...jest.requireActual('@/utils/updateCheck'),
  checkForUpdate: jest.fn(),
  getBuildMeta: jest.fn(),
  isUpdateCheckEnabled: jest.fn(),
  setUpdateCheckEnabled: jest.fn(),
  getLastCheckedAt: jest.fn(),
  setLastCheckedAt: jest.fn(),
}));

jest.mock('@/utils/clipboard', () => ({
  copyToClipboardWithToast: jest.fn(),
}));

const mockCheck = jest.requireMock('@/utils/updateCheck').checkForUpdate as jest.Mock;
const mockGetMeta = jest.requireMock('@/utils/updateCheck').getBuildMeta as jest.Mock;
const mockIsEnabled = jest.requireMock('@/utils/updateCheck').isUpdateCheckEnabled as jest.Mock;
const mockSetEnabled = jest.requireMock('@/utils/updateCheck').setUpdateCheckEnabled as jest.Mock;
const mockGetLast = jest.requireMock('@/utils/updateCheck').getLastCheckedAt as jest.Mock;
const mockSetLast = jest.requireMock('@/utils/updateCheck').setLastCheckedAt as jest.Mock;
const mockCopy = jest.requireMock('@/utils/clipboard').copyToClipboardWithToast as jest.Mock;

const nightlyMeta = { channel: 'nightly' as const, sha: 'abc', builtAt: '2026-09-26T00:00:00Z' };

const result = (overrides: Partial<UpdateCheckResult>): UpdateCheckResult => ({
  status: 'up-to-date',
  channel: 'nightly',
  currentVersion: '0.1.0',
  latestVersion: 'abc1234',
  detailUrl: null,
  ...overrides,
});

beforeEach(() => {
  jest.clearAllMocks();
  mockGetMeta.mockReturnValue(nightlyMeta);
  mockIsEnabled.mockReturnValue(true);
  mockGetLast.mockReturnValue(null);
});

describe('components/UpdateCheckSection', () => {
  it('shows the build channel and an enabled switch by default', () => {
    render(<UpdateCheckSection />);

    expect(screen.getByTestId('update-check-channel')).toHaveTextContent('每日构建');
    expect(screen.getByTestId('update-check-toggle')).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByText('尚未检查')).toBeInTheDocument();
  });

  it('toggling off persists the opt-out', () => {
    render(<UpdateCheckSection />);

    fireEvent.click(screen.getByTestId('update-check-toggle'));

    expect(mockSetEnabled).toHaveBeenCalledWith(false);
  });

  it('a manual check renders the update-available status and copies the link', async () => {
    mockCheck.mockResolvedValue(
      result({
        status: 'update-available',
        latestVersion: 'def5678',
        detailUrl: 'https://github.com/cuihairu/persona/actions/runs/99',
      }),
    );
    render(<UpdateCheckSection />);

    fireEvent.click(screen.getByTestId('update-check-button'));

    await waitFor(() => {
      expect(screen.getByTestId('update-check-status')).toHaveTextContent('def5678');
    });
    expect(mockCheck).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId('update-check-copy-link'));
    expect(mockCopy).toHaveBeenCalledWith(
      'https://github.com/cuihairu/persona/actions/runs/99',
      '复制链接',
    );
    expect(mockSetLast).toHaveBeenCalled();
  });

  it('an unavailable outcome renders the mapped reason', async () => {
    mockCheck.mockResolvedValue(
      result({ status: 'unavailable', latestVersion: null, reason: 'no-release' }),
    );
    render(<UpdateCheckSection />);

    fireEvent.click(screen.getByTestId('update-check-button'));

    await waitFor(() => {
      expect(screen.getByTestId('update-check-status')).toHaveTextContent('该渠道还没有可用的发布');
    });
    expect(screen.queryByTestId('update-check-copy-link')).not.toBeInTheDocument();
  });

  it('dev builds show the development channel label and check short-circuits', async () => {
    mockGetMeta.mockReturnValue({ channel: 'dev', sha: '', builtAt: '' });
    mockCheck.mockResolvedValue(
      result({ channel: 'dev', status: 'unavailable', latestVersion: null, reason: 'dev-channel' }),
    );
    render(<UpdateCheckSection />);

    expect(screen.getByTestId('update-check-channel')).toHaveTextContent('开发构建');

    fireEvent.click(screen.getByTestId('update-check-button'));

    await waitFor(() => {
      expect(screen.getByTestId('update-check-status')).toHaveTextContent('开发构建不参与版本比对');
    });
  });
});
