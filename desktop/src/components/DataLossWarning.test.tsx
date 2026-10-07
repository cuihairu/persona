import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import DataLossWarning from './DataLossWarning';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    syncGroupStatus: jest.fn(),
    syncListDevices: jest.fn(),
    getWorkspaceSettings: jest.fn(),
  },
}));

const mockStatus = personaAPI.syncGroupStatus as jest.Mock;
const mockDevices = personaAPI.syncListDevices as jest.Mock;
const mockSettings = personaAPI.getWorkspaceSettings as jest.Mock;

/** 三路状态源按档位编排：high=单设备无备份无账号；medium=有账号。 */
function mockSources(level: 'high' | 'medium' | 'none', failure = false): void {
  if (failure) {
    mockStatus.mockRejectedValue(new Error('backend down'));
    mockDevices.mockRejectedValue(new Error('backend down'));
    mockSettings.mockRejectedValue(new Error('backend down'));
    return;
  }
  const joined = level !== 'none';
  mockStatus.mockResolvedValue({ success: joined, data: joined ? true : null });
  mockDevices.mockResolvedValue({
    success: true,
    data: joined ? [{ id: 'only-device' }] : [],
  });
  const settings =
    level === 'medium' ? { backup: null, account: { id: 'acc' } } : { backup: null, account: null };
  mockSettings.mockResolvedValue({ success: true, data: settings });
}

beforeEach(() => {
  jest.clearAllMocks();
  // jsdom 没有 scrollIntoView；自救动作验证「滚到正确的节」——
  // 组件按 data-testid 全局查询目标节，测试树里植入替身
  Element.prototype.scrollIntoView = jest.fn();
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('components/DataLossWarning', () => {
  it('renders nothing while loading or when risk level is none', async () => {
    mockSources('none');
    const { container } = render(<DataLossWarning />);
    await waitFor(() => {
      expect(mockSettings).toHaveBeenCalled();
    });
    expect(screen.queryByTestId('data-loss-banner')).not.toBeInTheDocument();
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when every status source fails (fail-safe)', async () => {
    mockSources('high', true);
    const { container } = render(<DataLossWarning />);
    await waitFor(() => {
      expect(mockStatus).toHaveBeenCalled();
    });
    expect(container.firstChild).toBeNull();
  });

  it('banner high: alert role and single-device copy', async () => {
    mockSources('high');
    render(<DataLossWarning />);

    const banner = await screen.findByTestId('data-loss-banner');
    expect(banner).toHaveAttribute('role', 'alert');
    expect(screen.getByTestId('data-loss-banner-text')).toHaveTextContent('数据风险——仅一台设备');
  });

  it('banner medium: status role and account-bound copy', async () => {
    mockSources('medium');
    render(<DataLossWarning />);

    const banner = await screen.findByTestId('data-loss-banner');
    expect(banner).toHaveAttribute('role', 'status');
    expect(screen.getByTestId('data-loss-banner-text')).toHaveTextContent('数据风险——单台设备');
  });

  it('banner action scrolls to the backup section', async () => {
    const target = document.createElement('div');
    target.setAttribute('data-testid', 'backup-section');
    document.body.appendChild(target);
    const scroll = jest.fn();
    target.scrollIntoView = scroll;

    mockSources('high');
    render(<DataLossWarning />);
    fireEvent.click(await screen.findByTestId('data-loss-banner-action'));

    expect(scroll).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
  });

  it('strong high: strong copy with both rescue actions', async () => {
    mockSources('high');
    render(<DataLossWarning variant="strong" />);

    const box = await screen.findByTestId('data-loss-strong');
    expect(box).toHaveAttribute('role', 'alert');
    expect(screen.getByTestId('data-loss-strong-title')).toHaveTextContent('数据处于风险');
    expect(screen.getByTestId('data-loss-strong-body')).toHaveTextContent(
      '丢失该设备意味着丢失整个保险库',
    );
    expect(screen.getByTestId('data-loss-backup-action')).toHaveTextContent('导出加密备份');
    expect(screen.getByTestId('data-loss-device-action')).toHaveTextContent('添加另一台设备');
  });

  it('strong medium: downgraded body copy and status role', async () => {
    mockSources('medium');
    render(<DataLossWarning variant="strong" />);

    const box = await screen.findByTestId('data-loss-strong');
    expect(box).toHaveAttribute('role', 'status');
    expect(screen.getByTestId('data-loss-strong-body')).toHaveTextContent(
      '除非有其他设备或备份，否则将丢失保险库',
    );
  });

  it('strong device action scrolls to the sync devices section', async () => {
    const target = document.createElement('div');
    target.setAttribute('data-testid', 'sync-devices-section');
    document.body.appendChild(target);
    const scroll = jest.fn();
    target.scrollIntoView = scroll;

    mockSources('high');
    render(<DataLossWarning variant="strong" />);
    fireEvent.click(await screen.findByTestId('data-loss-device-action'));

    expect(scroll).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
  });

  it('strong backup action scrolls to the backup section', async () => {
    const target = document.createElement('div');
    target.setAttribute('data-testid', 'backup-section');
    document.body.appendChild(target);
    const scroll = jest.fn();
    target.scrollIntoView = scroll;

    mockSources('high');
    render(<DataLossWarning variant="strong" />);
    fireEvent.click(await screen.findByTestId('data-loss-backup-action'));

    expect(scroll).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
  });
});
