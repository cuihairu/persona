import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import SshIntegrationSection from './SshIntegrationSection';
import { personaAPI } from '@/utils/api';
import toast from 'react-hot-toast';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    sshAgentIntegrationStatus: jest.fn(),
    sshAgentIntegrationEnable: jest.fn(),
    sshAgentIntegrationDisable: jest.fn(),
  },
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

const statusOf = (over: Record<string, unknown> = {}) => ({
  enabled: false,
  anomaly: null,
  manualEntry: false,
  configPath: '/home/user/.ssh/config',
  socketPath: '/run/user/1000/persona/ssh-agent.sock',
  identityAgent: null,
  sshVersion: null,
  ...over,
});

const mockStatus = personaAPI.sshAgentIntegrationStatus as jest.Mock;
const mockEnable = personaAPI.sshAgentIntegrationEnable as jest.Mock;
const mockDisable = personaAPI.sshAgentIntegrationDisable as jest.Mock;

describe('components/SshIntegrationSection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders disabled state with enable button (status query failed hides section)', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });

    const { getByTestId, queryByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-badge')).toBeInTheDocument());
    expect(getByTestId('ssh-integration-badge')).toHaveTextContent('未启用');
    expect(getByTestId('ssh-integration-toggle')).toHaveTextContent('一键启用');
    expect(getByTestId('ssh-integration-socket')).toHaveTextContent(
      '/run/user/1000/persona/ssh-agent.sock',
    );

    expect(queryByTestId('ssh-integration-section')).toBeInTheDocument();

    // 查询失败：整区隐藏不谎报未启用（卸载旧实例后重渲染失败态）
    cleanup();
    mockStatus.mockResolvedValue({ success: false, data: null });
    const failed = render(<SshIntegrationSection />);
    await Promise.resolve();
    await Promise.resolve();
    expect(failed.queryByTestId('ssh-integration-section')).toBeNull();
  });

  it('enables idempotently and flips to enabled badge', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });
    mockEnable.mockResolvedValue({
      success: true,
      data: statusOf({ enabled: true, identityAgent: '/run/user/1000/persona/ssh-agent.sock' }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-toggle')).toBeInTheDocument());
    fireEvent.click(getByTestId('ssh-integration-toggle'));

    await waitFor(() => expect(mockEnable).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(getByTestId('ssh-integration-badge')).toHaveTextContent('已启用'));
    // 启用后按钮变成「一键停用」（状态联动）
    expect(getByTestId('ssh-integration-toggle')).toHaveTextContent('一键停用');
    expect(toast.success).toHaveBeenCalled();

    // 再点 = 停用链路
    mockDisable.mockResolvedValue({ success: true, data: statusOf() });
    fireEvent.click(getByTestId('ssh-integration-toggle'));
    await waitFor(() => expect(mockDisable).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(getByTestId('ssh-integration-badge')).toHaveTextContent('未启用'));
  });

  it('shows anomaly with the found value and re-enable hint', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: statusOf({
        anomaly: '/tmp/persona-ssh-agent-99.sock',
        identityAgent: '/tmp/persona-ssh-agent-99.sock',
      }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-anomaly')).toBeInTheDocument());
    expect(getByTestId('ssh-integration-badge')).toHaveTextContent('配置异常');
    expect(getByTestId('ssh-integration-anomaly')).toHaveTextContent(
      '/tmp/persona-ssh-agent-99.sock',
    );
    // 异常态仍提供一键启用（= 修复路径）
    expect(getByTestId('ssh-integration-toggle')).toHaveTextContent('一键启用');
  });

  it('reveals the manual snippet with the current socket path', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-manual-toggle')).toBeInTheDocument());
    fireEvent.click(getByTestId('ssh-integration-manual-toggle'));

    const snippet = getByTestId('ssh-integration-snippet');
    expect(snippet).toHaveTextContent('# persona managed begin');
    expect(snippet).toHaveTextContent(
      'IdentityAgent /run/user/1000/persona/ssh-agent.sock',
    );
    expect(snippet).toHaveTextContent('# persona managed end');
  });
});
