import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import SshIntegrationSection from './SshIntegrationSection';
import { personaAPI } from '@/utils/api';
import toast from 'react-hot-toast';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    sshAgentIntegrationStatus: jest.fn(),
    sshAgentIntegrationEnable: jest.fn(),
    sshAgentIntegrationDisable: jest.fn(),
    sshAgentConfigAnalysis: jest.fn(),
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
  configExists: true,
  readError: null,
  ...over,
});

const analysisOf = (over: Record<string, unknown> = {}) => ({
  configPath: '/home/user/.ssh/config',
  configExists: true,
  readable: true,
  readError: null,
  warnings: [],
  entries: [],
  forwardAgentEntries: [],
  identityAgentEffective: null,
  sshAuthSock: null,
  effectiveSocket: null,
  socketAlive: null,
  personaSocketAlive: false,
  ...over,
});

const mockStatus = personaAPI.sshAgentIntegrationStatus as jest.Mock;
const mockEnable = personaAPI.sshAgentIntegrationEnable as jest.Mock;
const mockDisable = personaAPI.sshAgentIntegrationDisable as jest.Mock;
const mockAnalysis = personaAPI.sshAgentConfigAnalysis as jest.Mock;

describe('components/SshIntegrationSection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // 默认分析查询失败 → 面板隐藏（只影响状态行，不影响既有断言）
    mockAnalysis.mockResolvedValue({ success: false, data: null });
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
    // Host * 作用域行与后端锚点块同构（缺它块会落入最后一个 Host 块作用域）
    expect(snippet).toHaveTextContent('Host *');
    expect(snippet).toHaveTextContent(
      'IdentityAgent /run/user/1000/persona/ssh-agent.sock',
    );
    expect(snippet).toHaveTextContent('# persona managed end');
  });

  it('renders the config analysis panel with entries and socket liveness', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });
    mockAnalysis.mockResolvedValue({
      success: true,
      data: analysisOf({
        sshAuthSock: '/env/sock',
        identityAgentEffective: '/run/user/1000/persona/ssh-agent.sock',
        effectiveSocket: '/run/user/1000/persona/ssh-agent.sock',
        socketAlive: true,
        personaSocketAlive: true,
        entries: [
          {
            file: '/home/user/.ssh/config',
            line: 4,
            scope: 'Host github.com',
            keyword: 'ForwardAgent',
            value: 'no',
          },
          {
            file: '/home/user/.ssh/conf.d/extra.conf',
            line: 1,
            scope: '',
            keyword: 'IdentityAgent',
            value: '/run/user/1000/persona/ssh-agent.sock',
          },
        ],
        forwardAgentEntries: [
          {
            file: '/home/user/.ssh/config',
            line: 4,
            scope: 'Host github.com',
            keyword: 'ForwardAgent',
            value: 'no',
          },
        ],
      }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-analysis-panel')).toBeInTheDocument());
    // 环境变量与生效值（读出来的真状态）
    expect(getByTestId('ssh-analysis-sock-env')).toHaveTextContent('/env/sock');
    expect(getByTestId('ssh-analysis-effective-agent')).toHaveTextContent(
      '/run/user/1000/persona/ssh-agent.sock',
    );
    // socket 存活灯 = 探测结果（绿/运行中）
    expect(getByTestId('ssh-analysis-alive')).toHaveClass('bg-green-500');
    expect(getByTestId('ssh-analysis-persona-alive')).toHaveClass('bg-green-500');
    expect(getByTestId('ssh-analysis-panel')).toHaveTextContent('运行中');
    // 条目列表：作用域行 + 文件:行号（Include 展开也进列表）
    const entries = getByTestId('ssh-analysis-entries');
    expect(entries).toHaveTextContent('Host github.com → ForwardAgent no');
    expect(entries).toHaveTextContent('/home/user/.ssh/config:4');
    expect(entries).toHaveTextContent('conf.d/extra.conf:1');
  });

  it('shows unreadable config and warnings honestly instead of hiding them', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });
    mockAnalysis.mockResolvedValue({
      success: true,
      data: analysisOf({
        readable: false,
        readError: 'Permission denied (os error 13)',
        warnings: ['Include 无匹配文件：conf.d/*.conf'],
        socketAlive: false,
      }),
    });

    const { getByTestId, queryByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-analysis-read-error')).toBeInTheDocument());
    expect(getByTestId('ssh-analysis-read-error')).toHaveTextContent(
      'Permission denied (os error 13)',
    );
    expect(getByTestId('ssh-analysis-warnings')).toHaveTextContent(
      'Include 无匹配文件：conf.d/*.conf',
    );
    // 无人监听：红点 + 文案
    expect(getByTestId('ssh-analysis-alive')).toHaveClass('bg-red-500');
    expect(getByTestId('ssh-analysis-panel')).toHaveTextContent('无人监听');
    // 读不出条目 ≠ 空列表渲染
    expect(queryByTestId('ssh-analysis-entries')).toBeNull();
  });

  it('hides only the analysis panel when the analysis query fails', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });
    mockAnalysis.mockRejectedValue(new Error('invoke failed'));

    const { getByTestId, queryByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-badge')).toBeInTheDocument());
    expect(queryByTestId('ssh-analysis-panel')).toBeNull();
  });

  it('renders the detected OpenSSH version with a compatibility verdict', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: statusOf({ sshVersion: 'OpenSSH_10.2p1' }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-version')).toBeInTheDocument());
    expect(getByTestId('ssh-integration-version')).toHaveTextContent('OpenSSH_10.2p1');
    expect(getByTestId('ssh-integration-version-verdict')).toHaveTextContent('支持 IdentityAgent');
    expect(getByTestId('ssh-integration-version-verdict')).toHaveClass('text-green-600');
  });

  it('flags an OpenSSH version too old for IdentityAgent', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: statusOf({ sshVersion: 'OpenSSH_8.2p1' }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() =>
      expect(getByTestId('ssh-integration-version-verdict')).toBeInTheDocument(),
    );
    expect(getByTestId('ssh-integration-version-verdict')).toHaveTextContent('版本过旧');
    expect(getByTestId('ssh-integration-version-verdict')).toHaveClass('text-red-600');
  });

  it('shows "not detected" honestly when the OpenSSH probe returns nothing', async () => {
    mockStatus.mockResolvedValue({
      success: true,
      data: statusOf({ sshVersion: null }),
    });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-integration-version')).toBeInTheDocument());
    expect(getByTestId('ssh-integration-version')).toHaveTextContent('未探测到');
    // 无法判定 ≠ 通过：既不绿也不红
    expect(getByTestId('ssh-integration-version-verdict')).toHaveTextContent('需 8.3+');
    expect(getByTestId('ssh-integration-version-verdict')).toHaveClass('text-gray-400');
  });

  it('manual refresh re-reads both status and analysis', async () => {
    mockStatus.mockResolvedValue({ success: true, data: statusOf() });
    mockAnalysis.mockResolvedValue({ success: true, data: analysisOf() });

    const { getByTestId } = render(<SshIntegrationSection />);
    await waitFor(() => expect(getByTestId('ssh-analysis-refresh')).toBeInTheDocument());
    const statusCallsBefore = mockStatus.mock.calls.length;
    const analysisCallsBefore = mockAnalysis.mock.calls.length;

    // 外部改了 config：重读后拉到的分析是新值
    mockAnalysis.mockResolvedValue({
      success: true,
      data: analysisOf({ identityAgentEffective: '/fresh/sock', socketAlive: true }),
    });
    fireEvent.click(getByTestId('ssh-analysis-refresh'));

    await waitFor(() =>
      expect(mockStatus.mock.calls.length).toBeGreaterThan(statusCallsBefore),
    );
    await waitFor(() =>
      expect(mockAnalysis.mock.calls.length).toBeGreaterThan(analysisCallsBefore),
    );
    await waitFor(() =>
      expect(getByTestId('ssh-analysis-effective-agent')).toHaveTextContent('/fresh/sock'),
    );
  });
});
