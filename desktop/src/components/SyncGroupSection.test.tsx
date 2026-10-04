import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SyncGroupSection from './SyncGroupSection';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    syncGroupStatus: jest.fn(),
    syncGroupPairingCreate: jest.fn(),
    syncGroupPairingPoll: jest.fn(),
    syncGroupPairingCancel: jest.fn(),
    syncGroupJoinBegin: jest.fn(),
    syncGroupJoinConfirm: jest.fn(),
    syncGroupJoinCancel: jest.fn(),
  },
}));

const mockStatus = personaAPI.syncGroupStatus as jest.Mock;
const mockCreate = personaAPI.syncGroupPairingCreate as jest.Mock;
const mockPoll = personaAPI.syncGroupPairingPoll as jest.Mock;
const mockPairingCancel = personaAPI.syncGroupPairingCancel as jest.Mock;
const mockJoinBegin = personaAPI.syncGroupJoinBegin as jest.Mock;
const mockJoinConfirm = personaAPI.syncGroupJoinConfirm as jest.Mock;
const mockJoinCancel = personaAPI.syncGroupJoinCancel as jest.Mock;

const ok = <T,>(data: T) => ({ success: true, data });
const err = (message: string) => ({ success: false, error: message });

const inviteOutcome = {
  code: 'ABCD12EFG',
  invite_link: 'persona-pair-1.eyJjb2RlIjoiQUJDRDEyRUZHIn0',
  session_id: 'sess-1',
  expires_in_secs: 600,
};

describe('components/SyncGroupSection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('未入组时展示出码与输码两个入口', async () => {
    mockStatus.mockResolvedValue(ok(false));
    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    expect(mockStatus).toHaveBeenCalledTimes(1);
  });

  it('已入组时只展示组状态面，不再出现配对入口', async () => {
    mockStatus.mockResolvedValue(ok(true));
    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-joined')).toBeInTheDocument());
    expect(screen.queryByTestId('sync-group-idle')).not.toBeInTheDocument();
  });

  it('出码成功后展示动态密码与邀请串；poll 完成后展示指纹并刷新入组状态', async () => {
    // mount = 未入组，之后的刷新 = 已入组（host 侧完成时组密钥落 keyring）
    let statusCalls = 0;
    mockStatus.mockImplementation(async () => {
      statusCalls += 1;
      return statusCalls === 1 ? ok(false) : ok(true);
    });
    mockCreate.mockResolvedValue(ok(inviteOutcome));
    // poll 挂住：waiting 面稳定可见，断言 code/link 后手动完成
    let resolvePoll!: (v: unknown) => void;
    mockPoll.mockReturnValue(
      new Promise((resolve) => {
        resolvePoll = resolve;
      })
    );

    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.click(screen.getByText('本机出码（发起配对）'));

    await waitFor(() =>
      expect(screen.getByTestId('sync-group-host-code')).toHaveTextContent('ABCD12EFG')
    );
    expect(screen.getByTestId('sync-group-host-link')).toHaveTextContent(inviteOutcome.invite_link);
    expect(screen.getByTestId('sync-group-host-wait')).toBeInTheDocument();
    expect(mockPoll).toHaveBeenCalledWith('sess-1');

    resolvePoll(ok({ completed: true, fingerprint: '123456' }));
    await waitFor(() =>
      expect(screen.getByTestId('sync-group-host-fingerprint')).toHaveTextContent('123456')
    );
    // 完成面常驻（不被入组状态面顶掉）；点关闭后回组状态面
    expect(mockStatus).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByText('关闭'));
    await waitFor(() => expect(screen.getByTestId('sync-group-joined')).toBeInTheDocument());
  });

  it('poll 报错时展示错误与继续等待按钮；取消会话后回到空闲', async () => {
    mockStatus.mockResolvedValue(ok(false));
    mockCreate.mockResolvedValue(ok(inviteOutcome));
    mockPoll.mockResolvedValueOnce(err('配对等待超时（90s，请重试）'));

    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.click(screen.getByText('本机出码（发起配对）'));

    await waitFor(() => expect(screen.getByTestId('sync-group-host-error')).toBeInTheDocument());
    expect(mockPoll).toHaveBeenCalledWith('sess-1');

    mockPairingCancel.mockResolvedValue(ok(true));
    fireEvent.click(screen.getByText('取消配对'));
    await waitFor(() => expect(mockPairingCancel).toHaveBeenCalledWith('sess-1'));
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
  });

  it('guest 空邀请串不发起任何请求', async () => {
    mockStatus.mockResolvedValue(ok(false));
    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.click(screen.getByText('开始配对'));
    expect(mockJoinBegin).not.toHaveBeenCalled();
  });

  it('guest 全流程：输码拿到指纹，确认后入组并清空输入', async () => {
    // mount = 未入组，确认成功后的刷新 = 已入组
    let statusCalls = 0;
    mockStatus.mockImplementation(async () => {
      statusCalls += 1;
      return statusCalls === 1 ? ok(false) : ok(true);
    });
    mockJoinBegin.mockResolvedValue(
      ok({ fingerprint: '654321', code: 'ABCD12EFG', session_id: 'sess-1' })
    );
    mockJoinConfirm.mockResolvedValue(ok(true));

    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.change(screen.getByTestId('sync-group-guest-input'), {
      target: { value: 'persona-pair-1.eyJjb2RlIjoiQUJDRDEyRUZHIn0' },
    });
    fireEvent.click(screen.getByText('开始配对'));

    await waitFor(() =>
      expect(screen.getByTestId('sync-group-guest-fingerprint')).toHaveTextContent('654321')
    );
    expect(screen.getByTestId('sync-group-guest-confirm')).toHaveTextContent('ABCD12EFG');

    fireEvent.click(screen.getByText('指纹一致，确认入组'));
    await waitFor(() => expect(mockJoinConfirm).toHaveBeenCalledWith('sess-1'));
    // 入组完成后刷新状态切入组面，配对表单整体卸载
    await waitFor(() => expect(screen.getByTestId('sync-group-joined')).toBeInTheDocument());
    expect(screen.queryByTestId('sync-group-guest-confirm')).not.toBeInTheDocument();
  });

  it('guest confirm 失败时错误留在确认面上，会话可取消', async () => {
    mockStatus.mockResolvedValue(ok(false));
    mockJoinBegin.mockResolvedValue(
      ok({ fingerprint: '654321', code: 'ABCD12EFG', session_id: 'sess-1' })
    );
    mockJoinConfirm.mockResolvedValue(err('配对证明不匹配（动态密码不一致）'));

    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.change(screen.getByTestId('sync-group-guest-input'), {
      target: { value: 'persona-pair-1.eyJjb2RlIjoiQUJDRDEyRUZHIn0' },
    });
    fireEvent.click(screen.getByText('开始配对'));
    await waitFor(() => expect(screen.getByTestId('sync-group-guest-confirm')).toBeInTheDocument());

    fireEvent.click(screen.getByText('指纹一致，确认入组'));
    await waitFor(() =>
      expect(screen.getByTestId('sync-group-guest-confirm-error')).toHaveTextContent(
        '配对证明不匹配（动态密码不一致）'
      )
    );

    mockJoinCancel.mockResolvedValue(ok(true));
    fireEvent.click(screen.getByText('指纹不一致 / 取消'));
    await waitFor(() => expect(mockJoinCancel).toHaveBeenCalledWith('sess-1'));
    await waitFor(() =>
      expect(screen.queryByTestId('sync-group-guest-confirm')).not.toBeInTheDocument()
    );
  });

  it('guest begin 报错（如已入组）时错误展示在输入面上', async () => {
    mockStatus.mockResolvedValue(ok(false));
    mockJoinBegin.mockResolvedValue(err('This vault already joined a sync group'));

    render(<SyncGroupSection />);
    await waitFor(() => expect(screen.getByTestId('sync-group-idle')).toBeInTheDocument());
    fireEvent.change(screen.getByTestId('sync-group-guest-input'), {
      target: { value: 'persona-pair-1.eyJjb2RlIjoiQUJDRDEyRUZHIn0' },
    });
    fireEvent.click(screen.getByText('开始配对'));
    await waitFor(() =>
      expect(screen.getByTestId('sync-group-guest-error')).toHaveTextContent(
        'This vault already joined a sync group'
      )
    );
  });
});
