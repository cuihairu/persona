import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SyncConflictsModal from './SyncConflictsModal';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    syncConflictsList: jest.fn(),
    syncConflictResolve: jest.fn(),
  },
}));

const mockList = personaAPI.syncConflictsList as jest.Mock;
const mockResolve = personaAPI.syncConflictResolve as jest.Mock;

const snapshot = (name: string, password: string) => ({
  identity_id: 'id-1',
  name,
  credential_type: 'Password',
  security_level: 'High',
  url: 'https://github.com',
  username: 'alice',
  notes: null,
  tags: [],
  metadata: {},
  is_favorite: false,
  is_active: true,
  data: { credential_type: 'Password', data: { password } },
});

const conflictedEntry = {
  item_id: 'item-1',
  primary: {
    op_id: 'op-p',
    device_id: 'dev-a',
    lamport: 5,
    timestamp: '2026-09-23T00:00:00Z',
    deleted: false,
    snapshot: snapshot('GitHub', 'secret-a'),
  },
  copies: [
    {
      op_id: 'op-c',
      device_id: 'dev-b',
      lamport: 5,
      timestamp: '2026-09-23T01:00:00Z',
      deleted: false,
      snapshot: snapshot('GitHub (renamed)', 'secret-b'),
    },
  ],
};

describe('components/SyncConflictsModal', () => {
  const onClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockList.mockResolvedValue({ success: true, data: [conflictedEntry] });
  });

  const renderModal = () => render(<SyncConflictsModal onClose={onClose} />);

  it('shows primary and copy side by side with badges and adopt action', async () => {
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-entry-item-1')).toBeInTheDocument();
    });
    // 主位标记当前版本；副本 data 不同 → 内容不同徽标
    expect(screen.getAllByTestId('sync-conflict-badge')).toHaveLength(2);
    expect(screen.getAllByTestId('sync-conflict-badge')[0]).toHaveTextContent('当前版本');
    expect(screen.getAllByTestId('sync-conflict-badge')[1]).toHaveTextContent('内容不同');
    // 副本名称与版本元数据可见
    expect(screen.getByText('GitHub (renamed)')).toBeInTheDocument();
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    // 采纳按钮指向副本 op_id
    expect(screen.getByTestId('sync-conflict-adopt-op-c')).toBeEnabled();
  });

  it('marks a tombstone copy as deleted and offers adoption for it', async () => {
    mockList.mockResolvedValue({
      success: true,
      data: [
        {
          ...conflictedEntry,
          copies: [
            {
              op_id: 'op-del',
              device_id: 'dev-b',
              lamport: 5,
              timestamp: null,
              deleted: true,
              snapshot: null,
            },
          ],
        },
      ],
    });
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-version-op-del')).toBeInTheDocument();
    });
    expect(screen.getByText('（已删除）')).toBeInTheDocument();
    // badge 有两枚（主位「当前版本」+ 副本「删除操作」）
    const badges = screen.getAllByTestId('sync-conflict-badge');
    expect(badges).toHaveLength(2);
    expect(badges[1]).toHaveTextContent('删除操作');
    expect(screen.getByTestId('sync-conflict-adopt-op-del')).toBeEnabled();
  });

  it('adopts a copy with item id + op id and refreshes the list', async () => {
    mockResolve.mockResolvedValue({ success: true, data: true });
    // 采纳后重拉：列表清空 → 自动关窗
    mockList
      .mockResolvedValueOnce({ success: true, data: [conflictedEntry] })
      .mockResolvedValueOnce({ success: true, data: [] });
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-adopt-op-c')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('sync-conflict-adopt-op-c'));

    await waitFor(() => {
      expect(mockResolve).toHaveBeenCalledWith('item-1', 'op-c');
    });
    // 裁决清空后自动关窗（无冲突可裁决）
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
    expect(mockList).toHaveBeenCalledTimes(2);
  });

  it('keeps the list when resolution fails and surfaces the error toast', async () => {
    mockResolve.mockResolvedValue({ success: false, error: 'Failed to resolve conflict' });
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-adopt-op-c')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('sync-conflict-adopt-op-c'));

    await waitFor(() => {
      expect(mockResolve).toHaveBeenCalledWith('item-1', 'op-c');
    });
    // 失败不刷新不关窗：列表仍在（加载只发生一次）
    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-entry-item-1')).toBeInTheDocument();
    });
    expect(mockList).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('auto-closes when there is nothing to resolve', async () => {
    mockList.mockResolvedValue({ success: true, data: [] });
    renderModal();

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('shows the load failure message and keeps the modal open', async () => {
    mockList.mockResolvedValue({ success: false, error: 'boom' });
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflicts-error')).toHaveTextContent('冲突列表加载失败');
    });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('handles a thrown list load as a failure and keeps the modal open', async () => {
    mockList.mockRejectedValue(new Error('network down'));
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflicts-error')).toHaveTextContent('冲突列表加载失败');
    });
    // 异常路径不自动关窗
    expect(onClose).not.toHaveBeenCalled();
  });

  it('keeps the list when resolution throws and surfaces the failure', async () => {
    mockResolve.mockRejectedValue(new Error('invoke crashed'));
    renderModal();

    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-adopt-op-c')).toBeEnabled();
    });
    fireEvent.click(screen.getByTestId('sync-conflict-adopt-op-c'));

    await waitFor(() => {
      expect(mockResolve).toHaveBeenCalledWith('item-1', 'op-c');
    });
    // 抛异常同样不刷新不关窗
    await waitFor(() => {
      expect(screen.getByTestId('sync-conflict-entry-item-1')).toBeInTheDocument();
    });
    expect(mockList).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
  });
});
