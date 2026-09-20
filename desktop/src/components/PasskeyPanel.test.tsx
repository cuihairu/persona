import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import PasskeyPanel from './PasskeyPanel';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import toast from 'react-hot-toast';
import type { Identity, Passkey } from '@/types';

const mockIdentities: Identity[] = [
  { id: 'id-1', name: 'Personal', identity_type: 'Personal', tags: [], created_at: '', updated_at: '', is_active: true },
  { id: 'id-2', name: 'Work', identity_type: 'Work', tags: [], created_at: '', updated_at: '', is_active: true },
];
/** 个别用例（空身份短路）需要替换；beforeEach 恢复默认 */
let identitiesFixture: Identity[] = mockIdentities;

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: () => ({ identities: identitiesFixture }),
}));

// reauth 弹窗由 useReauth 驱动；这里 mock 掉以聚焦面板自身的
// REAUTH_REQUIRED → requestReauth → 重试一次 编排（ReauthModal 交互属既有组件）
const mockRequestReauth = jest.fn();
jest.mock('@/hooks/useReauth', () => ({
  useReauth: () => ({
    isOpen: false,
    error: null,
    isVerifying: false,
    requestReauth: (...args: unknown[]) => mockRequestReauth(...args),
    submit: jest.fn(),
    cancel: jest.fn(),
  }),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    passkeyList: jest.fn(),
    passkeySelfTest: jest.fn(),
    passkeyExportPrivateKey: jest.fn(),
    passkeyDelete: jest.fn(),
    reauthVerify: jest.fn(),
  },
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

/** credential_id_b64 'YWJjZA==' = "abcd" → hex 61626364 */
const mkPasskey = (over: Partial<Passkey> = {}): Passkey => ({
  id: 'pk-1',
  identity_id: 'id-1',
  rp_id: 'github.com',
  rp_name: undefined,
  user_handle_b64: 'dXNlcg==',
  user_name: 'alice',
  user_display_name: undefined,
  credential_id_b64: 'YWJjZA==',
  uv_initialized: true,
  export_allowed: true,
  created_at: '2026-01-15T10:30:00Z',
  last_used_at: undefined,
  ...over,
});

const mockList = personaAPI.passkeyList as jest.Mock;
const mockSelfTest = personaAPI.passkeySelfTest as jest.Mock;
const mockExport = personaAPI.passkeyExportPrivateKey as jest.Mock;
const mockDelete = personaAPI.passkeyDelete as jest.Mock;

const openDetail = async () => {
  await waitFor(() => expect(screen.getByTestId('passkey-row-pk-1')).toBeInTheDocument());
  fireEvent.click(screen.getByTestId('passkey-row-pk-1'));
  await waitFor(() => expect(screen.getByTestId('passkey-detail-modal')).toBeInTheDocument());
};

describe('components/PasskeyPanel', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    identitiesFixture = mockIdentities;
    mockList.mockResolvedValue({ success: true, data: [] });
  });

  it('merges passkeys from all identities on mount', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data:
        identityId === 'id-1'
          ? [mkPasskey()]
          : [mkPasskey({ id: 'pk-2', identity_id: 'id-2', rp_id: 'gitlab.com', user_name: 'bob' })],
    }));

    render(<PasskeyPanel />);

    await waitFor(() => expect(screen.getByTestId('passkey-row-pk-1')).toBeInTheDocument());
    expect(screen.getByTestId('passkey-row-pk-2')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('id-1');
    expect(mockList).toHaveBeenCalledWith('id-2');
  });

  it('shows the empty state when no identities have passkeys', async () => {
    render(<PasskeyPanel />);

    await waitFor(() => expect(screen.getByTestId('passkey-empty')).toBeInTheDocument());
    expect(screen.queryByTestId('passkey-error')).toBeNull();
  });

  it('shows an error banner when listing fails', async () => {
    mockList.mockResolvedValue({ success: false, error: 'Service is locked' });

    render(<PasskeyPanel />);

    await waitFor(() => expect(screen.getByTestId('passkey-error')).toHaveTextContent('Service is locked'));
  });

  it('opens the detail modal with full fields on row click', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    render(<PasskeyPanel />);
    await openDetail();

    expect(screen.getByTestId('passkey-detail-rp')).toHaveTextContent('github.com');
    expect(screen.getByTestId('passkey-detail-user')).toHaveTextContent('alice');
    // b64 "abcd" → hex 61626364（与 CLI show 的展示格式一致）
    expect(screen.getByTestId('passkey-detail-credential-id')).toHaveTextContent('61626364');
    const modal = screen.getByTestId('passkey-detail-modal');
    expect(within(modal).getByText('Personal')).toBeInTheDocument();
  });

  it('runs a self-test and reports success', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockSelfTest.mockResolvedValue({ success: true, data: true });
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-selftest-button'));

    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent('自检通过'),
    );
    expect(mockSelfTest).toHaveBeenCalledWith('pk-1');
  });

  it('retries the self-test once after re-authentication succeeds', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockSelfTest
      .mockResolvedValueOnce({ success: false, error: 'reauth', error_code: 'REAUTH_REQUIRED' })
      .mockResolvedValue({ success: true, data: true });
    mockRequestReauth.mockResolvedValue(true);
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-selftest-button'));

    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent('自检通过'),
    );
    expect(mockSelfTest).toHaveBeenCalledTimes(2);
    expect(mockRequestReauth).toHaveBeenCalledTimes(1);
  });

  it('does not retry the self-test when re-authentication is cancelled', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockSelfTest.mockResolvedValue({
      success: false,
      error: 'reauth',
      error_code: 'REAUTH_REQUIRED',
    });
    mockRequestReauth.mockResolvedValue(false);
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-selftest-button'));

    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent(
        '需要重新认证',
      ),
    );
    expect(mockSelfTest).toHaveBeenCalledTimes(1);
  });

  it('disables export when export_allowed is false', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey({ export_allowed: false })] : [],
    }));
    render(<PasskeyPanel />);
    await openDetail();

    expect(screen.getByTestId('passkey-export-button')).toBeDisabled();
    expect(screen.getByText('该通行密钥已禁用导出。')).toBeInTheDocument();
  });

  it('exports the private key as hex (matching CLI export format)', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    // base64 'AAAAAQ==' → bytes 00 00 00 01 → hex 00000001
    mockExport.mockResolvedValue({ success: true, data: 'AAAAAQ==' });
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-export-button'));

    await waitFor(() =>
      expect(screen.getByTestId('passkey-export-value')).toHaveTextContent('00000001'),
    );
    expect(mockExport).toHaveBeenCalledWith('pk-1');
  });

  it('shows the backend message when export is refused', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockExport.mockResolvedValue({
      success: false,
      error: 'Passkey export is disabled for this credential',
    });
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-export-button'));

    await waitFor(() =>
      expect(screen.getByTestId('passkey-export-error')).toHaveTextContent(
        'Passkey export is disabled for this credential',
      ),
    );
  });

  it('deletes after confirmation and refreshes the list', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockDelete.mockResolvedValue({ success: true, data: true });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-delete-button'));

    await waitFor(() =>
      expect(screen.queryByTestId('passkey-detail-modal')).toBeNull(),
    );
    expect(mockDelete).toHaveBeenCalledWith('pk-1');
    // 刷新：列表再次加载
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(4));
    confirmSpy.mockRestore();
  });

  it('skips loading entirely when no identities exist', async () => {
    identitiesFixture = [];
    render(<PasskeyPanel />);

    await waitFor(() => expect(screen.getByTestId('passkey-empty')).toBeInTheDocument());
    expect(mockList).not.toHaveBeenCalled();
  });

  it('reloads the list from the refresh button', async () => {
    render(<PasskeyPanel />);
    await waitFor(() => expect(screen.getByTestId('passkey-empty')).toBeInTheDocument());
    expect(mockList).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByTestId('passkey-refresh-button'));
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(4));
  });

  it('closes the detail modal via Close', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    await waitFor(() =>
      expect(screen.queryByTestId('passkey-detail-modal')).toBeNull(),
    );
  });

  it('shows undecodable base64 as-is instead of hex', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data:
        identityId === 'id-1'
          ? [mkPasskey({ credential_id_b64: '@@@@', user_handle_b64: '@@@@' })]
          : [],
    }));
    render(<PasskeyPanel />);
    await openDetail();

    // atob 失败 → 原样展示（catch 分支）
    expect(screen.getByTestId('passkey-detail-credential-id')).toHaveTextContent('@@@@');
  });

  it('self-test: locked, generic failure and thrown errors each surface', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockSelfTest
      .mockResolvedValueOnce({ success: false, error_code: 'SERVICE_LOCKED' })
      .mockResolvedValueOnce({ success: false, error: 'signature mismatch' })
      .mockRejectedValueOnce(new Error('ipc gone'));
    render(<PasskeyPanel />);
    await openDetail();

    const btn = () => screen.getByTestId('passkey-selftest-button');

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent(
        '服务已锁定，解锁后重试。',
      ),
    );

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent(
        'signature mismatch',
      ),
    );

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-selftest-result')).toHaveTextContent('ipc gone'),
    );
  });

  it('export: cancelled re-auth, lock and thrown errors surface without a value', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockExport
      .mockResolvedValueOnce({ success: false, error_code: 'REAUTH_REQUIRED' })
      .mockResolvedValueOnce({ success: false, error_code: 'SERVICE_LOCKED' })
      .mockRejectedValueOnce(new Error('socket closed'));
    mockRequestReauth.mockResolvedValue(false);
    render(<PasskeyPanel />);
    await openDetail();

    const btn = () => screen.getByTestId('passkey-export-button');

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-export-error')).toHaveTextContent(
        '需要重新认证',
      ),
    );

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-export-error')).toHaveTextContent(
        '服务已锁定，解锁后重试。',
      ),
    );

    fireEvent.click(btn());
    await waitFor(() =>
      expect(screen.getByTestId('passkey-export-error')).toHaveTextContent('socket closed'),
    );
    expect(screen.queryByTestId('passkey-export-value')).toBeNull();
  });

  it('export value auto-hides after the countdown and is copyable meanwhile', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    mockExport.mockResolvedValue({ success: true, data: 'AAAAAQ==' });
    render(<PasskeyPanel />);
    await openDetail();

    jest.useFakeTimers();
    try {
      fireEvent.click(screen.getByTestId('passkey-export-button'));
      await act(async () => {}); // flush 导出 promise

      expect(screen.getByTestId('passkey-export-value')).toHaveTextContent('00000001');
      expect(screen.getByTestId('passkey-export-countdown')).toHaveTextContent('30 秒后隐藏');

      // 显示期间可复制
      fireEvent.click(screen.getByRole('button', { name: '复制私钥' }));
      expect(copyWithAutoClear).toHaveBeenCalledWith('00000001');

      // 逐秒推进：每次 act 让 React 提交后 effect 才重设下一秒的 timer
      for (let i = 0; i < 29; i++) {
        act(() => {
          jest.advanceTimersByTime(1_000);
        });
      }
      expect(screen.getByTestId('passkey-export-countdown')).toHaveTextContent('1 秒后隐藏');

      // 归零：导出值清除，倒计时消失
      act(() => {
        jest.advanceTimersByTime(1_000);
      });
      expect(screen.queryByTestId('passkey-export-value')).toBeNull();
      expect(screen.queryByTestId('passkey-export-countdown')).toBeNull();
    } finally {
      jest.useRealTimers();
    }
  });

  it('delete failure and thrown errors surface via toast and keep the modal open', async () => {
    mockList.mockImplementation(async (identityId: string) => ({
      success: true,
      data: identityId === 'id-1' ? [mkPasskey()] : [],
    }));
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    mockDelete
      .mockResolvedValueOnce({ success: false, error: 'still referenced by an RP' })
      .mockRejectedValueOnce(new Error('channel closed'));
    render(<PasskeyPanel />);
    await openDetail();

    fireEvent.click(screen.getByTestId('passkey-delete-button'));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('still referenced by an RP'));
    expect(screen.getByTestId('passkey-detail-modal')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('passkey-delete-button'));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('channel closed'));
    expect(screen.getByTestId('passkey-detail-modal')).toBeInTheDocument();
    confirmSpy.mockRestore();
  });
});
