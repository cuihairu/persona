import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import ConnectAutomationSection from './ConnectAutomationSection';
import { personaAPI } from '@/utils/api';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    connectServerStatus: jest.fn(),
    connectServerStart: jest.fn(),
    connectServerStop: jest.fn(),
    connectTokenList: jest.fn(),
    connectTokenCreate: jest.fn(),
    connectTokenRevoke: jest.fn(),
    getIdentities: jest.fn(),
    reauthVerify: jest.fn(),
  },
}));

const mockStatus = personaAPI.connectServerStatus as jest.Mock;
const mockStart = personaAPI.connectServerStart as jest.Mock;
const mockStop = personaAPI.connectServerStop as jest.Mock;
const mockList = personaAPI.connectTokenList as jest.Mock;
const mockCreate = personaAPI.connectTokenCreate as jest.Mock;
const mockRevoke = personaAPI.connectTokenRevoke as jest.Mock;
const mockGetIdentities = personaAPI.getIdentities as jest.Mock;
const mockReauthVerify = personaAPI.reauthVerify as jest.Mock;

const stopped = { success: true, data: { running: false, port: null } };
const running8080 = { success: true, data: { running: true, port: 8080 } };
const noIdentities = { success: true, data: [] };

const activeToken = {
  id: 'tok-1',
  label: 'my CLI',
  fingerprint: 'a1b2c3d4e5f6a7b8',
  scope: { identities: [], item_types: ['password'], verbs: ['read'] },
  created_at: '2026-09-01T00:00:00Z',
  last_used_at: null,
  revoked_at: null,
};

/** The default all-green panel load (status/list/identities) */
const seedDefaults = () => {
  mockStatus.mockResolvedValue(stopped);
  mockList.mockResolvedValue({ success: true, data: [] });
  mockGetIdentities.mockResolvedValue(noIdentities);
};

const renderSection = () => render(<ConnectAutomationSection />);

describe('components/ConnectAutomationSection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    seedDefaults();
  });

  it('renders the stopped state with an empty token list', async () => {
    renderSection();

    await waitFor(() => {
      expect(screen.getByTestId('connect-server-toggle')).toBeEnabled();
    });
    expect(screen.getByTestId('connect-server-toggle')).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('connect-status')).toHaveTextContent('已关闭');
    expect(screen.getByTestId('connect-tokens-empty')).toHaveTextContent('还没有 token');
    expect(screen.queryByTestId('connect-tokens-list')).not.toBeInTheDocument();
  });

  it('starts and stops the listener from the toggle', async () => {
    mockStart.mockResolvedValue(running8080);
    mockStop.mockResolvedValue(stopped);

    renderSection();
    // Click only after the status has finished loading (the toggle is no longer disabled); otherwise the disabled state swallows the click
    const toggle = await screen.findByTestId('connect-server-toggle');
    await waitFor(() => expect(toggle).toBeEnabled());

    await act(async () => {
      fireEvent.click(toggle);
    });
    expect(mockStart).toHaveBeenCalledWith(null);
    await waitFor(() => {
      expect(screen.getByTestId('connect-server-toggle')).toHaveAttribute('aria-checked', 'true');
    });
    expect(screen.getByTestId('connect-status')).toHaveTextContent('127.0.0.1:8080');
    expect(screen.getByTestId('connect-section')).toHaveTextContent('持有有效 token');

    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-server-toggle'));
    });
    expect(mockStop).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(screen.getByTestId('connect-server-toggle')).toHaveAttribute('aria-checked', 'false');
    });
  });

  it('lists tokens with fingerprint, scope summary and revocation controls', async () => {
    mockList.mockResolvedValue({
      success: true,
      data: [
        activeToken,
        {
          ...activeToken,
          id: 'tok-2',
          label: 'old token',
          fingerprint: 'ffff0000ffff0000',
          scope: { identities: [], item_types: [], verbs: ['read'] },
          revoked_at: '2026-09-02T00:00:00Z',
        },
      ],
    });

    renderSection();

    await waitFor(() => {
      expect(screen.getByTestId('connect-tokens-list')).toBeInTheDocument();
    });
    // An active token: fingerprint, scope summary (all identities · password · read-only), unused, revocable
    expect(screen.getByText('a1b2c3d4e5f6a7b8')).toBeInTheDocument();
    expect(screen.getByText('全部身份 · password · 只读')).toBeInTheDocument();
    expect(screen.getAllByText('从未使用')).toHaveLength(2);
    expect(screen.getByTestId('connect-revoke-tok-1')).toBeInTheDocument();
    // A revoked token: labeled, with no revoke button
    expect(screen.getByText('(已吊销)')).toBeInTheDocument();
    expect(screen.queryByTestId('connect-revoke-tok-2')).not.toBeInTheDocument();
  });

  it('revokes a token after confirm and refreshes the list', async () => {
    mockList
      .mockResolvedValueOnce({ success: true, data: [activeToken] })
      .mockResolvedValueOnce({ success: true, data: [{ ...activeToken, revoked_at: '2026-09-22T00:00:00Z' }] });
    mockRevoke.mockResolvedValue({ success: true, data: true });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);

    renderSection();
    await waitFor(() => {
      expect(screen.getByTestId('connect-revoke-tok-1')).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-revoke-tok-1'));
    });

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      expect(mockRevoke).toHaveBeenCalledWith('tok-1');
    });
    // After a refresh it shows as revoked: the button disappears
    await waitFor(() => {
      expect(screen.queryByTestId('connect-revoke-tok-1')).not.toBeInTheDocument();
    });
    confirmSpy.mockRestore();
  });

  it('creates a token and shows the plaintext once', async () => {
    mockCreate.mockResolvedValue({
      success: true,
      data: {
        token: 'pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        info: { ...activeToken, id: 'tok-new' },
      },
    });

    renderSection();
    fireEvent.click(await screen.findByTestId('connect-create-token'));

    // The default form: all identities + a specific type (password ticked), with the all-identities warning visible
    expect(screen.getByTestId('connect-all-identities-warning')).toBeInTheDocument();
    fireEvent.change(screen.getByTestId('connect-token-label'), { target: { value: 'cli' } });

    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-create-submit'));
    });

    await waitFor(() => {
      expect(mockCreate).toHaveBeenCalledWith('cli', {
        identities: [],
        item_types: ['password'],
        verbs: ['read'],
      });
    });
    // One-time plaintext display: warning + token + copy + done
    await waitFor(() => {
      expect(screen.getByTestId('connect-created-token')).toHaveTextContent(
        'pconn_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      );
    });
    expect(screen.getByTestId('connect-created-warning')).toHaveTextContent('无法再次查看');
    expect(screen.queryByTestId('connect-create-modal')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('connect-created-done'));
    expect(screen.queryByTestId('connect-created-modal')).not.toBeInTheDocument();
  });

  it('copies the plaintext token to the clipboard', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    mockCreate.mockResolvedValue({
      success: true,
      data: {
        token: 'pconn_AAAA',
        info: { ...activeToken, id: 'tok-new' },
      },
    });

    renderSection();
    fireEvent.click(await screen.findByTestId('connect-create-token'));
    fireEvent.change(screen.getByTestId('connect-token-label'), { target: { value: 'cli' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-create-submit'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('connect-created-copy')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('connect-created-copy'));
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith('pconn_AAAA');
      expect(screen.getByTestId('connect-created-copy')).toHaveTextContent('已复制');
    });
  });

  it('blocks submission until the form is valid', async () => {
    mockGetIdentities.mockResolvedValue({
      success: true,
      data: [{ id: 'id-1', name: 'Work' }],
    });

    renderSection();
    fireEvent.click(await screen.findByTestId('connect-create-token'));

    // An empty label
    fireEvent.click(screen.getByTestId('connect-create-submit'));
    await act(async () => {});
    expect(screen.getByTestId('connect-create-error')).toHaveTextContent('请填写名称');
    expect(mockCreate).not.toHaveBeenCalled();

    // Specific identities chosen but none ticked
    fireEvent.change(screen.getByTestId('connect-token-label'), { target: { value: 'cli' } });
    fireEvent.click(screen.getByTestId('connect-identities-pick'));
    fireEvent.click(screen.getByTestId('connect-create-submit'));
    await act(async () => {});
    expect(screen.getByTestId('connect-create-error')).toHaveTextContent('至少选择一个身份');
    expect(mockCreate).not.toHaveBeenCalled();

    // Ticking them lets it through, and the scope carries the specified identities
    // The type list must include all 10 grantable types (certificate was once missing, which left certificate entries ungrantable)
    fireEvent.click(screen.getByTestId('connect-types-pick'));
    expect(screen.getByTestId('connect-type-certificate')).toBeInTheDocument();
    expect(screen.getByTestId('connect-type-software_license')).toBeInTheDocument();
    mockCreate.mockResolvedValue({
      success: true,
      data: { token: 'pconn_BBBB', info: { ...activeToken, id: 'tok-new' } },
    });
    fireEvent.click(screen.getByTestId('connect-identity-id-1'));
    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-create-submit'));
    });
    await waitFor(() => {
      expect(mockCreate).toHaveBeenCalledWith('cli', {
        identities: ['id-1'],
        item_types: ['password'],
        verbs: ['read'],
      });
    });
  });

  it('interrupts creation with REAUTH_REQUIRED, verifies, and retries the same form', async () => {
    mockGetIdentities.mockResolvedValue({
      success: true,
      data: [{ id: 'id-1', name: 'Work' }],
    });
    mockCreate
      .mockResolvedValueOnce({
        success: false,
        error_code: 'REAUTH_REQUIRED',
        error: 'Re-authentication required',
      })
      .mockResolvedValueOnce({
        success: true,
        data: { token: 'pconn_CCCC', info: { ...activeToken, id: 'tok-new' } },
      });
    mockReauthVerify.mockResolvedValue({ success: true, data: true });

    renderSection();
    fireEvent.click(await screen.findByTestId('connect-create-token'));
    fireEvent.change(screen.getByTestId('connect-token-label'), { target: { value: 'cli' } });
    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-create-submit'));
    });

    // The form collapses and the master password re-verification pops up (findBy runs waitFor+act internally, so what we get is the stable DOM after it has drained)
    const reauthModal = await screen.findByTestId('reauth-modal');
    expect(screen.queryByTestId('connect-create-modal')).not.toBeInTheDocument();
    expect(mockReauthVerify).not.toHaveBeenCalled();

    fireEvent.change(reauthModal.querySelector('input') as HTMLInputElement, {
      target: { value: 'master-pw' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '确认' }));
    });

    // Verification passed → the original form reopens (the label is preserved), and the user must click create once more
    await waitFor(() => {
      expect(mockReauthVerify).toHaveBeenCalledWith('master-pw');
    });
    await screen.findByTestId('connect-create-modal');
    expect(screen.queryByTestId('reauth-modal')).not.toBeInTheDocument();
    expect((screen.getByTestId('connect-token-label') as HTMLInputElement).value).toBe('cli');

    await act(async () => {
      fireEvent.click(screen.getByTestId('connect-create-submit'));
    });
    await waitFor(() => {
      expect(mockCreate).toHaveBeenNthCalledWith(2, 'cli', {
        identities: [],
        item_types: ['password'],
        verbs: ['read'],
      });
    });
    await waitFor(() => {
      expect(screen.getByTestId('connect-created-token')).toHaveTextContent('pconn_CCCC');
    });
  });
});
