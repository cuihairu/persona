import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import SshAgentPanel from './SshAgentPanel';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';
import toast from 'react-hot-toast';

const noop = jest.fn();

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
  Toaster: () => null,
}));

// The native file dialog only fires when the import button is clicked; under jsdom the cases script the return value
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
}));

// Entry edit/delete (P1-③) goes through personaAPI directly (not via the service hook)
jest.mock('@/utils/api', () => ({
  personaAPI: {
    updateCredential: jest.fn(),
    deleteCredential: jest.fn(),
  },
}));

// Drag events are attached to the webview; the handler is captured here so cases can dispatch it manually
let dragHandler: ((event: any) => void) | undefined;
jest.mock('@tauri-apps/api/webview', () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: (handler: any) => {
      dragHandler = handler;
      return Promise.resolve(() => {});
    },
  }),
}));

const INSPECTION = {
  file_name: 'id_ed25519',
  key_type: 'ed25519',
  ssh_algorithm: 'ssh-ed25519',
  public_key: 'ssh-ed25519 AAAAC3Nza test@example',
  fingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  comment: 'cui@laptop',
  encrypted: false,
};

const makeService = (over: Record<string, any> = {}) => ({
  sshAgentStatus: { running: false, socket_path: null, key_count: 0 },
  sshKeys: [],
  refreshSshAgentStatus: noop,
  startSshAgent: noop,
  stopSshAgent: noop,
  loadSshKeys: noop,
  inspectSshKeyFile: noop,
  importSshKey: noop,
  ...over,
});

const LIST_KEY = {
  id: 'k1',
  identity_id: 'identity-1',
  identity_name: 'work',
  name: 'laptop',
  tags: ['dev'],
  created_at: '2026-10-05T00:00:00Z',
  updated_at: '2026-10-05T00:00:00Z',
  ssh_algorithm: 'ssh-ed25519',
  fingerprint: 'SHA256:AAAA',
  key_size: '256',
  public_key: 'ssh-ed25519 AAAA test',
};

describe('components/SshAgentPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    dragHandler = undefined;
    useAppStore.setState({ currentIdentity: { id: 'identity-1', name: 'work' } as any });
  });

  it('calls refreshSshAgentStatus and loadSshKeys on mount', async () => {
    const refreshSshAgentStatus = jest.fn();
    const loadSshKeys = jest.fn();

    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ refreshSshAgentStatus, loadSshKeys }),
    );

    render(<SshAgentPanel />);
    await Promise.resolve();
    expect(refreshSshAgentStatus).toHaveBeenCalled();
    expect(loadSshKeys).toHaveBeenCalled();
  });

  it('rereads agent status and keys when the window becomes visible again', async () => {
    // The agent can be started/stopped and keys loaded by the CLI: the badge and list must catch up when the window is focused again
    const refreshSshAgentStatus = jest.fn();
    const loadSshKeys = jest.fn();

    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ refreshSshAgentStatus, loadSshKeys }),
    );

    render(<SshAgentPanel />);
    await Promise.resolve();
    const callsAfterMount = refreshSshAgentStatus.mock.calls.length;
    const keyCallsAfterMount = loadSshKeys.mock.calls.length;

    // Controlled clock: the throttle window (1s) is decided via Date.now
    let clock = 1_000_000;
    const nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => clock);

    // Visibility change (returning to the tab / restoring the window) → automatic re-read
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(refreshSshAgentStatus.mock.calls.length).toBeGreaterThan(callsAfterMount);
    expect(loadSshKeys.mock.calls.length).toBeGreaterThan(keyCallsAfterMount);

    // 1s throttle: bursts within the window (visibilitychange+focus arrive in pairs on refocus) do not re-fetch
    clock += 300;
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    expect(refreshSshAgentStatus.mock.calls.length).toBe(callsAfterMount + 1);

    // Past the window, window focus triggers too (for OS-level refocus that produces no visibilitychange)
    clock += 2000;
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    expect(refreshSshAgentStatus.mock.calls.length).toBe(callsAfterMount + 2);

    // Hidden state does not fetch
    clock += 2000;
    jest.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(refreshSshAgentStatus.mock.calls.length).toBe(callsAfterMount + 2);
    nowSpy.mockRestore();
    jest.restoreAllMocks();
  });

  it('starts agent with optional master password', async () => {
    const startSshAgent = jest.fn().mockResolvedValue(undefined);
    const refreshSshAgentStatus = jest.fn().mockResolvedValue(undefined);

    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ startSshAgent, refreshSshAgentStatus }),
    );

    const { getByPlaceholderText, getByText } = render(<SshAgentPanel />);
    fireEvent.change(getByPlaceholderText('主密码（可选）'), { target: { value: 'pw' } });
    fireEvent.click(getByText('启动'));

    await Promise.resolve();
    await Promise.resolve();

    expect(startSshAgent).toHaveBeenCalledWith('pw');
    expect(refreshSshAgentStatus).toHaveBeenCalled();
  });

  // -----------------------------------------------------------------
  // P1-③: entry metadata edit and delete (with confirmation; the private
  // key material itself offers no editing)
  // -----------------------------------------------------------------

  it('edits entry name/tags via updateCredential and refreshes (P1-③)', async () => {
    const loadSshKeys = jest.fn();
    (personaAPI.updateCredential as jest.Mock).mockResolvedValue({
      success: true,
      data: { ...LIST_KEY, name: 'laptop-work' },
    });
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshKeys: [LIST_KEY], loadSshKeys }),
    );

    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-key-edit-k1'));
    const modal = getByTestId('ssh-edit-modal');
    expect(modal).toBeTruthy();
    // Name pre-filled, tags pre-filled as a comma string; the i18n key resolves (a bare key= is the missed-key regression)
    expect((getByTestId('ssh-edit-name') as HTMLInputElement).value).toBe('laptop');
    expect((getByTestId('ssh-edit-tags') as HTMLInputElement).value).toBe('dev');
    expect(getByTestId('ssh-edit-cancel')).toHaveTextContent('取消');

    fireEvent.change(getByTestId('ssh-edit-name'), { target: { value: 'laptop-work' } });
    fireEvent.change(getByTestId('ssh-edit-tags'), { target: { value: 'dev, work' } });
    fireEvent.click(getByTestId('ssh-edit-save'));

    // snake_case contract: only id/name/tags are sent (other metadata fields untouched)
    await waitFor(() =>
      expect(personaAPI.updateCredential).toHaveBeenCalledWith({
        id: 'k1',
        name: 'laptop-work',
        tags: ['dev', 'work'],
      }),
    );
    await waitFor(() => expect(queryByTestId('ssh-edit-modal')).toBeNull());
    expect(loadSshKeys).toHaveBeenCalled();
    expect(toast.success).toHaveBeenCalled();
  });

  it('rejects an empty name without calling update (P1-③ guard)', async () => {
    (usePersonaService as jest.Mock).mockReturnValue(makeService({ sshKeys: [LIST_KEY] }));
    const { getByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-key-edit-k1'));
    fireEvent.change(getByTestId('ssh-edit-name'), { target: { value: '   ' } });
    fireEvent.click(getByTestId('ssh-edit-save'));

    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(personaAPI.updateCredential).not.toHaveBeenCalled();
    expect(getByTestId('ssh-edit-modal')).toBeTruthy();
  });

  it('deletes after confirm and refreshes; cancel keeps the row (P1-③)', async () => {
    const loadSshKeys = jest.fn();
    (personaAPI.deleteCredential as jest.Mock).mockResolvedValue({ success: true, data: true });
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshKeys: [LIST_KEY], loadSshKeys }),
    );

    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const { getByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-key-delete-k1'));
    await waitFor(() => expect(window.confirm).toHaveBeenCalled());
    expect(personaAPI.deleteCredential).not.toHaveBeenCalled();

    confirmSpy.mockReturnValue(true);
    fireEvent.click(getByTestId('ssh-key-delete-k1'));
    await waitFor(() =>
      expect(personaAPI.deleteCredential).toHaveBeenCalledWith('k1'),
    );
    await waitFor(() => expect(loadSshKeys).toHaveBeenCalled());
    expect(toast.success).toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // -----------------------------------------------------------------
  // Inline copy lives in the "Actions" column (user directive 2026-11-08:
  // copy-public-key moved into the actions column, simply named Copy)
  // -----------------------------------------------------------------

  it('copies the public key from the actions column button labeled 复制', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshKeys: [LIST_KEY] }),
    );

    const { getByTestId, getByText } = render(<SshAgentPanel />);
    // The Copy button sits in the actions column (edit/delete share the same cell)
    const copyBtn = getByTestId('ssh-key-copy-k1');
    expect(copyBtn.textContent).toContain('复制');
    // The public-key column is plain text display only; it no longer hosts the copy button
    expect(copyBtn.contains(getByText('ssh-ed25519 AAAA test'))).toBe(false);
    fireEvent.click(copyBtn);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('ssh-ed25519 AAAA test'));
    await waitFor(() => expect(getByTestId('ssh-key-copy-k1').textContent).toContain('已复制'));
  });

  // -----------------------------------------------------------------
  // P2-⑤: type column key-size/curve badge (computed by the backend,
  // display-only on the frontend)
  // -----------------------------------------------------------------

  it('renders key size badge and hides it when backend reports none (P2-⑤)', () => {
    (usePersonaService as jest.Mock).mockReturnValue(makeService({ sshKeys: [LIST_KEY] }));
    const { getByTestId } = render(<SshAgentPanel />);
    expect(getByTestId('ssh-key-size-k1')).toHaveTextContent('256');

    // Certificate and other non-key containers: key_size is null → the badge does not render
    cleanup();
    const noSize = { ...LIST_KEY, id: 'k2', ssh_algorithm: 'cert-authority', key_size: null };
    (usePersonaService as jest.Mock).mockReturnValue(makeService({ sshKeys: [noSize] }));
    const { queryByTestId } = render(<SshAgentPanel />);
    expect(queryByTestId('ssh-key-size-k2')).toBeNull();
  });

  it('disables the start button while running, re-enables after stop (BUG ⑦)', async () => {
    // While running: the start button is disabled/grayed with copy “Running”; repeat clicks are physically blocked
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshAgentStatus: { running: true, socket_path: '/tmp/s', key_count: 1 } }),
    );
    const { getByTestId } = render(<SshAgentPanel />);
    const start = getByTestId('ssh-agent-start-button');
    expect(start).toBeDisabled();
    expect(start).toHaveTextContent('运行中');
    expect(getByTestId('ssh-agent-stop-button')).toBeEnabled();

    // After stop the state follows: the start button is clickable again and its copy falls back to “Start”; the stop button is disabled
    cleanup();
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshAgentStatus: { running: false, socket_path: null, key_count: 0 } }),
    );
    render(<SshAgentPanel />);
    expect(getByTestId('ssh-agent-start-button')).toBeEnabled();
    expect(getByTestId('ssh-agent-start-button')).toHaveTextContent('启动');
    expect(getByTestId('ssh-agent-stop-button')).toBeDisabled();
  });

  it('stop button invokes stopSshAgent and refreshes status (BUG ⑧ clickable)', async () => {
    const stopSshAgent = jest.fn().mockResolvedValue(undefined);
    const refreshSshAgentStatus = jest.fn().mockResolvedValue(undefined);
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({
        sshAgentStatus: { running: true, socket_path: '/tmp/s', key_count: 0 },
        stopSshAgent,
        refreshSshAgentStatus,
      }),
    );

    const { getByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-agent-stop-button'));
    await Promise.resolve();
    await Promise.resolve();
    expect(stopSshAgent).toHaveBeenCalled();
    expect(refreshSshAgentStatus).toHaveBeenCalled();
  });

  it('imports via file dialog and pins the snake_case IPC contract', async () => {
    const inspectSshKeyFile = jest
      .fn()
      .mockResolvedValue({ success: true, data: INSPECTION, error: null });
    const importSshKey = jest
      .fn()
      .mockResolvedValue({
        success: true,
        data: {
          credential_id: 'cred-1',
          name: 'cui@laptop',
          key_type: 'ed25519',
          public_key: INSPECTION.public_key,
          fingerprint: INSPECTION.fingerprint,
        },
        error: null,
      });
    const loadSshKeys = jest.fn();
    (openDialog as jest.Mock).mockResolvedValue('/home/cui/.ssh/id_ed25519');
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ inspectSshKeyFile, importSshKey, loadSshKeys }),
    );

    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-import-button'));

    await waitFor(() =>
      expect(getByTestId('ssh-import-modal')).toBeTruthy(),
    );
    // Preview comes before storing: the fingerprint is echoed back in the confirmation dialog
    expect(getByTestId('ssh-import-fingerprint').textContent).toBe(
      INSPECTION.fingerprint,
    );
    expect(inspectSshKeyFile).toHaveBeenCalledWith('/home/cui/.ssh/id_ed25519');
    expect(importSshKey).not.toHaveBeenCalled();

    // The name defaults to the comment fallback (editable)
    const nameInput = getByTestId('ssh-import-name') as HTMLInputElement;
    expect(nameInput.value).toBe('cui@laptop');
    fireEvent.change(nameInput, { target: { value: 'my-key' } });
    fireEvent.click(getByTestId('ssh-import-confirm'));

    await waitFor(() =>
      expect(importSshKey).toHaveBeenCalledWith({
        identity_id: 'identity-1',
        path: '/home/cui/.ssh/id_ed25519',
        name: 'my-key',
        passphrase: undefined,
      }),
    );
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    expect(loadSshKeys).toHaveBeenCalled();
    await waitFor(() => expect(queryByTestId('ssh-import-modal')).toBeNull());
  });

  it('sends passphrase for encrypted keys and keeps the modal open on wrong passphrase', async () => {
    const encrypted = { ...INSPECTION, encrypted: true };
    const inspectSshKeyFile = jest
      .fn()
      .mockResolvedValue({ success: true, data: encrypted, error: null });
    let attempt = 0;
    const importSshKey = jest.fn().mockImplementation(() => {
      attempt += 1;
      if (attempt === 1) {
        return Promise.resolve({
          success: false,
          data: null,
          error: 'SSH key passphrase is incorrect',
        });
      }
      return Promise.resolve({
        success: true,
        data: { credential_id: 'cred-2', name: 'id_enc', key_type: 'ed25519', public_key: 'k', fingerprint: 'f' },
        error: null,
      });
    });
    (openDialog as jest.Mock).mockResolvedValue('/home/cui/.ssh/id_enc');
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ inspectSshKeyFile, importSshKey }),
    );

    const { getByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-import-button'));
    await waitFor(() => expect(getByTestId('ssh-import-modal')).toBeTruthy());

    // Protected keys show a passphrase field; importing without a passphrase still passes undefined (not a camelCase key)
    fireEvent.click(getByTestId('ssh-import-confirm'));
    await waitFor(() =>
      expect(importSshKey).toHaveBeenCalledWith({
        identity_id: 'identity-1',
        path: '/home/cui/.ssh/id_enc',
        name: 'cui@laptop',
        passphrase: undefined,
      }),
    );

    // Wrong passphrase: the error shows in place and the dialog stays open
    await waitFor(() =>
      expect(getByTestId('ssh-import-error').textContent).toContain('incorrect'),
    );
    expect(getByTestId('ssh-import-modal')).toBeTruthy();

    // Retrying with the corrected passphrase: the dialog closes on success with a success toast
    fireEvent.change(getByTestId('ssh-import-passphrase'), {
      target: { value: 'hunter2' },
    });
    fireEvent.click(getByTestId('ssh-import-confirm'));
    await waitFor(() =>
      expect(importSshKey).toHaveBeenLastCalledWith({
        identity_id: 'identity-1',
        path: '/home/cui/.ssh/id_enc',
        name: 'cui@laptop',
        passphrase: 'hunter2',
      }),
    );
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
  });

  it('drop with paths runs the same inspect pipeline; non-file drag is ignored', async () => {
    const inspectSshKeyFile = jest
      .fn()
      .mockResolvedValue({ success: true, data: INSPECTION, error: null });
    const importSshKey = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ inspectSshKeyFile, importSshKey }),
    );

    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    await waitFor(() => expect(dragHandler).toBeDefined());

    // Dragging plain text (no paths) does not light up the dropzone
    await act(async () => {
      dragHandler!({ payload: { type: 'enter', paths: [], position: { x: 1, y: 1 } } });
    });
    expect(queryByTestId('ssh-dropzone')).toBeNull();

    // Dragging files: lights up; a drop with paths → the same inspect pipeline as the file picker
    await act(async () => {
      dragHandler!({ payload: { type: 'enter', paths: ['/tmp/id_rsa'], position: { x: 1, y: 1 } } });
    });
    expect(getByTestId('ssh-dropzone')).toBeTruthy();

    await act(async () => {
      dragHandler!({ payload: { type: 'drop', paths: ['/tmp/id_rsa'], position: { x: 1, y: 1 } } });
    });
    await waitFor(() => expect(inspectSshKeyFile).toHaveBeenCalledWith('/tmp/id_rsa'));
    // After drop the dropzone goes dark and the confirmation dialog opens
    expect(queryByTestId('ssh-dropzone')).toBeNull();
    expect(getByTestId('ssh-import-modal')).toBeTruthy();

    // Cancelling the dialog (blank-area click) produces no storing side effects
    fireEvent.mouseDown(getByTestId('ssh-import-modal'));
    await waitFor(() => expect(queryByTestId('ssh-import-modal')).toBeNull());
    expect(importSshKey).not.toHaveBeenCalled();
  });

  it('cancels drag overlay on cancel event', async () => {
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({
        inspectSshKeyFile: jest.fn(),
      }),
    );
    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    await waitFor(() => expect(dragHandler).toBeDefined());

    await act(async () => {
      dragHandler!({ payload: { type: 'over', position: { x: 1, y: 1 } } });
    });
    expect(getByTestId('ssh-dropzone')).toBeTruthy();
    await act(async () => {
      dragHandler!({ payload: { type: 'cancel' } });
    });
    expect(queryByTestId('ssh-dropzone')).toBeNull();
  });

  it('refuses to open the dialog without a current identity', async () => {
    (usePersonaService as jest.Mock).mockReturnValue(makeService());
    useAppStore.setState({ currentIdentity: null });

    const { getByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-import-button'));
    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(openDialog).not.toHaveBeenCalled();
  });

  // -----------------------------------------------------------------
  // Create (generate) dialog: type selection → generate and store →
  // copyable public key; blank-area click cancels
  // -----------------------------------------------------------------

  const GENERATED = {
    credential_id: 'cred-gen-1',
    name: 'cui@laptop',
    key_type: 'ed25519',
    public_key: 'ssh-ed25519 AAAAC3Nza GENERATED gen-test',
    fingerprint: 'SHA256:GENERATEDFINGERPRINT',
  };

  it('generates in place and shows a copyable public key', async () => {
    const generateSshKey = jest
      .fn()
      .mockResolvedValue({ success: true, data: GENERATED, error: null });
    const loadSshKeys = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ generateSshKey, loadSshKeys }),
    );

    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-generate-button'));

    const modal = getByTestId('ssh-generate-modal');
    expect(modal).toBeTruthy();

    // ed25519 selected by default; switch to rsa and back
    expect(getByTestId('ssh-generate-type-ed25519')).toHaveProperty('checked', true);
    fireEvent.click(getByTestId('ssh-generate-type-rsa'));
    expect(getByTestId('ssh-generate-type-rsa')).toHaveProperty('checked', true);
    fireEvent.click(getByTestId('ssh-generate-type-ed25519'));

    fireEvent.change(getByTestId('ssh-generate-comment'), {
      target: { value: 'cui@laptop' },
    });
    fireEvent.click(getByTestId('ssh-generate-confirm'));

    // snake_case key contract: empty comment/name are passed as undefined
    await waitFor(() =>
      expect(generateSshKey).toHaveBeenCalledWith({
        identity_id: 'identity-1',
        key_type: 'ed25519',
        comment: 'cui@laptop',
        name: undefined,
      }),
    );
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    expect(loadSshKeys).toHaveBeenCalled();

    // On success the dialog stays open: public key + copy button
    await waitFor(() => expect(getByTestId('ssh-generate-result')).toBeTruthy());
    expect(getByTestId('ssh-generate-copy')).toBeTruthy();

    Object.assign(navigator, { clipboard: { writeText: jest.fn().mockResolvedValue(undefined) } });
    fireEvent.click(getByTestId('ssh-generate-copy'));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(GENERATED.public_key),
    );

    // Done closes the dialog
    fireEvent.click(getByTestId('ssh-generate-done'));
    await waitFor(() => expect(queryByTestId('ssh-generate-modal')).toBeNull());
  });

  it('keeps the generate modal open on failure with an inline error', async () => {
    const generateSshKey = jest
      .fn()
      .mockResolvedValue({ success: false, data: null, error: 'boom' });
    (usePersonaService as jest.Mock).mockReturnValue(makeService({ generateSshKey }));
    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-generate-button'));
    fireEvent.click(getByTestId('ssh-generate-confirm'));

    await waitFor(() =>
      expect(getByTestId('ssh-generate-error').textContent).toBe('boom'),
    );
    expect(getByTestId('ssh-generate-modal')).toBeTruthy();
    expect(queryByTestId('ssh-generate-result')).toBeNull();
  });

  it('mask click cancels the generate modal but not while generating', async () => {
    let resolveGenerate: (v: unknown) => void = () => {};
    const generateSshKey = jest.fn(
      () =>
        new Promise((resolve) => {
          resolveGenerate = resolve;
        }),
    );
    (usePersonaService as jest.Mock).mockReturnValue(makeService({ generateSshKey }));
    const { getByTestId, queryByTestId } = render(<SshAgentPanel />);
    fireEvent.click(getByTestId('ssh-generate-button'));
    fireEvent.click(getByTestId('ssh-generate-confirm'));

    // While generating: a mask click does not close it (the background will still store the key, and closing would suggest nothing was generated)
    await waitFor(() => expect(generateSshKey).toHaveBeenCalled());
    fireEvent.mouseDown(getByTestId('ssh-generate-modal'));
    expect(getByTestId('ssh-generate-modal')).toBeTruthy();

    // After generation completes: a mask click closes it, and no second call is made
    resolveGenerate({ success: true, data: GENERATED, error: null });
    await waitFor(() => expect(getByTestId('ssh-generate-result')).toBeTruthy());
    fireEvent.mouseDown(getByTestId('ssh-generate-modal'));
    await waitFor(() => expect(queryByTestId('ssh-generate-modal')).toBeNull());
    expect(generateSshKey).toHaveBeenCalledTimes(1);
  });
});
