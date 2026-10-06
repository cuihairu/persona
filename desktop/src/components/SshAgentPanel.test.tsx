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

// 原生文件对话框只在点击导入按钮时触发；jsdom 下由用例编排返回值
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
}));

// 条目编辑/删除（P1-③）走 personaAPI 直调（不经 service hook）
jest.mock('@/utils/api', () => ({
  personaAPI: {
    updateCredential: jest.fn(),
    deleteCredential: jest.fn(),
  },
}));

// 拖拽事件挂在 webview 上；这里捕获处理器供用例手动派发
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
  // P1-③：条目元数据编辑与删除（二次确认；私钥本体不提供编辑）
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
    // 名称预填、标签逗号串预填；i18n 键命中（裸 key= 漏键回归）
    expect((getByTestId('ssh-edit-name') as HTMLInputElement).value).toBe('laptop');
    expect((getByTestId('ssh-edit-tags') as HTMLInputElement).value).toBe('dev');
    expect(getByTestId('ssh-edit-cancel')).toHaveTextContent('取消');

    fireEvent.change(getByTestId('ssh-edit-name'), { target: { value: 'laptop-work' } });
    fireEvent.change(getByTestId('ssh-edit-tags'), { target: { value: 'dev, work' } });
    fireEvent.click(getByTestId('ssh-edit-save'));

    // snake_case 契约：只传 id/name/tags（其余元数据字段不动）
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

  it('disables the start button while running, re-enables after stop (BUG ⑦)', async () => {
    // 运行中：启动按钮禁用置灰、文案「运行中」；重复点击物理禁掉
    (usePersonaService as jest.Mock).mockReturnValue(
      makeService({ sshAgentStatus: { running: true, socket_path: '/tmp/s', key_count: 1 } }),
    );
    const { getByTestId } = render(<SshAgentPanel />);
    const start = getByTestId('ssh-agent-start-button');
    expect(start).toBeDisabled();
    expect(start).toHaveTextContent('运行中');
    expect(getByTestId('ssh-agent-stop-button')).toBeEnabled();

    // 停止后状态联动：启动恢复可点、文案回落「启动」；停止按钮禁用
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
    // 预览先于入库：指纹在确认弹框里回显
    expect(getByTestId('ssh-import-fingerprint').textContent).toBe(
      INSPECTION.fingerprint,
    );
    expect(inspectSshKeyFile).toHaveBeenCalledWith('/home/cui/.ssh/id_ed25519');
    expect(importSshKey).not.toHaveBeenCalled();

    // 名字默认回退 comment（可改）
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

    // 受保护钥显示口令输入框；口令为空时直接导入也要带 undefined（不是 camelCase 键）
    fireEvent.click(getByTestId('ssh-import-confirm'));
    await waitFor(() =>
      expect(importSshKey).toHaveBeenCalledWith({
        identity_id: 'identity-1',
        path: '/home/cui/.ssh/id_enc',
        name: 'cui@laptop',
        passphrase: undefined,
      }),
    );

    // 错口令：错误就地显示，弹框不关
    await waitFor(() =>
      expect(getByTestId('ssh-import-error').textContent).toContain('incorrect'),
    );
    expect(getByTestId('ssh-import-modal')).toBeTruthy();

    // 补对口令重试：成功后弹框关、成功 toast
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

    // 纯文本拖入（无路径）不点亮拖放区
    await act(async () => {
      dragHandler!({ payload: { type: 'enter', paths: [], position: { x: 1, y: 1 } } });
    });
    expect(queryByTestId('ssh-dropzone')).toBeNull();

    // 文件拖入：点亮；drop 带路径 → 与选择器同一条 inspect 流水线
    await act(async () => {
      dragHandler!({ payload: { type: 'enter', paths: ['/tmp/id_rsa'], position: { x: 1, y: 1 } } });
    });
    expect(getByTestId('ssh-dropzone')).toBeTruthy();

    await act(async () => {
      dragHandler!({ payload: { type: 'drop', paths: ['/tmp/id_rsa'], position: { x: 1, y: 1 } } });
    });
    await waitFor(() => expect(inspectSshKeyFile).toHaveBeenCalledWith('/tmp/id_rsa'));
    // drop 后拖放区熄灭、确认弹框打开
    expect(queryByTestId('ssh-dropzone')).toBeNull();
    expect(getByTestId('ssh-import-modal')).toBeTruthy();

    // 取消弹框（点空白）不产生任何入库副作用
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
  // 新建（生成）弹框：类型选择 → 生成入库 → 公钥可复制；点空白取消
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

    // 默认 ed25519 选中；切到 rsa 再切回
    expect(getByTestId('ssh-generate-type-ed25519')).toHaveProperty('checked', true);
    fireEvent.click(getByTestId('ssh-generate-type-rsa'));
    expect(getByTestId('ssh-generate-type-rsa')).toHaveProperty('checked', true);
    fireEvent.click(getByTestId('ssh-generate-type-ed25519'));

    fireEvent.change(getByTestId('ssh-generate-comment'), {
      target: { value: 'cui@laptop' },
    });
    fireEvent.click(getByTestId('ssh-generate-confirm'));

    // snake_case 键契约：comment/name 空值传 undefined
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

    // 成功态留在弹框内：公钥 + 复制按钮
    await waitFor(() => expect(getByTestId('ssh-generate-result')).toBeTruthy());
    expect(getByTestId('ssh-generate-copy')).toBeTruthy();

    Object.assign(navigator, { clipboard: { writeText: jest.fn().mockResolvedValue(undefined) } });
    fireEvent.click(getByTestId('ssh-generate-copy'));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(GENERATED.public_key),
    );

    // 完成关闭
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

    // 生成中：点遮罩不关（后台仍会入库，关了会误以为没生成）
    await waitFor(() => expect(generateSshKey).toHaveBeenCalled());
    fireEvent.mouseDown(getByTestId('ssh-generate-modal'));
    expect(getByTestId('ssh-generate-modal')).toBeTruthy();

    // 生成完成后：点遮罩关闭，且不产生第二次调用
    resolveGenerate({ success: true, data: GENERATED, error: null });
    await waitFor(() => expect(getByTestId('ssh-generate-result')).toBeTruthy());
    fireEvent.mouseDown(getByTestId('ssh-generate-modal'));
    await waitFor(() => expect(queryByTestId('ssh-generate-modal')).toBeNull());
    expect(generateSshKey).toHaveBeenCalledTimes(1);
  });
});
