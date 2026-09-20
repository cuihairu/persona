import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialDetailPane from './CredentialDetailPane';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

// 原生文件对话框只在用户点击 Add File / 保存时触发；jsdom 下哑掉
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
  save: jest.fn(),
}));

// flag 开时面板会挂 useFavicons 预取；这里哑掉 IPC（缓存命中路径另有专测）
jest.mock('@/utils/api', () => ({
  personaAPI: {
    getFavicons: jest.fn().mockResolvedValue({ success: true, data: [] }),
  },
}));

// 单独测过 reveal 重试编排，这里哑渲染并暴露 field 传参
jest.mock('@/components/RevealSecretButton', () => ({
  __esModule: true,
  default: ({ field, label }: any) => (
    <button data-testid={`reveal-${field}`}>{label}</button>
  ),
}));

const makeCred = (over: Record<string, any> = {}) => ({
  id: 'c1',
  identity_id: 'i1',
  name: 'Example',
  credential_type: 'Password',
  security_level: 'High',
  url: null,
  username: null,
  notes: null,
  tags: [] as string[],
  last_accessed: null,
  created_at: '2023-01-01T00:00:00Z',
  updated_at: '2023-01-01T00:00:00Z',
  is_active: true,
  is_favorite: false,
  ...over,
});

/** props 直驱渲染面板；service mock 覆盖默认空实现，onCopy/onClose 为 jest.fn */
const setupPane = (
  credOver: Record<string, any> = {},
  credentialData: any = null,
  serviceOver: Record<string, any> = {},
) => {
  const service = {
    toggleCredentialFavorite: jest.fn(),
    deleteCredential: jest.fn(),
    getTotpCode: jest.fn(),
    getCredentialHistory: jest.fn().mockResolvedValue([]),
    // 默认返回永不 resolve 的 promise：挂载期拉取不产生 setState，
    // 同步收尾的旧用例不受影响（悬挂 promise 卸载后无害）；附件用例
    // 显式传 mockResolvedValue 并用 findBy/act 收尾
    listAttachments: jest.fn(() => new Promise(() => {})),
    attachFileToCredential: jest.fn(),
    saveAttachmentToFile: jest.fn().mockResolvedValue(true),
    deleteAttachment: jest.fn().mockResolvedValue(true),
    ...serviceOver,
  };
  (usePersonaService as jest.Mock).mockReturnValue(service);
  const onCopy = jest.fn();
  const onClose = jest.fn();
  render(
    <CredentialDetailPane
      credential={makeCred(credOver) as any}
      credentialData={credentialData}
      onClose={onClose}
      onCopy={onCopy}
    />,
  );
  return { service, onCopy, onClose };
};

/** 点击紧挨着给定文本右侧的复制按钮（URL 行可能还有 Fetch icon 按钮，
 * 因此按复制按钮的 aria-label 定位，而不是 flex 容器里的第一个 button） */
const clickCopyNextTo = (text: string) => {
  const btn = screen
    .getByText(text)
    .parentElement!.querySelector('button[aria-label^="Copy"]');
  fireEvent.click(btn!);
};

describe('components/CredentialDetailPane', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      faviconCache: {},
      faviconMisses: {},
    });
  });

  it('shows a loading hint while credential data has not arrived', () => {
    setupPane({ name: 'Loading' }, null);
    expect(screen.getByTestId('detail-loading')).toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();
  });

  it('renders nothing in the body when detail data is missing its payload', () => {
    setupPane({ name: 'Broken' }, { credential_type: 'Password' });
    // credentialData 存在但无 data：不显示 loading，也不渲染任何字段
    expect(screen.queryByTestId('detail-loading')).not.toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument(); // 头部/元数据不受影响
  });

  it('shows last used and created dates in the metadata footer', () => {
    setupPane({ name: 'Meta', last_accessed: '2024-05-06T00:00:00Z' }, null);
    expect(screen.getByText(/Last used:/).textContent).toMatch(/2024/);
    expect(screen.getByText(/Created:/).textContent).toMatch(/2023/);
  });

  it('toggles favorite and keeps state when the service returns null', async () => {
    const toggleCredentialFavorite = jest.fn()
      .mockResolvedValueOnce({ is_favorite: true })
      .mockResolvedValueOnce({ is_favorite: false })
      .mockResolvedValueOnce(null);
    setupPane({}, null, { toggleCredentialFavorite });

    fireEvent.click(screen.getByTitle('Favorite'));
    await act(async () => {});
    expect(toggleCredentialFavorite).toHaveBeenCalledWith('c1');
    expect(screen.getByTitle('Unfavorite')).toBeInTheDocument();

    fireEvent.click(screen.getByTitle('Unfavorite'));
    await act(async () => {});
    expect(screen.getByTitle('Favorite')).toBeInTheDocument();

    // favorite 返回空（如失败）：状态不翻转、不崩
    fireEvent.click(screen.getByTitle('Favorite'));
    await act(async () => {});
    expect(screen.getByTitle('Favorite')).toBeInTheDocument();
  });

  it('Password pane: renders fields, copies url/username/email and closes', () => {
    const { onCopy, onClose } = setupPane(
      { name: 'Site', url: 'https://site.com', username: 'bob', notes: 'my note', tags: ['zebra'] },
      { credential_type: 'Password', data: { email: 'a@b.com', password: 'x' } },
    );

    expect(screen.getByText('a@b.com')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-password')).toBeInTheDocument(); // 密码走 reveal 流程
    expect(screen.getByText('my note')).toBeInTheDocument();
    expect(screen.getByText('zebra')).toBeInTheDocument();

    clickCopyNextTo('https://site.com');
    expect(onCopy).toHaveBeenCalledWith('https://site.com', 'URL');

    clickCopyNextTo('bob');
    expect(onCopy).toHaveBeenCalledWith('bob', 'Username');

    clickCopyNextTo('a@b.com');
    expect(onCopy).toHaveBeenCalledWith('a@b.com', 'Email');

    fireEvent.click(screen.getByTitle('Close'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('CryptoWallet pane: renders wallet fields and copies the address', () => {
    const { onCopy } = setupPane(
      { name: 'Cold', credential_type: 'CryptoWallet' },
      {
        credential_type: 'CryptoWallet',
        data: { wallet_type: 'MetaMask', address: '0xabc123', network: 'Ethereum' },
      },
    );

    expect(screen.getByText('MetaMask')).toBeInTheDocument();
    expect(screen.getByText('0xabc123')).toBeInTheDocument();
    expect(screen.getByText('Ethereum')).toBeInTheDocument();

    clickCopyNextTo('0xabc123');
    expect(onCopy).toHaveBeenCalledWith('0xabc123', 'Address');
  });

  it('SshKey pane: renders key material with three reveal seams', () => {
    const { onCopy } = setupPane(
      { name: 'Server key', credential_type: 'SshKey' },
      {
        credential_type: 'SshKey',
        data: { key_type: 'ed25519', public_key: 'ssh-ed25519 AAA' },
      },
    );

    expect(screen.getByText('ed25519')).toBeInTheDocument();
    expect(screen.getByText('ssh-ed25519 AAA')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-ssh_private_key')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-ssh_passphrase')).toBeInTheDocument();

    clickCopyNextTo('ssh-ed25519 AAA');
    expect(onCopy).toHaveBeenCalledWith('ssh-ed25519 AAA', 'Public key');
  });

  it('ApiKey pane: renders three reveal seams, permissions and expiry', () => {
    setupPane(
      { name: 'API', credential_type: 'ApiKey' },
      {
        credential_type: 'ApiKey',
        data: {
          permissions: ['read', 'write'],
          expires_at: '2030-01-01T00:00:00Z',
        },
      },
    );

    expect(screen.getByTestId('reveal-api_key')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-api_secret')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-token')).toBeInTheDocument();
    expect(screen.getByText('read')).toBeInTheDocument();
    expect(screen.getByText('write')).toBeInTheDocument();
    expect(screen.getByText(/2030/)).toBeInTheDocument();
  });

  it('BankCard pane: renders masked number and card fields', () => {
    setupPane(
      { name: 'Card', credential_type: 'BankCard' },
      {
        credential_type: 'BankCard',
        data: { cardholder_name: 'C. Ui', bank_name: 'Test Bank', last4: '4242', expiry_date: '09/29' },
      },
    );

    expect(screen.getByText('C. Ui')).toBeInTheDocument();
    expect(screen.getByText('Test Bank')).toBeInTheDocument();
    expect(screen.getByText('•••• •••• •••• 4242')).toBeInTheDocument();
    expect(screen.getByText('09/29')).toBeInTheDocument();
  });

  it('unknown credential types fall back to the encrypted notice', () => {
    setupPane(
      { name: 'Mystery', credential_type: 'Custom' },
      { credential_type: 'Custom', data: { body: 'whatever' } },
    );
    expect(screen.getByText('Credential data is encrypted and secure.')).toBeInTheDocument();
  });

  it('SecureNote pane renders the multi-line body verbatim and copies it', () => {
    const { onCopy } = setupPane(
      { name: 'Recovery codes', credential_type: 'SecureNote' },
      { credential_type: 'SecureNote', data: { note: '1111-2222\n3333-4444' } },
    );

    // pre 块按原样保留换行（getByText 默认空白归一化会吃掉 \n，
    // 这里对 textContent 做精确断言）
    const pre = screen.getByText(
      (_, element) =>
        element?.tagName === 'PRE' && element.textContent === '1111-2222\n3333-4444',
    );
    expect(pre.tagName).toBe('PRE');

    fireEvent.click(screen.getByRole('button', { name: 'Copy Note' }));
    expect(onCopy).toHaveBeenCalledWith('1111-2222\n3333-4444', 'Note');
  });

  it('Identity pane renders present fields, hides empty ones, and copies document numbers', () => {
    const { onCopy } = setupPane(
      { name: 'Passport (main)', credential_type: 'Identity' },
      {
        credential_type: 'Identity',
        data: {
          first_name: 'Alice',
          last_name: 'Zhang',
          email: 'alice@example.com',
          phone: '+86 13800000000',
          birthday: undefined,
          address: '1 Main St\nBeijing',
          id_number: '110101199001310011',
          passport_number: undefined,
          driver_license: undefined,
          tax_id: undefined,
          organization: 'Example Inc',
          job_title: undefined,
        },
      },
    );

    expect(screen.getByText('Alice Zhang')).toBeInTheDocument();
    expect(screen.getByText('110101199001310011')).toBeInTheDocument();
    // 多行地址对 textContent 精确断言（getByText 会归一化换行；限定 span
    // 避免命中逐层相同 textContent 的外层容器）
    expect(
      screen.getByText(
        (_, el) => el?.tagName === 'SPAN' && el.textContent === '1 Main St\nBeijing',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('Example Inc')).toBeInTheDocument();
    // 未提供的字段整行不渲染（birthday / passport / job title 缺席）
    expect(screen.queryByText('Birthday')).not.toBeInTheDocument();
    expect(screen.queryByText('Passport no.')).not.toBeInTheDocument();
    expect(screen.queryByText('Job title')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Copy ID number' }));
    expect(onCopy).toHaveBeenCalledWith('110101199001310011', 'ID number');
  });

  it('SoftwareLicense pane renders the key with metadata and copies it', () => {
    const { onCopy } = setupPane(
      { name: 'JetBrains All Products', credential_type: 'SoftwareLicense' },
      {
        credential_type: 'SoftwareLicense',
        data: {
          license_key: 'AAAA-BBBB-CCCC-DDDD',
          version: '2024.2',
          publisher: 'JetBrains',
          seats: 3,
          valid_until: '2027-05-01',
        },
      },
    );

    expect(screen.getByText('AAAA-BBBB-CCCC-DDDD')).toBeInTheDocument();
    expect(screen.getByText('2024.2')).toBeInTheDocument();
    expect(screen.getByText('JetBrains')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('2027-05-01')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Copy License key' }));
    expect(onCopy).toHaveBeenCalledWith('AAAA-BBBB-CCCC-DDDD', 'License key');
  });

  it('item history: lazy-loads the timeline on expand and renders field diffs', async () => {
    const getCredentialHistory = jest.fn().mockResolvedValue([
      {
        id: 'h2',
        entity_id: 'c1',
        change_type: 'updated',
        version: 2,
        timestamp: '2026-09-20T10:00:00Z',
        changes: [
          { field: 'encrypted_data', old_value: '<encrypted>', new_value: '<encrypted>' },
          { field: 'username', old_value: '', new_value: 'alice' },
        ],
      },
      {
        id: 'h1',
        entity_id: 'c1',
        change_type: 'created',
        version: 1,
        timestamp: '2026-09-19T09:00:00Z',
        changes: [],
      },
    ]);
    setupPane(
      { name: 'Gmail', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { getCredentialHistory },
    );

    // 折叠态不预取
    expect(getCredentialHistory).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByTestId('history-toggle'));
    });

    expect(await screen.findByText('v2 · updated')).toBeInTheDocument();
    expect(getCredentialHistory).toHaveBeenCalledWith('c1');
    // 字段 diff：old 为空展示 (empty)，密文变化只出现占位
    expect(screen.getByText(/\(empty\)/)).toBeInTheDocument();
    expect(
      screen.getAllByText(/<encrypted>/).length,
    ).toBeGreaterThanOrEqual(2);
    // created 行（无字段 diff）也在时间线上
    expect(screen.getByText('v1 · created')).toBeInTheDocument();
  });

  it('item history: empty timeline shows the no-changes notice', async () => {
    setupPane(
      { name: 'Fresh', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId('history-toggle'));
    });

    expect(await screen.findByText('No recorded changes.')).toBeInTheDocument();
  });

  it('attachments: loads on mount and renders filename, size and encrypted marker', async () => {
    const listAttachments = jest.fn().mockResolvedValue([
      {
        id: 'a1',
        credential_id: 'c1',
        filename: 'recovery-codes.txt',
        mime_type: 'text/plain',
        size: 2048,
        is_encrypted: true,
        content_hash: 'deadbeef',
        created_at: '2026-09-20T00:00:00Z',
      },
    ]);
    setupPane(
      { name: 'With Attachment', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { listAttachments },
    );

    expect(await screen.findByText('recovery-codes.txt')).toBeInTheDocument();
    expect(listAttachments).toHaveBeenCalledWith('c1');
    // 大小（2 KB）与加密标记
    expect(screen.getByText(/2\.0 KB/)).toBeInTheDocument();
    expect(screen.getByText(/encrypted/)).toBeInTheDocument();
    expect(screen.getByTestId('attachment-save-a1')).toBeInTheDocument();
    expect(screen.getByTestId('attachment-delete-a1')).toBeInTheDocument();
  });

  it('attachments: empty state explains item-key encryption', async () => {
    setupPane(
      { name: 'Bare', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
    );

    expect(
      await screen.findByText(/No attachments\. Files are encrypted with this item's key\./),
    ).toBeInTheDocument();
  });

  it('attachments: Add File picks via native dialog, attaches encrypted and appends', async () => {
    const attachFileToCredential = jest
      .fn()
      .mockResolvedValue({
        id: 'a9',
        credential_id: 'c1',
        filename: 'picked.bin',
        mime_type: 'application/octet-stream',
        size: 10,
        is_encrypted: true,
        content_hash: 'x',
        created_at: '2026-09-20T00:00:00Z',
      });
    setupPane(
      { name: 'Attach Flow', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { attachFileToCredential },
    );

    (openDialog as jest.Mock).mockResolvedValue('/tmp/picked.bin');
    await act(async () => {
      fireEvent.click(screen.getByTestId('attachment-add'));
    });

    expect(await screen.findByText('picked.bin')).toBeInTheDocument();
    expect(openDialog).toHaveBeenCalledWith(expect.objectContaining({ multiple: false }));
    expect(attachFileToCredential).toHaveBeenCalledWith('c1', '/tmp/picked.bin', true);
  });

  it('attachments: canceling the picker never calls attach', async () => {
    const attachFileToCredential = jest.fn();
    setupPane(
      { name: 'Cancel Flow', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { attachFileToCredential },
    );

    (openDialog as jest.Mock).mockResolvedValue(null);
    await act(async () => {
      fireEvent.click(screen.getByTestId('attachment-add'));
    });

    expect(attachFileToCredential).not.toHaveBeenCalled();
  });

  it('attachments: Save goes through the native save dialog and decrypts to disk', async () => {
    const saveAttachmentToFile = jest.fn().mockResolvedValue(true);
    const listAttachments = jest.fn().mockResolvedValue([
      {
        id: 'a1',
        credential_id: 'c1',
        filename: 'doc.pdf',
        mime_type: 'application/pdf',
        size: 500,
        is_encrypted: true,
        content_hash: 'h',
        created_at: '2026-09-20T00:00:00Z',
      },
    ]);
    setupPane(
      { name: 'Save Flow', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { listAttachments, saveAttachmentToFile },
    );

    (saveDialog as jest.Mock).mockResolvedValue('/tmp/out/doc.pdf');
    await screen.findByText('doc.pdf');
    await act(async () => {
      fireEvent.click(screen.getByTestId('attachment-save-a1'));
    });

    expect(saveDialog).toHaveBeenCalledWith(
      expect.objectContaining({ defaultPath: 'doc.pdf' }),
    );
    expect(saveAttachmentToFile).toHaveBeenCalledWith('a1', '/tmp/out/doc.pdf');
  });

  it('attachments: Delete confirms, removes from the list on success', async () => {
    const deleteAttachment = jest.fn().mockResolvedValue(true);
    const listAttachments = jest.fn().mockResolvedValue([
      {
        id: 'a1',
        credential_id: 'c1',
        filename: 'gone.txt',
        mime_type: 'text/plain',
        size: 3,
        is_encrypted: true,
        content_hash: 'h',
        created_at: '2026-09-20T00:00:00Z',
      },
    ]);
    setupPane(
      { name: 'Delete Flow', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { listAttachments, deleteAttachment },
    );

    await screen.findByText('gone.txt');
    jest.spyOn(window, 'confirm').mockReturnValue(true);
    await act(async () => {
      fireEvent.click(screen.getByTestId('attachment-delete-a1'));
    });

    expect(deleteAttachment).toHaveBeenCalledWith('a1');
    expect(await screen.findByText(/No attachments\./)).toBeInTheDocument();
  });

  it('TwoFactor pane: shows the live code, copies it and refreshes on demand', async () => {
    const getTotpCode = jest.fn()
      .mockResolvedValueOnce({ code: 'AAA111', remaining_seconds: 30 })
      .mockResolvedValueOnce({ code: 'BBB222', remaining_seconds: 60 });

    const { onCopy } = setupPane(
      { name: '2FA', credential_type: 'TwoFactor' },
      { credential_type: 'TwoFactor', data: { issuer: 'GitHub', account_name: 'me@example.com' } },
      { getTotpCode },
    );

    expect(await screen.findByText('AAA111')).toBeInTheDocument();
    expect(screen.getByText('Expires in 30s')).toBeInTheDocument();
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('me@example.com')).toBeInTheDocument();

    clickCopyNextTo('AAA111');
    expect(onCopy).toHaveBeenCalledWith('AAA111', 'TOTP');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText('BBB222');
    expect(getTotpCode).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Expires in 60s')).toBeInTheDocument();
  });

  it('TwoFactor pane counts down each second and auto-refreshes at zero', async () => {
    jest.useFakeTimers();
    try {
      const getTotpCode = jest.fn()
        .mockResolvedValueOnce({ code: 'AAA111', remaining_seconds: 2 })
        .mockResolvedValueOnce({ code: 'BBB222', remaining_seconds: 30 });
      setupPane(
        { name: 'Ticker', credential_type: 'TwoFactor' },
        { credential_type: 'TwoFactor', data: {} },
        { getTotpCode },
      );

      // flush：面板挂载 + 首次 refreshTotp
      await act(async () => {});
      expect(screen.getByText('AAA111')).toBeInTheDocument();
      expect(screen.getByText('Expires in 2s')).toBeInTheDocument();

      act(() => {
        jest.advanceTimersByTime(1000);
      });
      expect(screen.getByText('Expires in 1s')).toBeInTheDocument();

      // 归零后自动重新拉取
      act(() => {
        jest.advanceTimersByTime(1000);
      });
      expect(screen.getByText('Expires in 0s')).toBeInTheDocument();

      await act(async () => {});
      expect(screen.getByText('BBB222')).toBeInTheDocument();
      expect(screen.getByText('Expires in 30s')).toBeInTheDocument();
      expect(getTotpCode).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('delete flow: cancel keeps the pane, confirm+ok calls onClose', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const deleteCredential = jest.fn().mockResolvedValue(true);

    const { onClose } = setupPane({ name: 'Victim' }, null, { deleteCredential });

    // 取消确认：不删除，面板保留
    fireEvent.click(screen.getByTitle('Delete'));
    expect(confirmSpy).toHaveBeenCalledWith(
      'Delete "Victim"? This cannot be undone.',
    );
    expect(deleteCredential).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();

    // 确认但后端返回 false：面板同样保留
    confirmSpy.mockReturnValue(true);
    (deleteCredential as jest.Mock).mockResolvedValue(false);
    fireEvent.click(screen.getByTitle('Delete'));
    await act(async () => {});
    expect(deleteCredential).toHaveBeenCalledWith('c1');
    expect(onClose).not.toHaveBeenCalled();

    // 确认且成功：onClose 被调（由父组件清空选中）
    (deleteCredential as jest.Mock).mockResolvedValue(true);
    fireEvent.click(screen.getByTitle('Delete'));
    await act(async () => {});
    expect(onClose).toHaveBeenCalledTimes(1);
    confirmSpy.mockRestore();
  });

  it('hides the fetch-icon button and favicon img when the flag is off', () => {
    setupPane({ url: 'https://site.com' });
    expect(screen.queryByTestId('fetch-favicon')).not.toBeInTheDocument();
    expect(screen.queryByTestId('favicon-img')).not.toBeInTheDocument();
  });

  it('fetches the icon on demand when the flag is on', async () => {
    const fetchFavicon = jest
      .fn()
      .mockResolvedValue({ host: 'site.com', mime_type: 'image/png', data: 'AAA' });
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
    });
    setupPane({ url: 'https://site.com' }, null, { fetchFavicon });

    const btn = screen.getByTestId('fetch-favicon');
    fireEvent.click(btn);
    await act(async () => {});
    expect(fetchFavicon).toHaveBeenCalledWith('c1');
  });

  it('renders a cached favicon in place of the static icon', () => {
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS, fetch_favicons: true },
      faviconCache: { 'site.com': { mime_type: 'image/png', data: 'AAA' } },
    });
    setupPane({ url: 'https://site.com' });

    // 头部图标被 favicon 替换（无 url 字段的静态图标不受影响）
    const img = screen.getByTestId('favicon-img');
    expect(img).toHaveAttribute('src', 'data:image/png;base64,AAA');

    // 破图回退：onError 后回到静态 heroicon
    fireEvent.error(img);
    expect(screen.queryByTestId('favicon-img')).not.toBeInTheDocument();
  });
});
