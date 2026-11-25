import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialDetailPane from './CredentialDetailPane';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import toast from 'react-hot-toast';
import { copyToClipboardWithToast } from '@/utils/clipboard';

const mockTauriWriteText = jest.fn();
const mockTauriReadText = jest.fn();

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

// The copy-failure toast cases go through the real copyToClipboardWithToast: the primary write path (tauri plugin)
// is intercepted here, while the navigator.clipboard / execCommand fallbacks are mocked per case
jest.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: (...args: any[]) => mockTauriWriteText(...args),
  readText: (...args: any[]) => mockTauriReadText(...args),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
  Toaster: () => null,
}));

// The native file dialog only triggers on an Add File / save click; stubbed out under jsdom
jest.mock('@tauri-apps/plugin-dialog', () => ({
  open: jest.fn(),
  save: jest.fn(),
}));

// With the flag on the pane mounts useFavicons to prefetch; the IPC is stubbed here (the cache-hit path has its own dedicated test)
jest.mock('@/utils/api', () => ({
  personaAPI: {
    getFavicons: jest.fn().mockResolvedValue({ success: true, data: [] }),
  },
}));

// The reveal retry choreography is tested separately; here the render is stubbed and the field argument exposed
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

/** Renders the pane driven directly by props; the service mock overrides the default empty implementation, onCopy/onClose are jest.fn
 *  (onCopyOverride: injects the real copyToClipboardWithToast for the copy-failure toast cases) */
const setupPane = (
  credOver: Record<string, any> = {},
  credentialData: any = null,
  serviceOver: Record<string, any> = {},
  onCopyOverride?: (text: string, label: string) => void,
) => {
  const service = {
    toggleCredentialFavorite: jest.fn(),
    deleteCredential: jest.fn(),
    getTotpCode: jest.fn(),
    getCredentialHistory: jest.fn().mockResolvedValue([]),
    // By default return a promise that never resolves: the mount-time fetch produces no setState,
    // older cases that finish synchronously are unaffected (a dangling promise is harmless after unmount);
    // attachment cases pass mockResolvedValue explicitly and wrap up with findBy/act
    listAttachments: jest.fn(() => new Promise(() => {})),
    // Same policy for custom fields: dangling by default, dedicated cases pass mockResolvedValue explicitly and finish with findBy
    getCredentialCustomFields: jest.fn(() => new Promise(() => {})),
    attachFileToCredential: jest.fn(),
    saveAttachmentToFile: jest.fn().mockResolvedValue(true),
    deleteAttachment: jest.fn().mockResolvedValue(true),
    restoreCredentialVersion: jest.fn().mockResolvedValue(null),
    ...serviceOver,
  };
  (usePersonaService as jest.Mock).mockReturnValue(service);
  const onCopy = onCopyOverride ?? jest.fn();
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

/** Clicks the copy button right next to the given text (the URL row may also carry a Fetch icon button,
 * so the copy button is located by its aria-label rather than the first button in the flex container) */
const clickCopyNextTo = (text: string) => {
  const btn = screen
    .getByText(text)
    .parentElement!.querySelector('button[aria-label^="复制"]');
  fireEvent.click(btn!);
};

describe('components/CredentialDetailPane', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useAppStore.setState({
      featureFlags: { ...DEFAULT_FEATURE_FLAGS },
      faviconCache: {},
      faviconMisses: {},
      editingCredential: null,
    });
  });

  it('shows a loading hint while credential data has not arrived', () => {
    setupPane({ name: 'Loading' }, null);
    expect(screen.getByTestId('detail-loading')).toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();
  });

  it('renders nothing in the body when detail data is missing its payload', () => {
    setupPane({ name: 'Broken' }, { credential_type: 'Password' });
    // credentialData exists but has no data: no loading state and no fields rendered
    expect(screen.queryByTestId('detail-loading')).not.toBeInTheDocument();
    expect(screen.queryByTestId('reveal-password')).not.toBeInTheDocument();
    expect(screen.getByText('高')).toBeInTheDocument(); // header/metadata unaffected
  });

  it('shows last used and created dates in the metadata footer', () => {
    setupPane({ name: 'Meta', last_accessed: '2024-05-06T00:00:00Z' }, null);
    expect(screen.getByText(/最近使用/).textContent).toMatch(/2024/);
    expect(screen.getByText(/创建于/).textContent).toMatch(/2023/);
  });

  it('toggles favorite and keeps state when the service returns null', async () => {
    const toggleCredentialFavorite = jest.fn()
      .mockResolvedValueOnce({ is_favorite: true })
      .mockResolvedValueOnce({ is_favorite: false })
      .mockResolvedValueOnce(null);
    setupPane({}, null, { toggleCredentialFavorite });

    fireEvent.click(screen.getByTitle('收藏'));
    await act(async () => {});
    expect(toggleCredentialFavorite).toHaveBeenCalledWith('c1');
    expect(screen.getByTitle('取消收藏')).toBeInTheDocument();

    fireEvent.click(screen.getByTitle('取消收藏'));
    await act(async () => {});
    expect(screen.getByTitle('收藏')).toBeInTheDocument();

    // favorite returns empty (e.g. on failure): state does not flip and nothing crashes
    fireEvent.click(screen.getByTitle('收藏'));
    await act(async () => {});
    expect(screen.getByTitle('收藏')).toBeInTheDocument();
  });

  it('Password pane: renders fields, copies url/username/email and closes', () => {
    const { onCopy, onClose } = setupPane(
      { name: '站点', url: 'https://site.com', username: 'bob', notes: 'my note', tags: ['zebra'] },
      { credential_type: 'Password', data: { email: 'a@b.com', password: 'x' } },
    );

    expect(screen.getByText('a@b.com')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-password')).toBeInTheDocument(); // the password goes through the reveal flow
    expect(screen.getByText('my note')).toBeInTheDocument();
    expect(screen.getByText('zebra')).toBeInTheDocument();

    clickCopyNextTo('https://site.com');
    expect(onCopy).toHaveBeenCalledWith('https://site.com', 'URL');

    clickCopyNextTo('bob');
    expect(onCopy).toHaveBeenCalledWith('bob', '用户名');

    clickCopyNextTo('a@b.com');
    expect(onCopy).toHaveBeenCalledWith('a@b.com', '邮箱');

    fireEvent.click(screen.getByTitle('关闭'));
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
    expect(onCopy).toHaveBeenCalledWith('0xabc123', '地址');
  });

  it('CryptoWallet pane: reveals seed material and copies the public key', () => {
    const { onCopy } = setupPane(
      { name: 'Seed', credential_type: 'CryptoWallet' },
      {
        credential_type: 'CryptoWallet',
        data: {
          wallet_type: 'Bitcoin',
          address: 'bc1qxyz',
          network: 'mainnet',
          mnemonic_phrase: 'abandon ability able',
          bip39_passphrase: 'tungsten',
          private_key: 'L1priv',
          public_key: '02a1b2',
        },
      },
    );

    // The high-sensitivity hint line plus three reveal slots (mnemonic / 25th word / private key)
    expect(screen.getByText(/钱包种子材料为高敏字段/)).toBeInTheDocument();
    expect(screen.getByTestId('reveal-wallet_mnemonic')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-wallet_bip39_passphrase')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-wallet_private_key')).toBeInTheDocument();

    // The public key is not sensitive: shown directly and copyable
    expect(screen.getByText('02a1b2')).toBeInTheDocument();
    clickCopyNextTo('02a1b2');
    expect(onCopy).toHaveBeenCalledWith('02a1b2', '公钥');
  });

  it('CryptoWallet pane: omits seed rows when payload lacks them', () => {
    setupPane(
      { name: 'Bare', credential_type: 'CryptoWallet' },
      {
        credential_type: 'CryptoWallet',
        data: { wallet_type: 'Bitcoin', address: 'bc1qxyz', network: 'mainnet' },
      },
    );

    expect(screen.queryByTestId('reveal-wallet_mnemonic')).not.toBeInTheDocument();
    expect(screen.queryByTestId('reveal-wallet_bip39_passphrase')).not.toBeInTheDocument();
    expect(screen.queryByTestId('reveal-wallet_private_key')).not.toBeInTheDocument();
  });

  it('CryptoWallet pane: item password manager enables then clears the per-item guard', async () => {
    const walletSetItemPassword = jest.fn().mockResolvedValue({ success: true, data: true });
    const walletClearItemPassword = jest.fn().mockResolvedValue({ success: true, data: true });
    (personaAPI as any).walletSetItemPassword = walletSetItemPassword;
    (personaAPI as any).walletClearItemPassword = walletClearItemPassword;

    setupPane(
      { name: 'Guarded', credential_type: 'CryptoWallet' },
      {
        credential_type: 'CryptoWallet',
        data: { wallet_type: 'Bitcoin', address: 'bc1qxyz', network: 'mainnet' },
      },
    );

    // Not enabled: badge plus an enable entry; the form holds two inputs, the new password and the hint
    expect(screen.getByText('未启用')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '启用' }));
    expect(screen.getByPlaceholderText('新条目密码（至少 4 位）')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('密码提示（可选）')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText('新条目密码（至少 4 位）'), {
      target: { value: 'item-pass' },
    });
    fireEvent.change(screen.getByPlaceholderText('密码提示（可选）'), {
      target: { value: 'hint' },
    });
    fireEvent.click(screen.getByRole('button', { name: '启用' }));
    await act(async () => {});
    expect(walletSetItemPassword).toHaveBeenCalledWith('c1', 'item-pass', 'hint');
    expect(toast.success).toHaveBeenCalledWith('条目独立密码已启用');
    expect(screen.getByText('已启用')).toBeInTheDocument();

    // Enabled -> the clear entry swaps in the current-password form
    fireEvent.click(screen.getByRole('button', { name: '清除' }));
    expect(screen.getByPlaceholderText('当前条目密码')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('当前条目密码'), {
      target: { value: 'item-pass' },
    });
    fireEvent.click(screen.getByRole('button', { name: '清除' }));
    await act(async () => {});
    expect(walletClearItemPassword).toHaveBeenCalledWith('c1', 'item-pass');
    expect(toast.success).toHaveBeenCalledWith('条目独立密码已清除');
    expect(screen.getByText('未启用')).toBeInTheDocument();
  });

  it('CryptoWallet pane: item password clear failure surfaces inline, badge stays', async () => {
    (personaAPI as any).walletSetItemPassword = jest.fn();
    (personaAPI as any).walletClearItemPassword = jest
      .fn()
      .mockResolvedValue({ success: false, error: 'Item password is incorrect' });

    setupPane(
      { name: 'Guarded', credential_type: 'CryptoWallet' },
      {
        credential_type: 'CryptoWallet',
        data: {
          wallet_type: 'Bitcoin',
          address: 'bc1qxyz',
          network: 'mainnet',
          item_password_hash: '$argon2id$...',
        },
      },
    );

    // Payload carries a hash -> the badge shows enabled right away
    expect(screen.getByText('已启用')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '清除' }));
    fireEvent.change(screen.getByPlaceholderText('当前条目密码'), {
      target: { value: 'wrong' },
    });
    fireEvent.click(screen.getByRole('button', { name: '清除' }));
    await act(async () => {});
    expect(screen.getByText('Item password is incorrect')).toBeInTheDocument();
    // Badge unchanged and the form is kept for retry
    expect(screen.getByText('已启用')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('当前条目密码')).toBeInTheDocument();
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
    expect(onCopy).toHaveBeenCalledWith('ssh-ed25519 AAA', '公钥');
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
    expect(screen.getByText('凭据数据已加密保存。')).toBeInTheDocument();
  });

  it('SecureNote pane renders the multi-line body verbatim and copies it', () => {
    const { onCopy } = setupPane(
      { name: 'Recovery codes', credential_type: 'SecureNote' },
      { credential_type: 'SecureNote', data: { note: '1111-2222\n3333-4444' } },
    );

    // The pre block keeps line breaks verbatim (getByText normalizes whitespace by default and swallows \n,
    // so the assertion here runs against textContent exactly)
    const pre = screen.getByText(
      (_, element) =>
        element?.tagName === 'PRE' && element.textContent === '1111-2222\n3333-4444',
    );
    expect(pre.tagName).toBe('PRE');

    fireEvent.click(screen.getByRole('button', { name: '复制笔记内容' }));
    expect(onCopy).toHaveBeenCalledWith('1111-2222\n3333-4444', '笔记内容');
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
    // The multi-line address is asserted against textContent exactly (getByText normalizes line breaks; scoping
    // to the span avoids matching outer containers with identical textContent at each level)
    expect(
      screen.getByText(
        (_, el) => el?.tagName === 'SPAN' && el.textContent === '1 Main St\nBeijing',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('Example Inc')).toBeInTheDocument();
    // Fields not provided do not render their whole row (birthday / passport / job title absent)
    expect(screen.queryByText('生日')).not.toBeInTheDocument();
    expect(screen.queryByText('护照号')).not.toBeInTheDocument();
    expect(screen.queryByText('职位')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '复制证件号码' }));
    expect(onCopy).toHaveBeenCalledWith('110101199001310011', '证件号码');
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

    fireEvent.click(screen.getByRole('button', { name: '复制许可密钥' }));
    expect(onCopy).toHaveBeenCalledWith('AAAA-BBBB-CCCC-DDDD', '许可密钥');
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

    // No prefetch while collapsed
    expect(getCredentialHistory).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByTestId('history-toggle'));
    });

    expect(await screen.findByText('v2 · updated')).toBeInTheDocument();
    expect(getCredentialHistory).toHaveBeenCalledWith('c1');
    // Field diff: an empty old value renders as (empty); changed secrets show only a placeholder
    expect(screen.getByText(/（空）/)).toBeInTheDocument();
    expect(
      screen.getAllByText(/<encrypted>/).length,
    ).toBeGreaterThanOrEqual(2);
    // The created row (no field diff) is on the timeline too
    expect(screen.getByText('v1 · created')).toBeInTheDocument();
  });

  it('item history: restore button reverts to the chosen version and reloads', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    const restoredCred = { ...makeCred(), name: 'Old name' };
    const restoreCredentialVersion = jest.fn().mockResolvedValue(restoredCred);
    const getCredentialHistory = jest.fn().mockResolvedValue([
      {
        id: 'h1',
        entity_id: 'c1',
        change_type: 'created',
        version: 1,
        timestamp: '2026-09-19T09:00:00Z',
        changes: [],
        restorable: true,
      },
      {
        id: 'h0',
        entity_id: 'c1',
        change_type: 'deleted',
        version: 0,
        timestamp: '2026-09-18T09:00:00Z',
        changes: [],
        restorable: false,
      },
    ]);
    setupPane(
      { name: 'Gmail', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
      { getCredentialHistory, restoreCredentialVersion },
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId('history-toggle'));
    });
    await screen.findByText('v1 · created');

    // Restorable rows have a restore button; non-restorable ones (such as deletion rows) do not
    const buttons = screen.getAllByTestId('history-restore');
    expect(buttons).toHaveLength(1);

    await act(async () => {
      fireEvent.click(buttons[0]);
    });
    expect(confirmSpy).toHaveBeenCalled();
    expect(restoreCredentialVersion).toHaveBeenCalledWith('c1', 1);
    // On success the loaded flag resets -> the timeline is fetched again
    expect(getCredentialHistory).toHaveBeenCalledTimes(2);
    confirmSpy.mockRestore();
  });

  it('item history: empty timeline shows the no-changes notice', async () => {
    setupPane(
      { name: 'Fresh', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId('history-toggle'));
    });

    expect(await screen.findByText('暂无变更记录。')).toBeInTheDocument();
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
    // Size (2 KB) and the encrypted marker
    expect(screen.getByText(/2\.0 KB/)).toBeInTheDocument();
    expect(screen.getByText(/已加密/)).toBeInTheDocument();
    expect(screen.getByTestId('attachment-save-a1')).toBeInTheDocument();
    expect(screen.getByTestId('attachment-delete-a1')).toBeInTheDocument();
  });

  it('attachments: empty state explains item-key encryption', async () => {
    setupPane(
      { name: 'Bare', credential_type: 'Password' },
      { credential_type: 'Password', data: {} },
    );

    expect(
      await screen.findByText(/文件均用该条目的密钥加密/),
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
    expect(await screen.findByText(/暂无附件/)).toBeInTheDocument();
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
    expect(screen.getByText('30 秒后过期')).toBeInTheDocument();
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('me@example.com')).toBeInTheDocument();

    clickCopyNextTo('AAA111');
    expect(onCopy).toHaveBeenCalledWith('AAA111', 'TOTP 验证码');

    fireEvent.click(screen.getByRole('button', { name: '刷新' }));
    await screen.findByText('BBB222');
    expect(getTotpCode).toHaveBeenCalledTimes(2);
    expect(screen.getByText('60 秒后过期')).toBeInTheDocument();
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

      // Flush: pane mounted plus the first refreshTotp
      await act(async () => {});
      expect(screen.getByText('AAA111')).toBeInTheDocument();
      expect(screen.getByText('2 秒后过期')).toBeInTheDocument();

      act(() => {
        jest.advanceTimersByTime(1000);
      });
      expect(screen.getByText('1 秒后过期')).toBeInTheDocument();

      // After reaching zero it refetches automatically
      act(() => {
        jest.advanceTimersByTime(1000);
      });
      expect(screen.getByText('0 秒后过期')).toBeInTheDocument();

      await act(async () => {});
      expect(screen.getByText('BBB222')).toBeInTheDocument();
      expect(screen.getByText('30 秒后过期')).toBeInTheDocument();
      expect(getTotpCode).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('delete flow: cancel keeps the pane, confirm+ok calls onClose', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const deleteCredential = jest.fn().mockResolvedValue(true);

    const { onClose } = setupPane({ name: 'Victim' }, null, { deleteCredential });

    // Confirmation cancelled: nothing deleted and the pane stays
    fireEvent.click(screen.getByTitle('删除'));
    expect(confirmSpy).toHaveBeenCalledWith(
      '删除「Victim」？此操作不可撤销。',
    );
    expect(deleteCredential).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();

    // Confirmed but the backend returns false: the pane likewise stays
    confirmSpy.mockReturnValue(true);
    (deleteCredential as jest.Mock).mockResolvedValue(false);
    fireEvent.click(screen.getByTitle('删除'));
    await act(async () => {});
    expect(deleteCredential).toHaveBeenCalledWith('c1');
    expect(onClose).not.toHaveBeenCalled();

    // Confirmed and successful: onClose is called (the parent clears the selection)
    (deleteCredential as jest.Mock).mockResolvedValue(true);
    fireEvent.click(screen.getByTitle('删除'));
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

    // The header icon is replaced by the favicon (static icons without a url field are unaffected)
    const img = screen.getByTestId('favicon-img');
    expect(img).toHaveAttribute('src', 'data:image/png;base64,AAA');

    // Broken-image fallback: after onError it reverts to the static heroicon
    fireEvent.error(img);
    expect(screen.queryByTestId('favicon-img')).not.toBeInTheDocument();
  });

  // ------------------------------------------------------------------
  // Edit entry: the Edit button writes the credential plus the pane's already-decrypted payload into the store
  // ------------------------------------------------------------------
  it('writes credential and decrypted payload to the store on Edit', () => {
    const payload = { credential_type: 'Password', data: { password: 'secret' } };
    setupPane({ name: 'Edit me' }, payload);

    fireEvent.click(screen.getByTestId('edit-credential-button'));

    const editing = useAppStore.getState().editingCredential;
    expect(editing).not.toBeNull();
    expect(editing!.credential.name).toBe('Edit me');
    expect(editing!.credential.id).toBe('c1');
    expect(editing!.data).toEqual(payload);
  });

  it('keeps Edit usable when the payload has not been decrypted yet', () => {
    setupPane({ name: 'No payload' }, null);

    // Editing also works with a null payload (the modal degrades to metadata editing with blank payload fields)
    fireEvent.click(screen.getByTestId('edit-credential-button'));
    const editing = useAppStore.getState().editingCredential;
    expect(editing).not.toBeNull();
    expect(editing!.data).toBeNull();
  });

  it('surfaces the error toast when copying fails end-to-end', async () => {
    // The real clipboard chain (exactly what App passes to the pane): the tauri plugin refuses ->
    // navigator.clipboard unavailable -> execCommand returns false -> failure toast
    setupPane(
      { username: 'bob' },
      { credential_type: 'Password', data: { username: 'bob' } },
      {},
      copyToClipboardWithToast as any,
    );

    mockTauriWriteText.mockRejectedValueOnce(new Error('no backend'));
    document.execCommand = jest.fn().mockReturnValue(false) as any;
    clickCopyNextTo('bob');
    await act(async () => {});
    expect(toast.error).toHaveBeenCalledWith('复制到剪贴板失败');
  });

  it('renders custom fields with concealed masking, reveal and copy', async () => {
    // Structured custom fields (1Password-aligned): text shows in the clear, concealed is
    // masked at the UI layer (the value is already decrypted with the list; masking only guards
    // against shoulder surfing); copying carries the field label
    const { onCopy } = setupPane(
      { name: 'WithFields' },
      null,
      {
        getCredentialCustomFields: jest.fn().mockResolvedValue([
          { id: 'f1', label: 'Server', value: 'db.internal:5432', type: 'text', section: null },
          { id: 'f2', label: 'Recovery code', value: 'abcd-efgh', type: 'concealed', section: null },
        ]),
      },
    );

    await screen.findByTestId('custom-fields-section');
    expect(screen.getByTestId('custom-field-value-f1')).toHaveTextContent('db.internal:5432');
    // concealed is masked by default
    expect(screen.getByTestId('custom-field-value-f2')).toHaveTextContent('••••••••');
    expect(screen.getByTestId('custom-field-value-f2')).not.toHaveTextContent('abcd-efgh');

    // Toggle between the visible and hidden states
    fireEvent.click(screen.getByTestId('custom-field-reveal-f2'));
    expect(screen.getByTestId('custom-field-value-f2')).toHaveTextContent('abcd-efgh');
    fireEvent.click(screen.getByTestId('custom-field-reveal-f2'));
    expect(screen.getByTestId('custom-field-value-f2')).toHaveTextContent('••••••••');

    // Copying goes through onCopy, carrying the field label
    fireEvent.click(screen.getByTestId('custom-field-copy-f2'));
    expect(onCopy).toHaveBeenCalledWith('abcd-efgh', 'Recovery code');
  });

  it('hides the custom fields section for credentials without fields', async () => {
    setupPane({ name: 'NoFields' }, null, {
      getCredentialCustomFields: jest.fn().mockResolvedValue([]),
    });

    await act(async () => {});
    expect(screen.queryByTestId('custom-fields-section')).not.toBeInTheDocument();
  });

  it('shows an error line when custom fields fail to load (no fake empty state)', async () => {
    // A read failure (e.g. the vault is locked) must show the error row honestly, never masquerading as "no fields"
    setupPane({ name: 'Locked' }, null, {
      getCredentialCustomFields: jest.fn().mockResolvedValue(null),
    });

    const err = await screen.findByTestId('custom-fields-error');
    expect(err).toHaveTextContent('自定义字段读取失败');
    expect(screen.queryByTestId('custom-field-entry')).not.toBeInTheDocument();
  });
});
