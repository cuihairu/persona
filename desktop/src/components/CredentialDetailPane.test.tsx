import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialDetailPane from './CredentialDetailPane';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
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
