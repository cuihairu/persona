import { act, fireEvent, render, screen } from '@testing-library/react';
import CredentialList, { filterCredentials } from './CredentialList';
import { usePersonaService } from '@/hooks/usePersonaService';
import { copyWithAutoClear } from '@/utils/clipboard';
import toast from 'react-hot-toast';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: jest.fn(), error: jest.fn() },
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
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

const setupList = (credentials: any[], serviceOver: Record<string, any> = {}) => {
  const service = {
    credentials,
    currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
    getCredentialData: jest.fn(),
    toggleCredentialFavorite: jest.fn(),
    deleteCredential: jest.fn(),
    getTotpCode: jest.fn(),
    ...serviceOver,
  };
  (usePersonaService as jest.Mock).mockReturnValue(service);
  render(<CredentialList onCreateCredential={() => {}} />);
  return service;
};

/** 打开第一张卡片的详情 modal（默认 credentialData 与列表类型一致、data 为空对象） */
const openModal = async (creds: any[], serviceOver: Record<string, any> = {}) => {
  const service = setupList(creds, {
    getCredentialData: jest.fn().mockResolvedValue({
      credential_type: creds[0].credential_type,
      data: {},
    }),
    ...serviceOver,
  });
  fireEvent.click(screen.getByText(creds[0].name));
  await screen.findByTitle('Close');
  return service;
};

/** 点击紧挨着给定文本右侧的复制按钮（span 与按钮同处一个 flex 容器） */
const clickCopyNextTo = (text: string) => {
  const btn = screen.getByText(text).parentElement!.querySelector('button');
  fireEvent.click(btn!);
};

describe('filterCredentials (pure)', () => {
  const creds = [
    makeCred({ id: '1', name: 'GitHub Login', credential_type: 'Password', tags: ['work'], is_favorite: true }),
    makeCred({ id: '2', name: 'Stripe Key', credential_type: 'ApiKey', tags: ['dev'] }),
  ];

  it('filters by query across name and type, case-insensitively', () => {
    expect(filterCredentials(creds, { query: 'git' }).map((c) => c.id)).toEqual(['1']);
    expect(filterCredentials(creds, { query: 'APIKEY' }).map((c) => c.id)).toEqual(['2']);
    expect(filterCredentials(creds, { query: 'nope' })).toEqual([]);
    expect(filterCredentials(creds, {})).toHaveLength(2);
  });

  it('combines type, tag and favorites dimensions with AND', () => {
    expect(filterCredentials(creds, { types: new Set(['Password']) }).map((c) => c.id)).toEqual(['1']);
    expect(filterCredentials(creds, { tags: new Set(['dev']) }).map((c) => c.id)).toEqual(['2']);
    expect(filterCredentials(creds, { favoritesOnly: true }).map((c) => c.id)).toEqual(['1']);
    // 命中 query + type 才保留
    expect(filterCredentials(creds, { query: 'git', types: new Set(['ApiKey']) })).toEqual([]);
    // 空集合 = 不过滤
    expect(filterCredentials(creds, { types: new Set(), tags: new Set() })).toHaveLength(2);
  });
});

describe('components/CredentialList', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (copyWithAutoClear as jest.Mock).mockResolvedValue(true);
  });

  it('renders placeholder when no identity selected', () => {
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: null,
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={() => {}} />);
    expect(screen.getByText('Select an identity to view credentials')).toBeInTheDocument();
  });

  it('shows empty state and calls onCreateCredential', () => {
    const onCreateCredential = jest.fn();
    (usePersonaService as jest.Mock).mockReturnValue({
      credentials: [],
      currentIdentity: { id: 'i1', name: 'Me', identity_type: 'Personal' },
      getCredentialData: jest.fn(),
    });

    render(<CredentialList onCreateCredential={onCreateCredential} />);
    fireEvent.click(screen.getByText('Add Your First Credential'));
    expect(onCreateCredential).toHaveBeenCalledTimes(1);
  });

  it('filters by search query and shows the no-results hint', () => {
    setupList([
      makeCred({ id: '1', name: 'Bank one', credential_type: 'Password' }),
      makeCred({ id: '2', name: 'Keytwo', credential_type: 'ApiKey' }),
    ]);

    // 命中类型名（大小写不敏感）
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: 'api' },
    });
    expect(screen.getByText('1 credential')).toBeInTheDocument();
    expect(screen.getByText('Keytwo')).toBeInTheDocument();
    expect(screen.queryByText('Bank one')).not.toBeInTheDocument();

    // 无结果：提示调整搜索词，且不渲染首建按钮
    fireEvent.change(screen.getByPlaceholderText('Search credentials...'), {
      target: { value: 'zzz' },
    });
    expect(screen.getByText('No credentials found')).toBeInTheDocument();
    expect(screen.getByText('Try adjusting your search terms')).toBeInTheDocument();
    expect(screen.queryByText('Add Your First Credential')).not.toBeInTheDocument();
  });

  it('toggles favorites/type/tag filters and clears them', () => {
    setupList([
      makeCred({ id: '1', name: 'Fav-one', credential_type: 'Password', tags: ['work'], is_favorite: true }),
      makeCred({ id: '2', name: 'Dev-two', credential_type: 'ApiKey', tags: ['dev'] }),
    ]);

    // 仅收藏
    fireEvent.click(screen.getByTestId('filter-favorites'));
    expect(screen.getByText('1 credential')).toBeInTheDocument();
    expect(screen.getByText('Fav-one')).toBeInTheDocument();

    // 收藏 ∩ ApiKey = 空
    fireEvent.click(screen.getByTestId('filter-type-ApiKey'));
    expect(screen.getByText('No credentials found')).toBeInTheDocument();

    // 类型再点一次取消（toggle off），回到仅收藏
    fireEvent.click(screen.getByTestId('filter-type-ApiKey'));
    expect(screen.queryByText('No credentials found')).not.toBeInTheDocument();

    // 清除全部筛选
    fireEvent.click(screen.getByTestId('clear-filters'));
    expect(screen.getByText('2 credentials')).toBeInTheDocument();
    expect(screen.getByText('Dev-two')).toBeInTheDocument();

    // 仅标签
    fireEvent.click(screen.getByTestId('filter-tag-dev'));
    expect(screen.getByText('Dev-two')).toBeInTheDocument();
    expect(screen.queryByText('Fav-one')).not.toBeInTheDocument();
  });

  it('renders card variants: security colors, icons, hostnames and metadata', () => {
    setupList([
      makeCred({ id: 'c1', name: 'N-Critical', credential_type: 'Password', security_level: 'Critical' }),
      makeCred({ id: 'c2', name: 'N-Medium', credential_type: 'CryptoWallet', security_level: 'Medium', url: 'https://wallet.example.com/x' }),
      makeCred({ id: 'c3', name: 'N-Low', credential_type: 'SshKey', security_level: 'Low' }),
      makeCred({ id: 'c4', name: 'N-Weird', credential_type: 'Certificate', security_level: 'Weird', url: 'not-a-url' }),
      makeCred({ id: 'c5', name: 'N-High', credential_type: 'BankCard', security_level: 'High', is_favorite: true, last_accessed: '2024-05-06T00:00:00Z' }),
    ]);

    // 五档安全色（含未知档走 default 灰）
    expect(document.querySelector('.bg-red-100.text-red-800')).not.toBeNull();
    expect(document.querySelector('.bg-orange-100.text-orange-800')).not.toBeNull();
    expect(document.querySelector('.bg-yellow-100.text-yellow-800')).not.toBeNull();
    expect(document.querySelector('.bg-green-100.text-green-800')).not.toBeNull();
    expect(document.querySelector('.bg-gray-100.text-gray-800')).not.toBeNull();

    // 合法 URL 取 hostname；非法 URL 原样回显（catch 分支）
    expect(screen.getByText('wallet.example.com')).toBeInTheDocument();
    expect(screen.getByText('not-a-url')).toBeInTheDocument();

    // 收藏小红心 + 最后使用时间
    expect(document.querySelector('svg.text-red-500')).not.toBeNull();
    expect(screen.getByText(/Last used:/).textContent).toMatch(/2024/);
  });

  it('opens credential modal and toggles favorite', async () => {
    const getCredentialData = jest.fn().mockResolvedValue({
      credential_type: 'Password',
      data: { email: 'a@b.com', password: 'secret' },
    });
    const toggleCredentialFavorite = jest.fn().mockResolvedValue({ is_favorite: true });

    setupList(
      [makeCred({ url: 'https://example.com', username: 'user' })],
      { getCredentialData, toggleCredentialFavorite },
    );

    fireEvent.click(screen.getByText('Example'));
    await screen.findByTitle('Favorite');

    fireEvent.click(screen.getByTitle('Favorite'));
    await act(async () => {});
    expect(toggleCredentialFavorite).toHaveBeenCalledWith('c1');

    // 上一步已切为已收藏：按钮标题变为 Unfavorite
    fireEvent.click(screen.getByTitle('Unfavorite'));
    await act(async () => {});
    expect(toggleCredentialFavorite).toHaveBeenCalledTimes(2);

    // favorite 返回空（如失败）：状态不翻转、不崩
    (toggleCredentialFavorite as jest.Mock).mockResolvedValue(null);
    fireEvent.click(screen.getByTitle('Unfavorite'));
    await act(async () => {});
    expect(screen.getByTitle('Unfavorite')).toBeInTheDocument();
  });

  it('Password modal: renders fields, copies url/username/email and closes', async () => {
    await openModal(
      [makeCred({ name: 'Site', url: 'https://site.com', username: 'bob', notes: 'my note', tags: ['zebra'] })],
      {
        getCredentialData: jest.fn().mockResolvedValue({
          credential_type: 'Password',
          data: { email: 'a@b.com', password: 'x' },
        }),
      },
    );

    expect(await screen.findByText('a@b.com')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-password')).toBeInTheDocument(); // 密码走 reveal 流程
    expect(screen.getByText('my note')).toBeInTheDocument();
    expect(screen.getByText('zebra')).toBeInTheDocument();

    clickCopyNextTo('https://site.com');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('URL copied (clears in 30s)');

    clickCopyNextTo('bob');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('Username copied (clears in 30s)');

    clickCopyNextTo('a@b.com');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('Email copied (clears in 30s)');

    // 复制失败：toast.error
    (copyWithAutoClear as jest.Mock).mockResolvedValueOnce(false);
    clickCopyNextTo('bob');
    await act(async () => {});
    expect(toast.error).toHaveBeenCalledWith('Failed to copy to clipboard');

    fireEvent.click(screen.getByTitle('Close'));
    expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
  });

  it('CryptoWallet modal: renders wallet fields and copies the address', async () => {
    await openModal([makeCred({ name: 'Cold', credential_type: 'CryptoWallet' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'CryptoWallet',
        data: { wallet_type: 'MetaMask', address: '0xabc123', network: 'Ethereum' },
      }),
    });

    expect(await screen.findByText('MetaMask')).toBeInTheDocument();
    expect(screen.getByText('0xabc123')).toBeInTheDocument();
    expect(screen.getByText('Ethereum')).toBeInTheDocument();

    clickCopyNextTo('0xabc123');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('Address copied (clears in 30s)');
  });

  it('SshKey modal: renders key material with three reveal seams', async () => {
    await openModal([makeCred({ name: 'Server key', credential_type: 'SshKey' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'SshKey',
        data: { key_type: 'ed25519', public_key: 'ssh-ed25519 AAA' },
      }),
    });

    expect(await screen.findByText('ed25519')).toBeInTheDocument();
    expect(screen.getByText('ssh-ed25519 AAA')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-ssh_private_key')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-ssh_passphrase')).toBeInTheDocument();

    clickCopyNextTo('ssh-ed25519 AAA');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('Public key copied (clears in 30s)');
  });

  it('ApiKey modal: renders three reveal seams, permissions and expiry', async () => {
    await openModal([makeCred({ name: 'API', credential_type: 'ApiKey' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'ApiKey',
        data: {
          permissions: ['read', 'write'],
          expires_at: '2030-01-01T00:00:00Z',
        },
      }),
    });

    expect(await screen.findByTestId('reveal-api_key')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-api_secret')).toBeInTheDocument();
    expect(screen.getByTestId('reveal-token')).toBeInTheDocument();
    expect(screen.getByText('read')).toBeInTheDocument();
    expect(screen.getByText('write')).toBeInTheDocument();
    expect(screen.getByText(/2030/)).toBeInTheDocument();
  });

  it('BankCard modal: renders masked number and card fields', async () => {
    await openModal([makeCred({ name: 'Card', credential_type: 'BankCard' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'BankCard',
        data: { cardholder_name: 'C. Ui', bank_name: 'Test Bank', last4: '4242', expiry_date: '09/29' },
      }),
    });

    expect(await screen.findByText('C. Ui')).toBeInTheDocument();
    expect(screen.getByText('Test Bank')).toBeInTheDocument();
    expect(screen.getByText('•••• •••• •••• 4242')).toBeInTheDocument();
    expect(screen.getByText('09/29')).toBeInTheDocument();
  });

  it('unknown credential types fall back to the encrypted notice', async () => {
    await openModal([makeCred({ name: 'Note', credential_type: 'SecureNote' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'SecureNote',
        data: { body: 'whatever' },
      }),
    });

    expect(
      await screen.findByText('Credential data is encrypted and secure.'),
    ).toBeInTheDocument();
  });

  it('TwoFactor modal: shows the live code, copies it and refreshes on demand', async () => {
    const getTotpCode = jest.fn()
      .mockResolvedValueOnce({ code: 'AAA111', remaining_seconds: 30 })
      .mockResolvedValueOnce({ code: 'BBB222', remaining_seconds: 60 });

    await openModal([makeCred({ name: '2FA', credential_type: 'TwoFactor' })], {
      getCredentialData: jest.fn().mockResolvedValue({
        credential_type: 'TwoFactor',
        data: { issuer: 'GitHub', account_name: 'me@example.com' },
      }),
      getTotpCode,
    });

    expect(await screen.findByText('AAA111')).toBeInTheDocument();
    expect(screen.getByText('Expires in 30s')).toBeInTheDocument();
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('me@example.com')).toBeInTheDocument();

    clickCopyNextTo('AAA111');
    await act(async () => {});
    expect(toast.success).toHaveBeenCalledWith('TOTP copied (clears in 30s)');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText('BBB222');
    expect(getTotpCode).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Expires in 60s')).toBeInTheDocument();
  });

  it('TwoFactor modal counts down each second and auto-refreshes at zero', async () => {
    jest.useFakeTimers();
    try {
      const getTotpCode = jest.fn()
        .mockResolvedValueOnce({ code: 'AAA111', remaining_seconds: 2 })
        .mockResolvedValueOnce({ code: 'BBB222', remaining_seconds: 30 });
      setupList([makeCred({ name: 'Ticker', credential_type: 'TwoFactor' })], {
        getCredentialData: jest.fn().mockResolvedValue({
          credential_type: 'TwoFactor',
          data: {},
        }),
        getTotpCode,
      });
      fireEvent.click(screen.getByText('Ticker'));

      // flush：modal 挂载 + 首次 refreshTotp
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

  it('delete flow: cancel keeps the modal, confirm+ok closes it', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const deleteCredential = jest.fn().mockResolvedValue(true);

    await openModal([makeCred({ name: 'Victim' })], { deleteCredential });

    // 取消确认：不删除，modal 保留
    fireEvent.click(screen.getByTitle('Delete'));
    expect(confirmSpy).toHaveBeenCalledWith(
      'Delete "Victim"? This cannot be undone.',
    );
    expect(deleteCredential).not.toHaveBeenCalled();
    expect(screen.getByTitle('Close')).toBeInTheDocument();

    // 确认但后端返回 false：modal 同样保留
    confirmSpy.mockReturnValue(true);
    (deleteCredential as jest.Mock).mockResolvedValue(false);
    fireEvent.click(screen.getByTitle('Delete'));
    await act(async () => {});
    expect(deleteCredential).toHaveBeenCalledWith('c1');
    expect(screen.getByTitle('Close')).toBeInTheDocument();

    // 确认且成功：modal 关闭
    (deleteCredential as jest.Mock).mockResolvedValue(true);
    fireEvent.click(screen.getByTitle('Delete'));
    await act(async () => {});
    expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
    confirmSpy.mockRestore();
  });
});
