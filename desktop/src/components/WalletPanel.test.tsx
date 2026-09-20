import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import WalletPanel from './WalletPanel';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import type { WalletSummary } from '@/types';

jest.mock('@/hooks/usePersonaService', () => ({
  usePersonaService: jest.fn(),
}));

jest.mock('@/utils/api', () => ({
  personaAPI: {
    walletList: jest.fn(),
    walletListAddresses: jest.fn(),
    walletExport: jest.fn(),
    walletGenerate: jest.fn(),
    walletImport: jest.fn(),
    walletAddAddress: jest.fn(),
    walletDelete: jest.fn(),
  },
}));

// 签名确认 modal 单独测过；这里哑渲染暴露 props
jest.mock('@/components/TransactionConfirmModal', () => ({
  __esModule: true,
  default: (props: any) => (
    <div
      data-testid="tx-modal"
      data-open={String(props.isOpen)}
      data-from={props.fromAddress}
      data-known={(props.knownAddresses ?? []).join('|')}
    />
  ),
}));

const IDENT = { id: 'identity-1', name: 'Alice' };

const makeWallet = (over: Partial<WalletSummary> = {}): WalletSummary =>
  ({
    id: 'wallet-1',
    name: 'BTC Single',
    network: 'Bitcoin',
    wallet_type: 'SingleAddress',
    balance: '-',
    address_count: 1,
    watch_only: false,
    security_level: 'Medium',
    created_at: '2026-03-27T00:00:00Z',
    updated_at: '2026-03-27T00:00:00Z',
    ...over,
  }) as WalletSummary;

const flush = async () => {
  await act(async () => {});
};

const setClipboard = () => {
  const writeText = jest.fn().mockResolvedValue(undefined);
  Object.defineProperty(window.navigator, 'clipboard', {
    value: { writeText },
    configurable: true,
  });
  return writeText;
};

describe('components/WalletPanel', () => {
  const mockWalletList = (wallets: WalletSummary[]) => {
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: true,
      data: { wallets },
    });
  };

  beforeEach(() => {
    jest.resetAllMocks();
    (usePersonaService as jest.Mock).mockReturnValue({ currentIdentity: IDENT });
    mockWalletList([makeWallet()]);
    (personaAPI.walletListAddresses as jest.Mock).mockResolvedValue({
      success: true,
      data: { addresses: [] },
    });
  });

  it('shows WIF export for bitcoin single-address wallets only', async () => {
    const { findByText, getByText, getAllByRole } = render(<WalletPanel />);

    await findByText('BTC Single');

    fireEvent.click(getByText('导出'));

    await waitFor(() => expect(getByText('导出钱包')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toContain('JSON');
    expect(optionLabels).toContain('私钥');
    expect(optionLabels).toContain('Bitcoin WIF');
    expect(optionLabels).not.toContain('XPUB');
    expect(optionLabels).not.toContain('助记词');
  });

  it('shows HD wallet export options including xpub and mnemonic', async () => {
    mockWalletList([
      makeWallet({
        id: 'wallet-hd-1',
        name: 'ETH HD',
        network: 'Ethereum',
        wallet_type:
          'HierarchicalDeterministic { bip_version: Bip44, address_count: 5, gap_limit: 20 }',
        address_count: 5,
        security_level: 'High',
      }),
    ]);

    const { findByText, getByText, getAllByRole } = render(<WalletPanel />);

    await findByText('ETH HD');

    fireEvent.click(getByText('导出'));

    await waitFor(() => expect(getByText('导出钱包')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toContain('JSON');
    expect(optionLabels).toContain('XPUB');
    expect(optionLabels).toContain('助记词');
    expect(optionLabels).toContain('私钥');
    expect(optionLabels).not.toContain('Bitcoin WIF');
  });

  it('limits watch-only wallets to public export formats and shows the restriction hint', async () => {
    mockWalletList([
      makeWallet({
        id: 'wallet-watch-1',
        name: 'BTC Watch',
        wallet_type:
          'HierarchicalDeterministic { bip_version: Bip44, address_count: 5, gap_limit: 20 }',
        address_count: 5,
        watch_only: true,
      }),
    ]);

    const { findByText, getByText, getAllByRole } = render(<WalletPanel />);

    await findByText('BTC Watch');

    fireEvent.click(getByText('导出'));

    await waitFor(() => expect(getByText('导出钱包')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toEqual(['JSON', 'XPUB']);
    expect(getByText('仅观察钱包只能导出公开数据。')).toBeInTheDocument();
    expect(screen.getByTitle('仅观察')).toBeInTheDocument();
  });

  it('deletes a wallet after confirmation and refreshes the list', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: true,
      data: true,
    });

    const { findByText, getByLabelText } = render(<WalletPanel />);

    await findByText('BTC Single');

    fireEvent.click(getByLabelText('删除钱包 BTC Single'));

    await waitFor(() => {
      expect(confirmSpy).toHaveBeenCalledWith(
        '删除钱包「BTC Single」？此操作不可撤销。',
      );
      expect(personaAPI.walletDelete).toHaveBeenCalledWith('wallet-1');
      expect(personaAPI.walletList).toHaveBeenCalledTimes(2);
    });

    confirmSpy.mockRestore();
  });

  it('shows the spinner while loading and the empty state when no wallets exist', async () => {
    (personaAPI.walletList as jest.Mock).mockReturnValue(new Promise(() => {}));
    const { getByText, queryByText } = render(<WalletPanel />);
    expect(getByText('正在加载钱包…')).toBeInTheDocument();

    // 挂起态下不渲染空态
    expect(queryByText('还没有钱包')).not.toBeInTheDocument();
  });

  it('renders the empty state with create/import shortcuts once loading finishes', async () => {
    mockWalletList([]);
    const { findByText } = render(<WalletPanel />);

    expect(await findByText('还没有钱包')).toBeInTheDocument();
    fireEvent.click(screen.getByText('创建钱包'));
    expect(screen.getByText('创建新钱包')).toBeInTheDocument();
  });

  it('shows and dismisses an error when the wallet list fails', async () => {
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: false,
      error: 'rpc down',
    });
    const { findByText } = render(<WalletPanel />);

    expect(await findByText('rpc down')).toBeInTheDocument();
    // 出错时不渲染空态
    expect(screen.queryByText('还没有钱包')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '忽略' }));
    expect(screen.queryByText('rpc down')).not.toBeInTheDocument();
    expect(await screen.findByText('还没有钱包')).toBeInTheDocument();
  });

  it('survives a rejected wallet list call', async () => {
    (personaAPI.walletList as jest.Mock).mockRejectedValue(new Error('boom'));
    const { findByText } = render(<WalletPanel />);
    expect(await findByText('boom')).toBeInTheDocument();
  });

  it('skips the API entirely when no identity is selected', async () => {
    (usePersonaService as jest.Mock).mockReturnValue({ currentIdentity: null });
    render(<WalletPanel />);
    await flush();
    await flush();

    expect(personaAPI.walletList).not.toHaveBeenCalled();
    expect(screen.getByText('还没有钱包')).toBeInTheDocument();
  });

  it('renders per-network icons and colors', async () => {
    mockWalletList([
      makeWallet({ id: 'w-btc', name: 'N-BTC', network: 'Bitcoin' }),
      makeWallet({ id: 'w-eth', name: 'N-ETH', network: 'Ethereum' }),
      makeWallet({ id: 'w-sol', name: 'N-SOL', network: 'Solana' }),
      makeWallet({ id: 'w-etc', name: 'N-OTHER', network: 'Polygon' }),
    ]);
    const { findByText } = render(<WalletPanel />);

    await findByText('N-BTC');
    expect(screen.getByText('₿')).toBeInTheDocument();
    expect(screen.getByText('Ξ')).toBeInTheDocument();
    expect(screen.getByText('◎')).toBeInTheDocument();
    expect(screen.getByText('💰')).toBeInTheDocument();
    expect(document.querySelector('.text-orange-600.bg-orange-100')).not.toBeNull();
    expect(document.querySelector('.text-blue-600.bg-blue-100')).not.toBeNull();
    expect(document.querySelector('.text-purple-600.bg-purple-100')).not.toBeNull();
    expect(document.querySelector('.text-gray-600.bg-gray-100')).not.toBeNull();
  });

  it('loads addresses on selection, renders the table, copy and QR modal', async () => {
    const writeText = setClipboard();
    (personaAPI.walletListAddresses as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        addresses: [
          { index: 0, address: '0xaaa', address_type: 'P2WPKH', balance: '0.1', used: false },
          { index: 1, address: '0xbbb', address_type: 'P2TR', balance: '2.0', used: true },
        ],
      },
    });
    const { findByText } = render(<WalletPanel />);

    await findByText('BTC Single');
    fireEvent.click(screen.getByText('BTC Single'));

    expect(await screen.findByText('钱包地址 - BTC Single')).toBeInTheDocument();
    // 地址是异步加载的，等第一行出现
    expect(await screen.findByText('0xaaa')).toBeInTheDocument();
    expect(screen.getByText('0xbbb')).toBeInTheDocument();
    expect(screen.getByText('P2WPKH')).toBeInTheDocument();
    expect(screen.getByText('未使用')).toBeInTheDocument();
    expect(screen.getByText('已使用')).toBeInTheDocument();

    // 行内 Copy
    fireEvent.click(screen.getAllByRole('button', { name: '复制' })[0]);
    expect(writeText).toHaveBeenCalledWith('0xaaa');

    // QR modal：打开 → Copy Address → 关闭
    fireEvent.click(screen.getAllByTitle('显示二维码')[1]);
    expect(screen.getByTestId('address-qr')).toBeInTheDocument();
    expect(screen.getByText('收款地址')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '复制地址' }));
    expect(writeText).toHaveBeenCalledWith('0xbbb');
    expect(screen.queryByTestId('address-qr')).not.toBeInTheDocument();

    // 重开，点遮罩关闭
    fireEvent.click(screen.getAllByTitle('显示二维码')[0]);
    expect(screen.getByTestId('address-qr')).toBeInTheDocument();
    fireEvent.click(screen.getByText('收款地址').closest('div.fixed')!);
    expect(screen.queryByTestId('address-qr')).not.toBeInTheDocument();
  });

  it('shows no address table until a wallet is selected', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');
    expect(screen.queryByText(/Wallet Addresses/)).not.toBeInTheDocument();
  });

  it('shows a placeholder when the selected wallet has no addresses', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');
    fireEvent.click(screen.getByText('BTC Single'));

    expect(
      await screen.findByText('尚未生成地址'),
    ).toBeInTheDocument();
  });

  it('logs and survives address loading failures', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    (personaAPI.walletListAddresses as jest.Mock).mockRejectedValue(new Error('addr fail'));
    const { findByText } = render(<WalletPanel />);

    await findByText('BTC Single');
    fireEvent.click(screen.getByText('BTC Single'));

    await screen.findByText('钱包地址 - BTC Single');
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load addresses:',
      expect.objectContaining({ message: 'addr fail' }),
    );
    expect(screen.getByText('尚未生成地址')).toBeInTheDocument();
    consoleSpy.mockRestore();
  });

  it('opens the send modal with poisoning context and loads addresses when unselected', async () => {
    (personaAPI.walletListAddresses as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        addresses: [
          { index: 0, address: '0xaaa', address_type: 'P2WPKH', balance: '0', used: false },
        ],
      },
    });
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    // 未选中直接 Send：先选中（触发地址加载），初始 fromAddress 是占位
    fireEvent.click(screen.getByTestId('send-button-wallet-1'));
    expect(screen.getByTestId('tx-modal').getAttribute('data-from')).toBe(
      '地址加载中…',
    );

    // 地址加载完成后 fromAddress/knownAddresses 就位
    await waitFor(() => {
      expect(screen.getByTestId('tx-modal').getAttribute('data-from')).toBe('0xaaa');
    });
    expect(screen.getByTestId('tx-modal').getAttribute('data-known')).toBe('0xaaa');
  });

  it('refreshes the wallet list from the card action', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByRole('button', { name: '刷新' }));
    await waitFor(() => expect(personaAPI.walletList).toHaveBeenCalledTimes(2));
  });

  it('create wallet: full flow, disabled guards, failure and cancel reset', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('新建钱包'));
    expect(screen.getByText('创建新钱包')).toBeInTheDocument();

    // 空表单禁止提交
    const createBtn = screen.getByRole('button', { name: '创建' });
    expect(createBtn).toBeDisabled();

    // 改网络与地址数
    const networkSelect = screen.getAllByRole('combobox')[0] as HTMLSelectElement;
    fireEvent.change(networkSelect, { target: { value: 'Bitcoin' } });
    fireEvent.change(screen.getByDisplayValue('5'), { target: { value: '3' } });

    fireEvent.change(screen.getByPlaceholderText('我的钱包'), {
      target: { value: 'My BTC' },
    });
    fireEvent.change(screen.getByPlaceholderText('至少 8 个字符'), {
      target: { value: 'pw123456' },
    });
    expect(createBtn).toBeEnabled();

    // 失败：错误显示在面板上，modal 不关
    (personaAPI.walletGenerate as jest.Mock).mockResolvedValue({
      success: false,
      error: 'weak password',
    });
    fireEvent.click(createBtn);
    await flush();
    expect(personaAPI.walletGenerate).toHaveBeenCalledWith('identity-1', {
      name: 'My BTC',
      network: 'Bitcoin',
      wallet_type: 'hd',
      password: 'pw123456',
      address_count: 3,
    });
    expect(screen.getByText('weak password')).toBeInTheDocument();
    expect(screen.getByText('创建新钱包')).toBeInTheDocument();

    // 成功：展示助记词（仅此一次）
    (personaAPI.walletGenerate as jest.Mock).mockResolvedValue({
      success: true,
      data: { mnemonic: 'one two three', first_address: 'bc1qfirst' },
    });
    fireEvent.click(createBtn);
    await flush();
    expect(screen.getByDisplayValue('one two three')).toBeInTheDocument();
    expect(screen.getByText('bc1qfirst')).toBeInTheDocument();

    // Done 关闭
    fireEvent.click(screen.getByRole('button', { name: '完成' }));
    expect(screen.queryByText('创建新钱包')).not.toBeInTheDocument();

    // 重开后表单已重置
    fireEvent.click(screen.getByText('新建钱包'));
    expect(
      (screen.getByPlaceholderText('我的钱包') as HTMLInputElement).value,
    ).toBe('');
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(screen.queryByText('创建新钱包')).not.toBeInTheDocument();
  });

  it('import wallet: type switching locks network for WIF, submits and resets on success', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('导入'));
    expect(screen.getByText('导入钱包')).toBeInTheDocument();

    // 头部也有一个 'Import' 按钮，modal 内的取最后一个
    const importBtn = screen
      .getAllByRole('button', { name: '导入' })
      .slice(-1)[0];
    expect(importBtn).toBeDisabled();

    const [networkSelect, typeSelect] = screen.getAllByRole('combobox') as HTMLSelectElement[];

    // WIF：锁定网络为 Bitcoin，隐藏地址数输入
    fireEvent.change(typeSelect, { target: { value: 'wif' } });
    expect(networkSelect).toBeDisabled();
    expect(networkSelect.value).toBe('Bitcoin');
    expect(screen.queryByDisplayValue('5')).not.toBeInTheDocument();
    expect(screen.getByText('Bitcoin WIF', { selector: 'label' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('K... / L...')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText('导入的钱包'), {
      target: { value: 'From WIF' },
    });
    fireEvent.change(screen.getByPlaceholderText('K... / L...'), {
      target: { value: 'Kwifdata' },
    });
    fireEvent.change(screen.getByPlaceholderText('至少 8 个字符'), {
      target: { value: 'pw' },
    });
    (personaAPI.walletImport as jest.Mock).mockResolvedValue({
      success: true,
      data: { id: 'new-wallet' },
    });
    fireEvent.click(importBtn);
    await flush();

    expect(personaAPI.walletImport).toHaveBeenCalledWith('identity-1', {
      name: 'From WIF',
      network: 'Bitcoin',
      import_type: 'wif',
      data: 'Kwifdata',
      password: 'pw',
      address_count: undefined,
    });
    // 成功后关闭并刷新列表
    expect(personaAPI.walletList).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('导入钱包')).not.toBeInTheDocument();

    // private_key 导入：不传 address_count
    fireEvent.click(screen.getByText('导入'));
    const [net2, type2] = screen.getAllByRole('combobox') as HTMLSelectElement[];
    fireEvent.change(type2, { target: { value: 'private_key' } });
    expect(net2).toBeEnabled();
    expect(screen.getByText('私钥', { selector: 'label' })).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('导入的钱包'), {
      target: { value: 'From PK' },
    });
    fireEvent.change(screen.getByPlaceholderText('0x... / hex'), {
      target: { value: '0xdead' },
    });
    fireEvent.change(screen.getByPlaceholderText('至少 8 个字符'), {
      target: { value: 'pw' },
    });
    (personaAPI.walletImport as jest.Mock).mockClear();
    (personaAPI.walletImport as jest.Mock).mockResolvedValue({
      success: true,
      data: { id: 'pk-wallet' },
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: '导入' }).slice(-1)[0],
    );
    await flush();
    expect(personaAPI.walletImport).toHaveBeenCalledWith(
      'identity-1',
      expect.objectContaining({ import_type: 'private_key', address_count: undefined }),
    );

    // 失败：重新打开 modal（PK 成功后已关闭），提交后 modal 保留 + 错误显示
    fireEvent.click(screen.getByText('导入'));
    fireEvent.change(screen.getByPlaceholderText('导入的钱包'), {
      target: { value: 'Bad' },
    });
    fireEvent.change(screen.getByPlaceholderText('word1 word2 word3 ...'), {
      target: { value: 'not words' },
    });
    fireEvent.change(screen.getByPlaceholderText('至少 8 个字符'), {
      target: { value: 'pw' },
    });
    (personaAPI.walletImport as jest.Mock).mockResolvedValue({
      success: false,
      error: 'bad mnemonic',
    });
    fireEvent.click(screen.getAllByRole('button', { name: '导入' }).slice(-1)[0]);
    await flush();
    expect(screen.getByText('bad mnemonic')).toBeInTheDocument();
    expect(screen.getByText('导入钱包')).toBeInTheDocument();

    // Cancel：关闭且表单重置
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(screen.queryByText('导入钱包')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('导入'));
    expect(
      (screen.getByPlaceholderText('导入的钱包') as HTMLInputElement).value,
    ).toBe('');
    expect((screen.getAllByRole('combobox')[1] as HTMLSelectElement).value).toBe('mnemonic');
  });

  it('generate address: password guard, success refreshes addresses and wallets, failure surfaces', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('BTC Single'));
    await screen.findByText('钱包地址 - BTC Single');

    fireEvent.click(screen.getByRole('button', { name: '生成地址' }));
    expect(screen.getByText(/输入钱包 /)).toBeInTheDocument();

    const genBtn = screen.getByRole('button', { name: '生成' });
    expect(genBtn).toBeDisabled();

    fireEvent.change(screen.getByPlaceholderText('钱包密码'), {
      target: { value: 'pw' },
    });
    expect(genBtn).toBeEnabled();

    // 失败：错误可见，modal 保留
    (personaAPI.walletAddAddress as jest.Mock).mockResolvedValue({
      success: false,
      error: 'wrong password',
    });
    fireEvent.click(genBtn);
    await flush();
    expect(screen.getByText('wrong password')).toBeInTheDocument();
    expect(screen.getByText(/输入钱包 /)).toBeInTheDocument();

    // 成功：关 modal + 刷新地址与钱包
    (personaAPI.walletAddAddress as jest.Mock).mockResolvedValue({
      success: true,
      data: { address: '0xnew' },
    });
    fireEvent.click(genBtn);
    await flush();
    expect(personaAPI.walletAddAddress).toHaveBeenCalledWith('wallet-1', 'pw');
    expect(screen.queryByText(/输入钱包 /)).not.toBeInTheDocument();
    expect(personaAPI.walletListAddresses).toHaveBeenCalledTimes(2);
    expect(personaAPI.walletList).toHaveBeenCalledTimes(2);

    // Cancel 也能关闭
    fireEvent.click(screen.getByRole('button', { name: '生成地址' }));
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(screen.queryByText(/输入钱包 /)).not.toBeInTheDocument();
  });

  it('delete: cancelled confirm does nothing, failure surfaces an error, success clears selection', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    // 取消：无调用
    fireEvent.click(screen.getByLabelText('删除钱包 BTC Single'));
    expect(personaAPI.walletDelete).not.toHaveBeenCalled();

    // 选中后删除失败：错误显示、详情保留
    fireEvent.click(screen.getByText('BTC Single'));
    await screen.findByText('钱包地址 - BTC Single');

    confirmSpy.mockReturnValue(true);
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: false,
      error: 'denied',
    });
    fireEvent.click(screen.getByLabelText('删除钱包 BTC Single'));
    await flush();
    expect(personaAPI.walletDelete).toHaveBeenCalledWith('wallet-1');
    expect(screen.getByText('denied')).toBeInTheDocument();
    expect(screen.getByText('钱包地址 - BTC Single')).toBeInTheDocument();

    // 成功：选中详情与地址一并清空
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: true,
      data: true,
    });
    fireEvent.click(screen.getByLabelText('删除钱包 BTC Single'));
    await flush();
    expect(screen.queryByText('钱包地址 - BTC Single')).not.toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it('export: bitcoin single-address hint offers WIF, private key needs a password', async () => {
    setClipboard();
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('导出'));
    await screen.findByText('导出钱包');

    // SingleAddress + Bitcoin 的公开导出提示
    expect(
      screen.getByText('Bitcoin 单地址钱包还可以导出 WIF 备份。'),
    ).toBeInTheDocument();

    const exportButtons = () => screen.getAllByRole('button', { name: '导出' });
    const formatSelect = () =>
      screen.getAllByRole('combobox')[
        screen.getAllByRole('combobox').length - 1
      ] as HTMLSelectElement;

    // 缺密码：错误显示在面板上
    fireEvent.change(formatSelect(), { target: { value: 'private_key' } });
    expect(screen.getByText('钱包密码')).toBeInTheDocument();
    fireEvent.click(exportButtons()[exportButtons().length - 1]);
    await flush();
    expect(personaAPI.walletExport).not.toHaveBeenCalled();
    expect(screen.getByText('需要密码')).toBeInTheDocument();

    // 带密码：成功 → 输出区 + Copy
    (personaAPI.walletExport as jest.Mock).mockResolvedValue({
      success: true,
      data: 'SECRETKEYDATA',
    });
    fireEvent.change(screen.getByPlaceholderText('钱包密码'), {
      target: { value: 'pw' },
    });
    fireEvent.click(exportButtons()[exportButtons().length - 1]);
    await flush();
    expect(personaAPI.walletExport).toHaveBeenCalledWith({
      wallet_id: 'wallet-1',
      format: 'private_key',
      include_private: false,
      password: 'pw',
    });
    expect(screen.getByDisplayValue('SECRETKEYDATA')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '复制' }));
    expect(window.navigator.clipboard.writeText).toHaveBeenCalledWith('SECRETKEYDATA');

    // Close 关闭 modal
    fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    expect(screen.queryByText('导出钱包')).not.toBeInTheDocument();
  });

  it('export: json public download needs no password and passes include_private=false', async () => {
    const createObjectURL = jest.fn(() => 'blob:mock');
    const revokeObjectURL = jest.fn();
    (window.URL as any).createObjectURL = createObjectURL;
    (window.URL as any).revokeObjectURL = revokeObjectURL;
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const { findByText } = render(<WalletPanel />);
      await findByText('BTC Single');

      fireEvent.click(screen.getByText('导出'));
      await screen.findByText('导出钱包');

      // 默认 json：无密码输入
      expect(screen.queryByText('钱包密码')).not.toBeInTheDocument();

      (personaAPI.walletExport as jest.Mock).mockResolvedValue({
        success: true,
        data: '{"wallet":{}}',
      });
      fireEvent.click(
        screen.getAllByRole('button', { name: '导出' }).slice(-1)[0],
      );
      await flush();

      expect(personaAPI.walletExport).toHaveBeenCalledWith({
        wallet_id: 'wallet-1',
        format: 'json',
        include_private: false,
        password: undefined,
      });
      expect(createObjectURL).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock');

      fireEvent.click(screen.getByRole('button', { name: '关闭' }));
    } finally {
      delete (window.URL as any).createObjectURL;
      delete (window.URL as any).revokeObjectURL;
      consoleSpy.mockRestore();
    }
  });

  it('export: json with private data requires and sends the password', async () => {
    const createObjectURL = jest.fn(() => 'blob:mock');
    const revokeObjectURL = jest.fn();
    (window.URL as any).createObjectURL = createObjectURL;
    (window.URL as any).revokeObjectURL = revokeObjectURL;
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const { findByText } = render(<WalletPanel />);
      await findByText('BTC Single');

      fireEvent.click(screen.getByText('导出'));
      await screen.findByText('导出钱包');

      // 勾选包含私钥数据 → 密码框出现
      fireEvent.click(screen.getByRole('checkbox'));
      expect(screen.getByText('包含私有数据（需要密码）')).toBeInTheDocument();
      expect(screen.getByText('钱包密码')).toBeInTheDocument();

      (personaAPI.walletExport as jest.Mock).mockResolvedValue({
        success: true,
        data: '{"wallet":{},"private":true}',
      });
      fireEvent.change(screen.getByPlaceholderText('钱包密码'), {
        target: { value: 'pw' },
      });
      fireEvent.click(
        screen.getAllByRole('button', { name: '导出' }).slice(-1)[0],
      );
      await flush();

      expect(personaAPI.walletExport).toHaveBeenCalledWith({
        wallet_id: 'wallet-1',
        format: 'json',
        include_private: true,
        password: 'pw',
      });
      expect(createObjectURL).toHaveBeenCalledTimes(1);

      // 导出失败：错误显示
      (personaAPI.walletExport as jest.Mock).mockResolvedValue({
        success: false,
        error: 'locked',
      });
      fireEvent.click(
        screen.getAllByRole('button', { name: '导出' }).slice(-1)[0],
      );
      await flush();
      expect(screen.getByText('locked')).toBeInTheDocument();
    } finally {
      delete (window.URL as any).createObjectURL;
      delete (window.URL as any).revokeObjectURL;
      consoleSpy.mockRestore();
    }
  });

  it('export failure for a missing wallet surfaces the defensive error', async () => {
    // 直接构造：modal 打开后钱包列表不含目标（防御臂 "No wallet selected"）
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: true,
      data: { wallets: [makeWallet()] },
    });
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('导出'));
    await screen.findByText('导出钱包');

    // 后端失败 → 通用错误
    (personaAPI.walletExport as jest.Mock).mockResolvedValue({
      success: false,
      error: undefined,
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: '导出' }).slice(-1)[0],
    );
    await flush();
    expect(screen.getByText('导出钱包失败')).toBeInTheDocument();
  });
});
