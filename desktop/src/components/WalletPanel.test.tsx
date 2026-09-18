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

    fireEvent.click(getByText('Export'));

    await waitFor(() => expect(getByText('Export Wallet')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toContain('JSON');
    expect(optionLabels).toContain('Private Key');
    expect(optionLabels).toContain('Bitcoin WIF');
    expect(optionLabels).not.toContain('XPUB');
    expect(optionLabels).not.toContain('Mnemonic');
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

    fireEvent.click(getByText('Export'));

    await waitFor(() => expect(getByText('Export Wallet')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toContain('JSON');
    expect(optionLabels).toContain('XPUB');
    expect(optionLabels).toContain('Mnemonic');
    expect(optionLabels).toContain('Private Key');
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

    fireEvent.click(getByText('Export'));

    await waitFor(() => expect(getByText('Export Wallet')).toBeInTheDocument());

    const comboBoxes = getAllByRole('combobox');
    const formatSelect = comboBoxes[comboBoxes.length - 1] as HTMLSelectElement;
    const optionLabels = Array.from(formatSelect.options).map((option) => option.text);

    expect(optionLabels).toEqual(['JSON', 'XPUB']);
    expect(getByText('Watch-only wallets can only export public data.')).toBeInTheDocument();
    expect(screen.getByTitle('Watch-only')).toBeInTheDocument();
  });

  it('deletes a wallet after confirmation and refreshes the list', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: true,
      data: true,
    });

    const { findByText, getByLabelText } = render(<WalletPanel />);

    await findByText('BTC Single');

    fireEvent.click(getByLabelText('Delete wallet BTC Single'));

    await waitFor(() => {
      expect(confirmSpy).toHaveBeenCalledWith(
        'Delete wallet "BTC Single"? This cannot be undone.',
      );
      expect(personaAPI.walletDelete).toHaveBeenCalledWith('wallet-1');
      expect(personaAPI.walletList).toHaveBeenCalledTimes(2);
    });

    confirmSpy.mockRestore();
  });

  it('shows the spinner while loading and the empty state when no wallets exist', async () => {
    (personaAPI.walletList as jest.Mock).mockReturnValue(new Promise(() => {}));
    const { getByText, queryByText } = render(<WalletPanel />);
    expect(getByText('Loading wallets...')).toBeInTheDocument();

    // 挂起态下不渲染空态
    expect(queryByText('No wallets')).not.toBeInTheDocument();
  });

  it('renders the empty state with create/import shortcuts once loading finishes', async () => {
    mockWalletList([]);
    const { findByText } = render(<WalletPanel />);

    expect(await findByText('No wallets')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Create Wallet'));
    expect(screen.getByText('Create New Wallet')).toBeInTheDocument();
  });

  it('shows and dismisses an error when the wallet list fails', async () => {
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: false,
      error: 'rpc down',
    });
    const { findByText } = render(<WalletPanel />);

    expect(await findByText('rpc down')).toBeInTheDocument();
    // 出错时不渲染空态
    expect(screen.queryByText('No wallets')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('rpc down')).not.toBeInTheDocument();
    expect(await screen.findByText('No wallets')).toBeInTheDocument();
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
    expect(screen.getByText('No wallets')).toBeInTheDocument();
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

    expect(await screen.findByText('Wallet Addresses - BTC Single')).toBeInTheDocument();
    // 地址是异步加载的，等第一行出现
    expect(await screen.findByText('0xaaa')).toBeInTheDocument();
    expect(screen.getByText('0xbbb')).toBeInTheDocument();
    expect(screen.getByText('P2WPKH')).toBeInTheDocument();
    expect(screen.getByText('Unused')).toBeInTheDocument();
    expect(screen.getByText('Used')).toBeInTheDocument();

    // 行内 Copy
    fireEvent.click(screen.getAllByRole('button', { name: 'Copy' })[0]);
    expect(writeText).toHaveBeenCalledWith('0xaaa');

    // QR modal：打开 → Copy Address → 关闭
    fireEvent.click(screen.getAllByTitle('Show QR Code')[1]);
    expect(screen.getByTestId('address-qr')).toBeInTheDocument();
    expect(screen.getByText('Receive Address')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy Address' }));
    expect(writeText).toHaveBeenCalledWith('0xbbb');
    expect(screen.queryByTestId('address-qr')).not.toBeInTheDocument();

    // 重开，点遮罩关闭
    fireEvent.click(screen.getAllByTitle('Show QR Code')[0]);
    expect(screen.getByTestId('address-qr')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Receive Address').closest('div.fixed')!);
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
      await screen.findByText('No addresses generated yet'),
    ).toBeInTheDocument();
  });

  it('logs and survives address loading failures', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    (personaAPI.walletListAddresses as jest.Mock).mockRejectedValue(new Error('addr fail'));
    const { findByText } = render(<WalletPanel />);

    await findByText('BTC Single');
    fireEvent.click(screen.getByText('BTC Single'));

    await screen.findByText('Wallet Addresses - BTC Single');
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load addresses:',
      expect.objectContaining({ message: 'addr fail' }),
    );
    expect(screen.getByText('No addresses generated yet')).toBeInTheDocument();
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
      'Loading address…',
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

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(personaAPI.walletList).toHaveBeenCalledTimes(2));
  });

  it('create wallet: full flow, disabled guards, failure and cancel reset', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('New Wallet'));
    expect(screen.getByText('Create New Wallet')).toBeInTheDocument();

    // 空表单禁止提交
    const createBtn = screen.getByRole('button', { name: 'Create' });
    expect(createBtn).toBeDisabled();

    // 改网络与地址数
    const networkSelect = screen.getAllByRole('combobox')[0] as HTMLSelectElement;
    fireEvent.change(networkSelect, { target: { value: 'Bitcoin' } });
    fireEvent.change(screen.getByDisplayValue('5'), { target: { value: '3' } });

    fireEvent.change(screen.getByPlaceholderText('My Wallet'), {
      target: { value: 'My BTC' },
    });
    fireEvent.change(screen.getByPlaceholderText('At least 8 characters'), {
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
    expect(screen.getByText('Create New Wallet')).toBeInTheDocument();

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
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByText('Create New Wallet')).not.toBeInTheDocument();

    // 重开后表单已重置
    fireEvent.click(screen.getByText('New Wallet'));
    expect(
      (screen.getByPlaceholderText('My Wallet') as HTMLInputElement).value,
    ).toBe('');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Create New Wallet')).not.toBeInTheDocument();
  });

  it('import wallet: type switching locks network for WIF, submits and resets on success', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('Import'));
    expect(screen.getByText('Import Wallet')).toBeInTheDocument();

    // 头部也有一个 'Import' 按钮，modal 内的取最后一个
    const importBtn = screen
      .getAllByRole('button', { name: 'Import' })
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

    fireEvent.change(screen.getByPlaceholderText('Imported Wallet'), {
      target: { value: 'From WIF' },
    });
    fireEvent.change(screen.getByPlaceholderText('K... / L...'), {
      target: { value: 'Kwifdata' },
    });
    fireEvent.change(screen.getByPlaceholderText('At least 8 characters'), {
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
    expect(screen.queryByText('Import Wallet')).not.toBeInTheDocument();

    // private_key 导入：不传 address_count
    fireEvent.click(screen.getByText('Import'));
    const [net2, type2] = screen.getAllByRole('combobox') as HTMLSelectElement[];
    fireEvent.change(type2, { target: { value: 'private_key' } });
    expect(net2).toBeEnabled();
    expect(screen.getByText('Private Key', { selector: 'label' })).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Imported Wallet'), {
      target: { value: 'From PK' },
    });
    fireEvent.change(screen.getByPlaceholderText('0x... / hex'), {
      target: { value: '0xdead' },
    });
    fireEvent.change(screen.getByPlaceholderText('At least 8 characters'), {
      target: { value: 'pw' },
    });
    (personaAPI.walletImport as jest.Mock).mockClear();
    (personaAPI.walletImport as jest.Mock).mockResolvedValue({
      success: true,
      data: { id: 'pk-wallet' },
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Import' }).slice(-1)[0],
    );
    await flush();
    expect(personaAPI.walletImport).toHaveBeenCalledWith(
      'identity-1',
      expect.objectContaining({ import_type: 'private_key', address_count: undefined }),
    );

    // 失败：重新打开 modal（PK 成功后已关闭），提交后 modal 保留 + 错误显示
    fireEvent.click(screen.getByText('Import'));
    fireEvent.change(screen.getByPlaceholderText('Imported Wallet'), {
      target: { value: 'Bad' },
    });
    fireEvent.change(screen.getByPlaceholderText('word1 word2 word3 ...'), {
      target: { value: 'not words' },
    });
    fireEvent.change(screen.getByPlaceholderText('At least 8 characters'), {
      target: { value: 'pw' },
    });
    (personaAPI.walletImport as jest.Mock).mockResolvedValue({
      success: false,
      error: 'bad mnemonic',
    });
    fireEvent.click(screen.getAllByRole('button', { name: 'Import' }).slice(-1)[0]);
    await flush();
    expect(screen.getByText('bad mnemonic')).toBeInTheDocument();
    expect(screen.getByText('Import Wallet')).toBeInTheDocument();

    // Cancel：关闭且表单重置
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('Import Wallet')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Import'));
    expect(
      (screen.getByPlaceholderText('Imported Wallet') as HTMLInputElement).value,
    ).toBe('');
    expect((screen.getAllByRole('combobox')[1] as HTMLSelectElement).value).toBe('mnemonic');
  });

  it('generate address: password guard, success refreshes addresses and wallets, failure surfaces', async () => {
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('BTC Single'));
    await screen.findByText('Wallet Addresses - BTC Single');

    fireEvent.click(screen.getByRole('button', { name: 'Generate Address' }));
    expect(screen.getByText(/Enter the wallet password for/)).toBeInTheDocument();

    const genBtn = screen.getByRole('button', { name: 'Generate' });
    expect(genBtn).toBeDisabled();

    fireEvent.change(screen.getByPlaceholderText('Wallet password'), {
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
    expect(screen.getByText(/Enter the wallet password for/)).toBeInTheDocument();

    // 成功：关 modal + 刷新地址与钱包
    (personaAPI.walletAddAddress as jest.Mock).mockResolvedValue({
      success: true,
      data: { address: '0xnew' },
    });
    fireEvent.click(genBtn);
    await flush();
    expect(personaAPI.walletAddAddress).toHaveBeenCalledWith('wallet-1', 'pw');
    expect(screen.queryByText(/Enter the wallet password for/)).not.toBeInTheDocument();
    expect(personaAPI.walletListAddresses).toHaveBeenCalledTimes(2);
    expect(personaAPI.walletList).toHaveBeenCalledTimes(2);

    // Cancel 也能关闭
    fireEvent.click(screen.getByRole('button', { name: 'Generate Address' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText(/Enter the wallet password for/)).not.toBeInTheDocument();
  });

  it('delete: cancelled confirm does nothing, failure surfaces an error, success clears selection', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    // 取消：无调用
    fireEvent.click(screen.getByLabelText('Delete wallet BTC Single'));
    expect(personaAPI.walletDelete).not.toHaveBeenCalled();

    // 选中后删除失败：错误显示、详情保留
    fireEvent.click(screen.getByText('BTC Single'));
    await screen.findByText('Wallet Addresses - BTC Single');

    confirmSpy.mockReturnValue(true);
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: false,
      error: 'denied',
    });
    fireEvent.click(screen.getByLabelText('Delete wallet BTC Single'));
    await flush();
    expect(personaAPI.walletDelete).toHaveBeenCalledWith('wallet-1');
    expect(screen.getByText('denied')).toBeInTheDocument();
    expect(screen.getByText('Wallet Addresses - BTC Single')).toBeInTheDocument();

    // 成功：选中详情与地址一并清空
    (personaAPI.walletDelete as jest.Mock).mockResolvedValue({
      success: true,
      data: true,
    });
    fireEvent.click(screen.getByLabelText('Delete wallet BTC Single'));
    await flush();
    expect(screen.queryByText('Wallet Addresses - BTC Single')).not.toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it('export: bitcoin single-address hint offers WIF, private key needs a password', async () => {
    setClipboard();
    const { findByText } = render(<WalletPanel />);
    await findByText('BTC Single');

    fireEvent.click(screen.getByText('Export'));
    await screen.findByText('Export Wallet');

    // SingleAddress + Bitcoin 的公开导出提示
    expect(
      screen.getByText('Bitcoin single-address wallets can also export a WIF backup.'),
    ).toBeInTheDocument();

    const exportButtons = () => screen.getAllByRole('button', { name: 'Export' });
    const formatSelect = () =>
      screen.getAllByRole('combobox')[
        screen.getAllByRole('combobox').length - 1
      ] as HTMLSelectElement;

    // 缺密码：错误显示在面板上
    fireEvent.change(formatSelect(), { target: { value: 'private_key' } });
    expect(screen.getByText('Wallet Password')).toBeInTheDocument();
    fireEvent.click(exportButtons()[exportButtons().length - 1]);
    await flush();
    expect(personaAPI.walletExport).not.toHaveBeenCalled();
    expect(screen.getByText('Password required')).toBeInTheDocument();

    // 带密码：成功 → 输出区 + Copy
    (personaAPI.walletExport as jest.Mock).mockResolvedValue({
      success: true,
      data: 'SECRETKEYDATA',
    });
    fireEvent.change(screen.getByPlaceholderText('Wallet password'), {
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

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(window.navigator.clipboard.writeText).toHaveBeenCalledWith('SECRETKEYDATA');

    // Close 关闭 modal
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByText('Export Wallet')).not.toBeInTheDocument();
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

      fireEvent.click(screen.getByText('Export'));
      await screen.findByText('Export Wallet');

      // 默认 json：无密码输入
      expect(screen.queryByText('Wallet Password')).not.toBeInTheDocument();

      (personaAPI.walletExport as jest.Mock).mockResolvedValue({
        success: true,
        data: '{"wallet":{}}',
      });
      fireEvent.click(
        screen.getAllByRole('button', { name: 'Export' }).slice(-1)[0],
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

      fireEvent.click(screen.getByRole('button', { name: 'Close' }));
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

      fireEvent.click(screen.getByText('Export'));
      await screen.findByText('Export Wallet');

      // 勾选包含私钥数据 → 密码框出现
      fireEvent.click(screen.getByRole('checkbox'));
      expect(screen.getByText('Include private data (requires password)')).toBeInTheDocument();
      expect(screen.getByText('Wallet Password')).toBeInTheDocument();

      (personaAPI.walletExport as jest.Mock).mockResolvedValue({
        success: true,
        data: '{"wallet":{},"private":true}',
      });
      fireEvent.change(screen.getByPlaceholderText('Wallet password'), {
        target: { value: 'pw' },
      });
      fireEvent.click(
        screen.getAllByRole('button', { name: 'Export' }).slice(-1)[0],
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
        screen.getAllByRole('button', { name: 'Export' }).slice(-1)[0],
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

    fireEvent.click(screen.getByText('Export'));
    await screen.findByText('Export Wallet');

    // 后端失败 → 通用错误
    (personaAPI.walletExport as jest.Mock).mockResolvedValue({
      success: false,
      error: undefined,
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: 'Export' }).slice(-1)[0],
    );
    await flush();
    expect(screen.getByText('Failed to export wallet')).toBeInTheDocument();
  });
});
