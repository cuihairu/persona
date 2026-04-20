import { fireEvent, render, waitFor } from '@testing-library/react';
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

describe('components/WalletPanel', () => {
  const mockWalletList = (wallets: WalletSummary[]) => {
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: true,
      data: { wallets },
    });
  };

  beforeEach(() => {
    jest.resetAllMocks();
    (usePersonaService as jest.Mock).mockReturnValue({
      currentIdentity: { id: 'identity-1', name: 'Alice' },
    });
    mockWalletList([
      {
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
      },
    ]);
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
      {
        id: 'wallet-hd-1',
        name: 'ETH HD',
        network: 'Ethereum',
        wallet_type: 'HierarchicalDeterministic { bip_version: Bip44, address_count: 5, gap_limit: 20 }',
        balance: '-',
        address_count: 5,
        watch_only: false,
        security_level: 'High',
        created_at: '2026-03-27T00:00:00Z',
        updated_at: '2026-03-27T00:00:00Z',
      },
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
      {
        id: 'wallet-watch-1',
        name: 'BTC Watch',
        network: 'Bitcoin',
        wallet_type: 'HierarchicalDeterministic { bip_version: Bip44, address_count: 5, gap_limit: 20 }',
        balance: '-',
        address_count: 5,
        watch_only: true,
        security_level: 'Medium',
        created_at: '2026-03-27T00:00:00Z',
        updated_at: '2026-03-27T00:00:00Z',
      },
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
      expect(confirmSpy).toHaveBeenCalledWith('Delete wallet "BTC Single"? This cannot be undone.');
      expect(personaAPI.walletDelete).toHaveBeenCalledWith('wallet-1');
      expect(personaAPI.walletList).toHaveBeenCalledTimes(2);
    });

    confirmSpy.mockRestore();
  });
});
