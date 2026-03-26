import { fireEvent, render, waitFor } from '@testing-library/react';
import WalletPanel from './WalletPanel';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';

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
  },
}));

describe('components/WalletPanel', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    (usePersonaService as jest.Mock).mockReturnValue({
      currentIdentity: { id: 'identity-1', name: 'Alice' },
    });
    (personaAPI.walletList as jest.Mock).mockResolvedValue({
      success: true,
      data: {
        wallets: [
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
        ],
      },
    });
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
});
