import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import TransactionConfirmModal from './TransactionConfirmModal';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import type { WalletSummary } from '@/types';

jest.mock('@/utils/api', () => ({
  personaAPI: {
    walletCreateTransaction: jest.fn(),
    walletSignTransaction: jest.fn(),
  },
}));

jest.mock('@/utils/clipboard', () => ({
  copyWithAutoClear: jest.fn().mockResolvedValue(true),
}));

const wallet = {
  id: 'w-1',
  name: 'Main ETH',
  network: 'Ethereum',
} as unknown as WalletSummary;

const knownAddress = '0x1111111111111111111111111111111111111111';
// 头 6 位与尾 6 位相同、中段不同 → 投毒启发式命中
const lookalikeAddress = '0x1111112222111111111111111111111111111111';

const signedTx = {
  transaction_id: 't-1',
  transaction_hash: '0xdeadbeef',
  raw_signed_transaction: [1, 255, 16],
} as any;

const fillForm = ({
  to = lookalikeAddress,
  amount = '1000000',
  fee = '21000',
  password = 'wallet-pass',
}: { to?: string; amount?: string; fee?: string; password?: string } = {}) => {
  fireEvent.change(screen.getByTestId('to-address-input'), { target: { value: to } });
  fireEvent.change(screen.getByTestId('amount-input'), { target: { value: amount } });
  fireEvent.change(screen.getByTestId('fee-input'), { target: { value: fee } });
  fireEvent.change(screen.getByTestId('sign-password-input'), { target: { value: password } });
};

describe('components/TransactionConfirmModal', () => {
  const onClose = jest.fn();
  const onSuccess = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    (personaAPI.walletCreateTransaction as jest.Mock).mockResolvedValue({
      success: true,
      data: { id: 't-1' },
    });
    (personaAPI.walletSignTransaction as jest.Mock).mockResolvedValue({
      success: true,
      data: signedTx,
    });
  });

  const renderModal = (props: Partial<Parameters<typeof TransactionConfirmModal>[0]> = {}) =>
    render(
      <TransactionConfirmModal
        isOpen
        onClose={onClose}
        wallet={wallet}
        fromAddress={knownAddress}
        knownAddresses={[knownAddress]}
        onSuccess={onSuccess}
        {...props}
      />,
    );

  it('renders nothing when closed', () => {
    const { container } = renderModal({ isOpen: false });
    expect(container).toBeEmptyDOMElement();
  });

  it('shows wallet context and disables confirm until the form is complete', () => {
    renderModal();

    expect(screen.getByText(new RegExp(knownAddress.slice(0, 10)))).toBeInTheDocument();
    expect(screen.getByText('Ethereum')).toBeInTheDocument();
    expect(screen.getByTestId('confirm-sign-button')).toBeDisabled();

    fillForm();
    expect(screen.getByTestId('confirm-sign-button')).toBeEnabled();
  });

  it('warns when the recipient mimics a known address', () => {
    renderModal();
    fireEvent.change(screen.getByTestId('to-address-input'), {
      target: { value: lookalikeAddress },
    });

    const warning = screen.getByTestId('poisoning-warning');
    expect(warning).toHaveAttribute('role', 'alert');
    expect(warning.textContent).toContain(knownAddress);

    // 正常地址无告警
    fireEvent.change(screen.getByTestId('to-address-input'), {
      target: { value: '0x9999999999999999999999999999999999999999' },
    });
    expect(screen.queryByTestId('poisoning-warning')).not.toBeInTheDocument();
  });

  it('creates and signs the transaction, then shows hash and raw bytes', async () => {
    renderModal();
    fillForm({ to: '0x9999999999999999999999999999999999999999' });
    fireEvent.click(screen.getByTestId('confirm-sign-button'));

    await waitFor(() => {
      expect(screen.getByTestId('tx-result')).toBeInTheDocument();
    });

    expect(personaAPI.walletCreateTransaction).toHaveBeenCalledWith({
      wallet_id: 'w-1',
      to_address: '0x9999999999999999999999999999999999999999',
      amount: '1000000',
      fee: '21000',
      memo: undefined,
    });
    expect(personaAPI.walletSignTransaction).toHaveBeenCalledWith({
      transaction_id: 't-1',
      password: 'wallet-pass',
    });

    expect(screen.getByTestId('tx-hash').textContent).toBe('0xdeadbeef');
    // raw bytes 以两位十六进制展示
    expect(screen.getByText(/01ff10/)).toBeInTheDocument();
    expect(onSuccess).toHaveBeenCalledWith(signedTx);

    // 复制按钮走 copyWithAutoClear
    fireEvent.click(screen.getByLabelText('Copy hash'));
    expect(copyWithAutoClear).toHaveBeenCalledWith('0xdeadbeef');
  });

  it('keeps the form open with the API error when creation fails', async () => {
    (personaAPI.walletCreateTransaction as jest.Mock).mockResolvedValue({
      success: false,
      data: undefined,
      error: 'insufficient balance',
    });

    renderModal();
    fillForm();
    fireEvent.click(screen.getByTestId('confirm-sign-button'));

    await waitFor(() => {
      expect(screen.getByTestId('tx-error')).toHaveTextContent('insufficient balance');
    });
    expect(screen.getByTestId('confirm-sign-button')).toBeInTheDocument();
    expect(personaAPI.walletSignTransaction).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('surfaces sign failures and recovers to the form step', async () => {
    (personaAPI.walletSignTransaction as jest.Mock).mockResolvedValue({
      success: false,
      data: undefined,
      error: 'wrong password',
    });

    renderModal();
    fillForm();
    fireEvent.click(screen.getByTestId('confirm-sign-button'));

    await waitFor(() => {
      expect(screen.getByTestId('tx-error')).toHaveTextContent('wrong password');
    });
    // 签名失败后密码已清空，需重填才能再签
    expect((screen.getByTestId('sign-password-input') as HTMLInputElement).value).toBe('');
  });

  it('shows the signing step while the promise is in flight', async () => {
    let resolveSign: (v: unknown) => void = () => {};
    (personaAPI.walletSignTransaction as jest.Mock).mockReturnValue(
      new Promise((res) => {
        resolveSign = res;
      }),
    );

    renderModal();
    fillForm();
    fireEvent.click(screen.getByTestId('confirm-sign-button'));

    expect(screen.getByText('Signing transaction…')).toBeInTheDocument();

    resolveSign({ success: true, data: signedTx });
    await waitFor(() => {
      expect(screen.getByTestId('tx-result')).toBeInTheDocument();
    });
  });

  it('resets the form after closing and remembers nothing on reopen', async () => {
    const { rerender } = renderModal();
    fillForm();
    fireEvent.click(screen.getByLabelText('Close'));

    expect(onClose).toHaveBeenCalledTimes(1);

    rerender(
      <TransactionConfirmModal
        isOpen={false}
        onClose={onClose}
        wallet={wallet}
        fromAddress={knownAddress}
        knownAddresses={[knownAddress]}
        onSuccess={onSuccess}
      />,
    );
    rerender(
      <TransactionConfirmModal
        isOpen
        onClose={onClose}
        wallet={wallet}
        fromAddress={knownAddress}
        knownAddresses={[knownAddress]}
        onSuccess={onSuccess}
      />,
    );

    expect((screen.getByTestId('to-address-input') as HTMLInputElement).value).toBe('');
    expect(screen.queryByTestId('poisoning-warning')).not.toBeInTheDocument();
  });
});
