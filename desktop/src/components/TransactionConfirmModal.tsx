import React, { useMemo, useState } from 'react';
import { XMarkIcon, ExclamationTriangleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import { looksLikeAddressPoisoning } from '@/utils/addressPoisoning';
import type { WalletSummary, WalletSignedTransaction } from '@/types';

export interface TransactionConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  wallet: WalletSummary;
  fromAddress: string;
  /** 已知地址列表（用于投毒启发式），通常是该钱包的全部历史地址 */
  knownAddresses: string[];
  onSuccess?: (signed: WalletSignedTransaction) => void;
}

type ModalStep = 'form' | 'signing' | 'result';

/**
 * 钱包签名确认流：填表 → 确认（含地址投毒告警）→ 输密码签名 → 展示 hash。
 * 密码只在本弹窗内使用，不落任何 store。
 */
const TransactionConfirmModal: React.FC<TransactionConfirmModalProps> = ({
  isOpen,
  onClose,
  wallet,
  fromAddress,
  knownAddresses,
  onSuccess,
}) => {
  const [toAddress, setToAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [fee, setFee] = useState('');
  const [memo, setMemo] = useState('');
  const [password, setPassword] = useState('');
  const [step, setStep] = useState<ModalStep>('form');
  const [error, setError] = useState<string | null>(null);
  const [signed, setSigned] = useState<WalletSignedTransaction | null>(null);

  const poisonSource = useMemo(
    () => (toAddress ? looksLikeAddressPoisoning(toAddress, knownAddresses) : null),
    [toAddress, knownAddresses],
  );

  if (!isOpen) return null;

  const reset = () => {
    setToAddress('');
    setAmount('');
    setFee('');
    setMemo('');
    setPassword('');
    setStep('form');
    setError(null);
    setSigned(null);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleConfirm = async () => {
    setError(null);
    if (!toAddress.trim() || !amount.trim() || !fee.trim() || !password) return;
    setStep('signing');
    try {
      const created = await personaAPI.walletCreateTransaction({
        wallet_id: wallet.id,
        to_address: toAddress.trim(),
        amount: amount.trim(),
        fee: fee.trim(),
        memo: memo.trim() || undefined,
      });
      if (!created.success || !created.data) {
        throw new Error(created.error ?? 'Failed to create transaction');
      }

      const result = await personaAPI.walletSignTransaction({
        transaction_id: created.data.id,
        password,
      });
      if (!result.success || !result.data) {
        throw new Error(result.error ?? 'Failed to sign transaction');
      }

      setSigned(result.data);
      setStep('result');
      onSuccess?.(result.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStep('form');
    } finally {
      setPassword('');
    }
  };

  const formValid = toAddress.trim() && amount.trim() && fee.trim() && password;

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
      data-testid="transaction-confirm-modal"
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            {step === 'result' ? 'Transaction Signed' : 'Send Transaction'}
          </h2>
          <button onClick={handleClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" aria-label="Close">
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          {step === 'form' && (
            <>
              {/* From */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">From ({wallet.name})</label>
                <div className="flex items-center justify-between gap-2">
                  <code className="text-xs font-mono break-all text-gray-700 dark:text-gray-300">{fromAddress}</code>
                  <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0">{wallet.network}</span>
                </div>
              </div>

              {/* To */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">To Address</label>
                <input
                  type="text"
                  value={toAddress}
                  onChange={(e) => setToAddress(e.target.value)}
                  placeholder="Recipient address"
                  className="w-full input font-mono text-xs"
                  data-testid="to-address-input"
                />
                {poisonSource && (
                  <div
                    className="mt-2 flex items-start gap-2 text-xs text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-500/10 border border-red-300 dark:border-red-500/40 rounded px-3 py-2"
                    data-testid="poisoning-warning"
                    role="alert"
                  >
                    <ExclamationTriangleIcon className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>
                      ⚠️ This address closely mimics a known address of yours
                      (<code className="break-all">{poisonSource}</code>). Address-poisoning
                      attacks rely on lookalike addresses — double-check every character or paste
                      the address from a trusted source.
                    </span>
                  </div>
                )}
              </div>

              {/* Amount + Fee */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label text-gray-600 dark:text-gray-300">Amount (min. unit)</label>
                  <input
                    type="text"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    placeholder="0"
                    className="w-full input"
                    data-testid="amount-input"
                  />
                </div>
                <div>
                  <label className="label text-gray-600 dark:text-gray-300">Fee (min. unit)</label>
                  <input
                    type="text"
                    value={fee}
                    onChange={(e) => setFee(e.target.value)}
                    placeholder="0"
                    className="w-full input"
                    data-testid="fee-input"
                  />
                </div>
              </div>

              {/* Memo */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Memo (optional)</label>
                <input
                  type="text"
                  value={memo}
                  onChange={(e) => setMemo(e.target.value)}
                  className="w-full input"
                />
              </div>

              {/* Password */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Wallet Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password to sign"
                  className="w-full input"
                  autoComplete="off"
                  data-testid="sign-password-input"
                />
              </div>

              {error && (
                <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded px-3 py-2" data-testid="tx-error">
                  {error}
                </div>
              )}
            </>
          )}

          {step === 'signing' && (
            <div className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">
              Signing transaction…
            </div>
          )}

          {step === 'result' && signed && (
            <div className="space-y-3" data-testid="tx-result">
              <div className="flex items-center gap-2 text-sm text-green-700 dark:text-green-300">
                <CheckCircleIcon className="w-5 h-5" />
                Signature verified and stored locally (not broadcast).
              </div>
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Transaction Hash</label>
                <div className="flex items-start gap-2">
                  <code className="text-xs font-mono break-all" data-testid="tx-hash">
                    {signed.transaction_hash}
                  </code>
                  <button
                    onClick={() => void copyWithAutoClear(signed.transaction_hash)}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                    aria-label="Copy hash"
                  >
                    ⧉
                  </button>
                </div>
              </div>
              {signed.raw_signed_transaction.length > 0 && (
                <div>
                  <label className="label text-gray-600 dark:text-gray-300">Raw Transaction ({signed.raw_signed_transaction.length} bytes)</label>
                  <code className="block text-xs font-mono break-all text-gray-500 dark:text-gray-400">
                    {Array.from(signed.raw_signed_transaction)
                      .map((b) => b.toString(16).padStart(2, '0'))
                      .join('')}
                  </code>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
          {step === 'form' && (
            <>
              <button onClick={handleClose} className="btn-ghost">
                Cancel
              </button>
              <button
                onClick={handleConfirm}
                disabled={!formValid}
                className="btn-primary"
                data-testid="confirm-sign-button"
              >
                Confirm &amp; Sign
              </button>
            </>
          )}
          {step === 'signing' && (
            <button disabled className="btn-primary opacity-50">
              Signing…
            </button>
          )}
          {step === 'result' && (
            <button onClick={handleClose} className="btn-primary">
              Done
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default TransactionConfirmModal;
