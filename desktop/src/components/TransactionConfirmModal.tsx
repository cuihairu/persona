import React, { useMemo, useState } from 'react';
import { XMarkIcon, ExclamationTriangleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import { looksLikeAddressPoisoning } from '@/utils/addressPoisoning';
import type { WalletSummary, WalletSignedTransaction } from '@/types';

export interface TransactionConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  wallet: WalletSummary;
  fromAddress: string;
  /** Known addresses (used by the poisoning heuristic), usually all historical addresses of this wallet */
  knownAddresses: string[];
  onSuccess?: (signed: WalletSignedTransaction) => void;
}

type ModalStep = 'form' | 'signing' | 'result';

/**
 * Wallet signing confirmation flow: fill the form → confirm (with address
 * poisoning warning) → enter the password to sign → show the hash.
 * The password is only used inside this dialog and never lands in any store.
 */
const TransactionConfirmModal: React.FC<TransactionConfirmModalProps> = ({
  isOpen,
  onClose,
  wallet,
  fromAddress,
  knownAddresses,
  onSuccess,
}) => {
  const { t } = useTranslation();
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
        throw new Error(created.error ?? t('tx.createFailed'));
      }

      const result = await personaAPI.walletSignTransaction({
        transaction_id: created.data.id,
        password,
        // The dialog showed the poisoning warning and the user still clicked confirm during the
        // second confirmation = an explicit acknowledgement (the backend sign entry point runs the
        // heuristic again and refuses to sign without an ack)
        confirm_poisoning_check: poisonSource !== null,
      });
      if (!result.success || !result.data) {
        throw new Error(result.error ?? t('tx.signFailed'));
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
      onMouseDown={(e) => {
        // Backdrop click = cancel (do not sign); signing requires an explicit confirm click, minimizing the cost of stray touches
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            {step === 'result' ? t('tx.titleResult') : t('tx.titleSign')}
          </h2>
          <button onClick={handleClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" aria-label={t('common.close')}>
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          {step === 'form' && (
            <>
              {/* From */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">{t('tx.from', { name: wallet.name })}</label>
                <div className="flex items-center justify-between gap-2">
                  <code className="text-xs font-mono break-all text-gray-700 dark:text-gray-300">{fromAddress}</code>
                  <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0">{wallet.network}</span>
                </div>
              </div>

              {/* To */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">{t('tx.toAddress')}</label>
                <input
                  type="text"
                  value={toAddress}
                  onChange={(e) => setToAddress(e.target.value)}
                  placeholder={t('tx.toPlaceholder')}
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
                      {t('tx.poisoningPrefix')}
                      (<code className="break-all">{poisonSource}</code>){t('tx.poisoningSuffix')}
                    </span>
                  </div>
                )}
              </div>

              {/* Amount + Fee */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label text-gray-600 dark:text-gray-300">{t('tx.amount')}</label>
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
                  <label className="label text-gray-600 dark:text-gray-300">{t('tx.fee')}</label>
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
                <label className="label text-gray-600 dark:text-gray-300">{t('tx.memo')}</label>
                <input
                  type="text"
                  value={memo}
                  onChange={(e) => setMemo(e.target.value)}
                  className="w-full input"
                />
              </div>

              {/* Password */}
              <div>
                <label className="label text-gray-600 dark:text-gray-300">{t('tx.walletPassword')}</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('tx.passwordPlaceholder')}
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
              {t('tx.signing')}
            </div>
          )}

          {step === 'result' && signed && (
            <div className="space-y-3" data-testid="tx-result">
              <div className="flex items-center gap-2 text-sm text-green-700 dark:text-green-300">
                <CheckCircleIcon className="w-5 h-5" />
                {t('tx.resultNote')}
              </div>
              <div>
                <label className="label text-gray-600 dark:text-gray-300">{t('tx.txHash')}</label>
                <div className="flex items-start gap-2">
                  <code className="text-xs font-mono break-all" data-testid="tx-hash">
                    {signed.transaction_hash}
                  </code>
                  <button
                    onClick={() => void copyWithAutoClear(signed.transaction_hash)}
                    className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                    aria-label={t('tx.copyHash')}
                  >
                    ⧉
                  </button>
                </div>
              </div>
              {signed.raw_signed_transaction.length > 0 && (
                <div>
                  <label className="label text-gray-600 dark:text-gray-300">{t('tx.rawTx', { count: signed.raw_signed_transaction.length })}</label>
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
                {t('common.cancel')}
              </button>
              <button
                onClick={handleConfirm}
                disabled={!formValid}
                className="btn-primary"
                data-testid="confirm-sign-button"
              >
                {t('tx.confirmSign')}
              </button>
            </>
          )}
          {step === 'signing' && (
            <button disabled className="btn-primary opacity-50">
              {t('tx.signingButton')}
            </button>
          )}
          {step === 'result' && (
            <button onClick={handleClose} className="btn-primary">
              {t('tx.done')}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default TransactionConfirmModal;
