import React from 'react';
import { useTranslation } from 'react-i18next';
import type { WalletGenerateResponse } from '@/types';

export interface CreateWalletForm {
  name: string;
  network: string;
  password: string;
  addressCount: number;
}

interface CreateWalletModalProps {
  form: CreateWalletForm;
  setForm: React.Dispatch<React.SetStateAction<CreateWalletForm>>;
  /** Mnemonic result after a successful generation; null = form state */
  result: WalletGenerateResponse | null;
  onCreate: () => void;
  /** Closes and resets the form and result (parent's responsibility) */
  onClose: () => void;
}

/** Create-wallet modal: two phases, form state <-> mnemonic display state */
const CreateWalletModal: React.FC<CreateWalletModalProps> = ({
  form,
  setForm,
  result,
  onCreate,
  onClose,
}) => {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold mb-4">{t('wallet.createTitle')}</h3>
        {!result ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.nameLabel')}</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                placeholder={t('wallet.namePlaceholder')}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.networkLabel')}</label>
                <select
                  value={form.network}
                  onChange={(e) => setForm({ ...form, network: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                >
                  <option>Ethereum</option>
                  <option>Bitcoin</option>
                  <option>Polygon</option>
                  <option>Arbitrum</option>
                  <option>Optimism</option>
                  <option>Binance Smart Chain</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.addressesCountLabel')}</label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={form.addressCount}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      addressCount: Number(e.target.value || 5),
                    })
                  }
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.walletPassword')}</label>
              <input
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                placeholder={t('wallet.passwordHint')}
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={onClose}
                className="whitespace-nowrap flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={onCreate}
                className="whitespace-nowrap flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                disabled={!form.name.trim() || !form.password}
              >
                {t('wallet.create')}
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-gray-700 dark:text-gray-300">
              {t('wallet.saveMnemonicHint')}
            </p>
            <textarea
              readOnly
              value={result.mnemonic}
              className="w-full h-28 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm"
            />
            <div className="text-sm text-gray-600 dark:text-gray-300">
              {t('wallet.firstAddress')}<code className="font-mono">{result.first_address}</code>
            </div>
            <button
              onClick={onClose}
              className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
            >
              {t('wallet.done')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default CreateWalletModal;
