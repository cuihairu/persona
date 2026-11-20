import React from 'react';
import { useTranslation } from 'react-i18next';

export type WalletImportType = 'mnemonic' | 'private_key' | 'wif' | 'keystore';

export interface ImportWalletForm {
  name: string;
  network: string;
  importType: WalletImportType;
  data: string;
  password: string;
  addressCount: number;
}

interface ImportWalletModalProps {
  form: ImportWalletForm;
  setForm: React.Dispatch<React.SetStateAction<ImportWalletForm>>;
  onImport: () => void;
  /** 关闭并复位表单（父层负责） */
  onClose: () => void;
}

/** 导入钱包弹窗：助记词/私钥/WIF/keystore 四种来源，类型联动网络与地址数 */
const ImportWalletModal: React.FC<ImportWalletModalProps> = ({
  form,
  setForm,
  onImport,
  onClose,
}) => {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold mb-4">{t('wallet.importTitle')}</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.nameLabel')}</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
              placeholder={t('wallet.importedPlaceholder')}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.networkLabel')}</label>
              <select
                value={form.network}
                onChange={(e) => setForm({ ...form, network: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
                disabled={form.importType === 'wif' || form.importType === 'keystore'}
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
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('wallet.colType')}</label>
              <select
                value={form.importType}
                onChange={(e) =>
                  setForm({
                    ...form,
                    importType: e.target.value as WalletImportType,
                    network:
                      e.target.value === 'wif'
                        ? 'Bitcoin'
                        : e.target.value === 'keystore'
                          ? 'Ethereum'
                          : form.network,
                  })
                }
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
              >
                <option value="mnemonic">{t('wallet.importMnemonic')}</option>
                <option value="private_key">{t('wallet.importPrivateKey')}</option>
                <option value="wif">Bitcoin WIF</option>
                <option value="keystore">Ethereum keystore v3</option>
              </select>
            </div>
          </div>
          {form.importType === 'mnemonic' && (
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
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {form.importType === 'mnemonic'
                ? t('wallet.importMnemonic')
                : form.importType === 'wif'
                  ? 'Bitcoin WIF'
                  : form.importType === 'keystore'
                    ? 'Ethereum keystore v3'
                    : t('wallet.importPrivateKey')}
            </label>
            <textarea
              value={form.data}
              onChange={(e) => setForm({ ...form, data: e.target.value })}
              className="w-full h-24 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm"
              placeholder={
                form.importType === 'mnemonic'
                  ? 'word1 word2 word3 ...'
                  : form.importType === 'wif'
                    ? 'K... / L...'
                    : form.importType === 'keystore'
                      ? '{"crypto": {"cipher": "aes-128-ctr"}}'
                      : '0x... / hex'
              }
            />
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
              onClick={onImport}
              className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
              disabled={!form.name.trim() || !form.data.trim() || !form.password}
            >
              {t('wallet.import')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ImportWalletModal;
