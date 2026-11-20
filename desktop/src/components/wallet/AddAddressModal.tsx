import React from 'react';
import { useTranslation } from 'react-i18next';

interface AddAddressModalProps {
  walletName: string | undefined;
  password: string;
  setPassword: (value: string) => void;
  onGenerate: () => void;
  /** 关闭并清空密码（父层负责） */
  onClose: () => void;
}

/** 加地址弹窗：输入钱包密码派生新地址 */
const AddAddressModal: React.FC<AddAddressModalProps> = ({
  walletName,
  password,
  setPassword,
  onGenerate,
  onClose,
}) => {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold mb-4">{t('wallet.generateAddress')}</h3>
        <div className="space-y-4">
          <div className="text-sm text-gray-600 dark:text-gray-300">
            {t('wallet.enterPasswordPrefix')}<span className="font-medium">{walletName}</span>{t('wallet.enterPasswordSuffix')}
          </div>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg"
            placeholder={t('wallet.passwordPlaceholder')}
          />
          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="whitespace-nowrap flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
            >
              {t('common.cancel')}
            </button>
            <button
              onClick={onGenerate}
              className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
              disabled={!password}
            >
              {t('wallet.generate')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddAddressModal;
