import React from 'react';
import { useTranslation } from 'react-i18next';
import { PlusIcon, QrCodeIcon } from '@heroicons/react/24/outline';
import type { WalletAddress, WalletSummary } from '@/types';

interface SelectedWalletAddressesProps {
  wallet: WalletSummary;
  addresses: WalletAddress[];
  onGenerate: () => void;
  /** 打开该地址的二维码弹窗 */
  onShowQr: (address: string) => void;
}

/** 选中钱包的地址面板：标题行 + 地址表（QR/复制动作）+ 空态 */
const SelectedWalletAddresses: React.FC<SelectedWalletAddressesProps> = ({
  wallet,
  addresses,
  onGenerate,
  onShowQr,
}) => {
  const { t } = useTranslation();
  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          {t('wallet.addressesTitle', { name: wallet.name })}
        </h3>
        <button
          onClick={onGenerate}
          className="whitespace-nowrap flex items-center gap-2 px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 transition-colors"
        >
          <PlusIcon className="h-4 w-4" />
          {t('wallet.generateAddress')}
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead>
            <tr>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colIndex')}
              </th>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colAddress')}
              </th>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colType')}
              </th>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colBalance')}
              </th>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colStatus')}
              </th>
              <th className="whitespace-nowrap px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                {t('wallet.colActions')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {addresses.map((address, index) => (
              <tr key={index}>
                <td className="px-4 py-2 text-sm text-gray-900 dark:text-gray-100">
                  {address.index}
                </td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-mono text-gray-900 dark:text-gray-100">
                      {address.address}
                    </code>
                    <button
                      onClick={() => onShowQr(address.address)}
                      className="whitespace-nowrap text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300"
                      title={t('wallet.showQr')}
                    >
                      <QrCodeIcon className="h-4 w-4" />
                    </button>
                  </div>
                </td>
                <td className="px-4 py-2 text-sm text-gray-900 dark:text-gray-100">
                  {address.address_type}
                </td>
                <td className="px-4 py-2 text-sm text-gray-900 dark:text-gray-100">
                  {address.balance}
                </td>
                <td className="px-4 py-2">
                  <span
                    className={`whitespace-nowrap inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                      address.used
                        ? 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
                        : 'bg-green-100 dark:bg-green-500/10 text-green-800 dark:text-green-300'
                    }`}
                  >
                    {address.used ? t('wallet.used') : t('wallet.unused')}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(address.address);
                    }}
                    className="text-indigo-600 hover:text-indigo-800 text-sm"
                  >
                    {t('common.copy')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {addresses.length === 0 && (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            {t('wallet.noAddresses')}
          </div>
        )}
      </div>
    </div>
  );
};

export default SelectedWalletAddresses;
