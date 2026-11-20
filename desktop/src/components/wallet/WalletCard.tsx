import React from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowTrendingUpIcon,
  ArrowUpTrayIcon,
  EyeIcon,
  PaperAirplaneIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { getNetworkColor, getNetworkIcon } from './networkDisplay';
import type { WalletSummary } from '@/types';

interface WalletCardProps {
  wallet: WalletSummary;
  /** 当前选中卡的描边态（父层由 selectedWallet?.id 派生） */
  selected: boolean;
  onSelect: (wallet: WalletSummary) => void;
  /** 发送 = 选中（未选中时触发地址加载做投毒检测）+ 打开签名弹窗 */
  onSend: (wallet: WalletSummary) => void;
  onExport: (wallet: WalletSummary) => void;
  /** 刷新即重新拉取钱包列表（余额随服务端刷新） */
  onRefresh: () => void;
  onDelete: (wallet: WalletSummary) => void;
}

/** 钱包网格单卡：网络徽标 + 余额 + 操作行；卡体可点选中，操作按钮 stopPropagation */
const WalletCard: React.FC<WalletCardProps> = ({
  wallet,
  selected,
  onSelect,
  onSend,
  onExport,
  onRefresh,
  onDelete,
}) => {
  const { t } = useTranslation();
  return (
    <div
      className={`bg-white dark:bg-gray-900 rounded-lg border ${
        selected
          ? 'border-indigo-500 ring-2 ring-indigo-200 dark:ring-indigo-500/30'
          : 'border-gray-200 dark:border-gray-700'
      } p-4 cursor-pointer hover:shadow-lg transition-all`}
      onClick={() => onSelect(wallet)}
    >
      {/* Wallet Header */}
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">{getNetworkIcon(wallet.network)}</span>
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">{wallet.name}</h3>
          </div>
          <span
            className={`whitespace-nowrap inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mt-1 ${getNetworkColor(
              wallet.network
            )}`}
          >
            {wallet.network}
          </span>
        </div>
        {wallet.watch_only && (
          <EyeIcon className="h-5 w-5 text-gray-400 dark:text-gray-500" title={t('wallet.watchOnly')} />
        )}
      </div>

      {/* Balance */}
      <div className="mb-3">
        <p className="text-sm text-gray-500 dark:text-gray-400">{t('wallet.balance')}</p>
        <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{wallet.balance}</p>
      </div>

      {/* Wallet Info */}
      <div className="space-y-1 text-sm text-gray-600 dark:text-gray-300">
        <div className="flex justify-between">
          <span>{t('wallet.typeLabel')}</span>
          <span className="font-medium">{wallet.wallet_type}</span>
        </div>
        <div className="flex justify-between">
          <span>{t('wallet.addressesLabel')}</span>
          <span className="font-medium">{wallet.address_count}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="mt-4 flex gap-2">
        <button
          onClick={async (e) => {
            e.stopPropagation();
            onSend(wallet);
          }}
          className="whitespace-nowrap flex-1 flex items-center justify-center gap-1 px-2 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 transition-colors"
          data-testid={`send-button-${wallet.id}`}
        >
          <PaperAirplaneIcon className="h-4 w-4" />
          {t('wallet.send')}
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onExport(wallet);
          }}
          className="whitespace-nowrap flex-1 flex items-center justify-center gap-1 px-2 py-1 text-sm bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
        >
          <ArrowUpTrayIcon className="h-4 w-4" />
          {t('wallet.export')}
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onRefresh();
          }}
          className="whitespace-nowrap flex-1 flex items-center justify-center gap-1 px-2 py-1 text-sm bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
          >
          <ArrowTrendingUpIcon className="h-4 w-4" />
          {t('wallet.refresh')}
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete(wallet);
          }}
          className="flex items-center justify-center gap-1 px-2 py-1 text-sm bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300 rounded hover:bg-red-100 dark:hover:bg-red-500/20 transition-colors"
          aria-label={t('wallet.deleteWalletAria', { name: wallet.name })}
        >
          <TrashIcon className="h-4 w-4" />
          {t('common.delete')}
        </button>
      </div>
    </div>
  );
};

export default WalletCard;
