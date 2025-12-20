import React, { useState, useEffect } from 'react';
import {
  WalletIcon,
  PlusIcon,
  EyeIcon,
  ArrowDownTrayIcon,
  ArrowUpTrayIcon,
  QrCodeIcon,
  ArrowTrendingUpIcon,
} from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';
import { LoadingSpinner, ErrorDisplay, ErrorBoundary } from '@/components/ErrorHandling';

interface Wallet {
  id: string;
  name: string;
  network: string;
  balance: string;
  addressCount: number;
  type: string;
  watchOnly: boolean;
  createdAt: string;
}

interface WalletAddress {
  address: string;
  type: string;
  index: number;
  used: boolean;
  balance: string;
}

const WalletPanel: React.FC = () => {
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [selectedWallet, setSelectedWallet] = useState<Wallet | null>(null);
  const [addresses, setAddresses] = useState<WalletAddress[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showAddressQr, setShowAddressQr] = useState<string | null>(null);
  const { invoke } = usePersonaService();

  // Load wallets on component mount
  useEffect(() => {
    loadWallets();
  }, []);

  // Load addresses when wallet is selected
  useEffect(() => {
    if (selectedWallet) {
      loadAddresses(selectedWallet.id);
    }
  }, [selectedWallet]);

  const loadWallets = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const result = await invoke('wallet_list');
      setWallets(result.wallets || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load wallets');
    } finally {
      setIsLoading(false);
    }
  };

  const loadAddresses = async (walletId: string) => {
    try {
      const result = await invoke('wallet_list_addresses', { walletId });
      setAddresses(result.addresses || []);
    } catch (err: any) {
      console.error('Failed to load addresses:', err);
    }
  };

  const exportWallet = async (walletId: string) => {
    try {
      const result = await invoke('wallet_export', { walletId });
      // Trigger download of wallet data
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `wallet-${walletId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || 'Failed to export wallet');
    }
  };

  const getNetworkIcon = (network: string) => {
    switch (network.toLowerCase()) {
      case 'bitcoin':
      case 'btc':
        return '₿';
      case 'ethereum':
      case 'eth':
        return 'Ξ';
      case 'solana':
      case 'sol':
        return '◎';
      default:
        return '💰';
    }
  };

  const getNetworkColor = (network: string) => {
    switch (network.toLowerCase()) {
      case 'bitcoin':
      case 'btc':
        return 'text-orange-600 bg-orange-100';
      case 'ethereum':
      case 'eth':
        return 'text-blue-600 bg-blue-100';
      case 'solana':
      case 'sol':
        return 'text-purple-600 bg-purple-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              <WalletIcon className="h-8 w-8 text-indigo-600" />
              Crypto Wallets
            </h2>
            <p className="mt-1 text-sm text-gray-500">
              Manage your cryptocurrency wallets
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowImportModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <ArrowDownTrayIcon className="h-5 w-5" />
              Import
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
            >
              <PlusIcon className="h-5 w-5" />
              New Wallet
            </button>
          </div>
        </div>

        {/* Error Display */}
        {error && <ErrorDisplay message={error} onDismiss={() => setError(null)} />}

        {/* Loading State */}
        {isLoading && wallets.length === 0 && (
          <div className="flex justify-center py-12">
            <LoadingSpinner message="Loading wallets..." />
          </div>
        )}

        {/* Wallet Grid */}
        {!isLoading && wallets.length === 0 && !error && (
          <div className="text-center py-12 bg-white rounded-lg border border-gray-200">
            <WalletIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-semibold text-gray-900">No wallets</h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by creating a new wallet or importing an existing one.
            </p>
            <div className="mt-6 flex justify-center gap-2">
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
              >
                Create Wallet
              </button>
              <button
                onClick={() => setShowImportModal(true)}
                className="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Import Wallet
              </button>
            </div>
          </div>
        )}

        {wallets.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {wallets.map((wallet) => (
              <div
                key={wallet.id}
                className={`bg-white rounded-lg border ${
                  selectedWallet?.id === wallet.id
                    ? 'border-indigo-500 ring-2 ring-indigo-200'
                    : 'border-gray-200'
                } p-4 cursor-pointer hover:shadow-lg transition-all`}
                onClick={() => setSelectedWallet(wallet)}
              >
                {/* Wallet Header */}
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{getNetworkIcon(wallet.network)}</span>
                      <h3 className="font-semibold text-gray-900">{wallet.name}</h3>
                    </div>
                    <span
                      className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mt-1 ${getNetworkColor(
                        wallet.network
                      )}`}
                    >
                      {wallet.network}
                    </span>
                  </div>
                  {wallet.watchOnly && (
                    <EyeIcon className="h-5 w-5 text-gray-400" title="Watch-only" />
                  )}
                </div>

                {/* Balance */}
                <div className="mb-3">
                  <p className="text-sm text-gray-500">Balance</p>
                  <p className="text-2xl font-bold text-gray-900">{wallet.balance}</p>
                </div>

                {/* Wallet Info */}
                <div className="space-y-1 text-sm text-gray-600">
                  <div className="flex justify-between">
                    <span>Type:</span>
                    <span className="font-medium">{wallet.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Addresses:</span>
                    <span className="font-medium">{wallet.addressCount}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      exportWallet(wallet.id);
                    }}
                    className="flex-1 flex items-center justify-center gap-1 px-2 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
                  >
                    <ArrowUpTrayIcon className="h-4 w-4" />
                    Export
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Refresh wallet balance
                      loadWallets();
                    }}
                    className="flex-1 flex items-center justify-center gap-1 px-2 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
                  >
                    <ArrowTrendingUpIcon className="h-4 w-4" />
                    Refresh
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Selected Wallet Details */}
        {selectedWallet && (
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">
                Wallet Addresses - {selectedWallet.name}
              </h3>
              <button
                onClick={() => {
                  // Generate new address
                  invoke('wallet_add_address', {
                    walletId: selectedWallet.id,
                  }).then(() => {
                    loadAddresses(selectedWallet.id);
                  });
                }}
                className="flex items-center gap-2 px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 transition-colors"
              >
                <PlusIcon className="h-4 w-4" />
                Generate Address
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead>
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Index
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Address
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Type
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Balance
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Status
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {addresses.map((address, index) => (
                    <tr key={index}>
                      <td className="px-4 py-2 text-sm text-gray-900">
                        {address.index}
                      </td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono text-gray-900">
                            {address.address}
                          </code>
                          <button
                            onClick={() => setShowAddressQr(address.address)}
                            className="text-gray-400 hover:text-gray-600"
                            title="Show QR Code"
                          >
                            <QrCodeIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-900">
                        {address.type}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-900">
                        {address.balance}
                      </td>
                      <td className="px-4 py-2">
                        <span
                          className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                            address.used
                              ? 'bg-gray-100 text-gray-800'
                              : 'bg-green-100 text-green-800'
                          }`}
                        >
                          {address.used ? 'Used' : 'Unused'}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(address.address);
                          }}
                          className="text-indigo-600 hover:text-indigo-800 text-sm"
                        >
                          Copy
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {addresses.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  No addresses generated yet
                </div>
              )}
            </div>
          </div>
        )}

        {/* QR Code Modal */}
        {showAddressQr && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
            onClick={() => setShowAddressQr(null)}
          >
            <div
              className="bg-white rounded-lg p-6 max-w-sm w-full mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4">Receive Address</h3>
              <div className="bg-gray-100 p-4 rounded-lg mb-4">
                {/* QR Code would go here - using placeholder for now */}
                <div className="aspect-square bg-gray-200 rounded flex items-center justify-center">
                  <QrCodeIcon className="h-32 w-32 text-gray-400" />
                </div>
              </div>
              <code className="block text-sm text-center text-gray-600 mb-4 break-all">
                {showAddressQr}
              </code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(showAddressQr);
                  setShowAddressQr(null);
                }}
                className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
              >
                Copy Address
              </button>
            </div>
          </div>
        )}

        {/* Create Wallet Modal Placeholder */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Create New Wallet</h3>
              <p className="text-gray-600 mb-4">
                Wallet creation functionality will be implemented in the Tauri commands.
              </p>
              <button
                onClick={() => setShowCreateModal(false)}
                className="w-full px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        )}

        {/* Import Wallet Modal Placeholder */}
        {showImportModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Import Wallet</h3>
              <p className="text-gray-600 mb-4">
                Wallet import functionality will be implemented in the Tauri commands.
              </p>
              <button
                onClick={() => setShowImportModal(false)}
                className="w-full px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default WalletPanel;
