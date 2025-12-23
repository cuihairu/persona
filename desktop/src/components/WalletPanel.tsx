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
import { LoadingSpinner, ErrorDisplay, ErrorBoundary } from '@/components/ErrorHandling';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { WalletAddress, WalletGenerateResponse, WalletSummary } from '@/types';

const WalletPanel: React.FC = () => {
  const { currentIdentity } = usePersonaService();
  const [wallets, setWallets] = useState<WalletSummary[]>([]);
  const [selectedWallet, setSelectedWallet] = useState<WalletSummary | null>(null);
  const [addresses, setAddresses] = useState<WalletAddress[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showAddressQr, setShowAddressQr] = useState<string | null>(null);
  const [showAddAddressModal, setShowAddAddressModal] = useState(false);
  const [addAddressPassword, setAddAddressPassword] = useState('');
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportWalletId, setExportWalletId] = useState<string | null>(null);
  const [exportWalletName, setExportWalletName] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<'json' | 'xpub' | 'mnemonic' | 'private_key'>(
    'json',
  );
  const [exportIncludePrivate, setExportIncludePrivate] = useState(false);
  const [exportPassword, setExportPassword] = useState('');
  const [exportOutput, setExportOutput] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState({
    name: '',
    network: 'Ethereum',
    password: '',
    addressCount: 5,
  });
  const [createResult, setCreateResult] = useState<WalletGenerateResponse | null>(null);
  const [importForm, setImportForm] = useState({
    name: '',
    network: 'Ethereum',
    importType: 'mnemonic' as 'mnemonic' | 'private_key',
    data: '',
    password: '',
    addressCount: 5,
  });

  // Load wallets on component mount
  useEffect(() => {
    loadWallets();
  }, [currentIdentity?.id]);

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
      if (!currentIdentity) {
        setWallets([]);
        setSelectedWallet(null);
        setAddresses([]);
        return;
      }
      const response = await personaAPI.walletList(currentIdentity.id);
      if (!response.success) {
        throw new Error(response.error || 'Failed to load wallets');
      }
      setWallets(response.data?.wallets || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load wallets');
    } finally {
      setIsLoading(false);
    }
  };

  const loadAddresses = async (walletId: string) => {
    try {
      const response = await personaAPI.walletListAddresses(walletId);
      if (!response.success) {
        throw new Error(response.error || 'Failed to load addresses');
      }
      setAddresses(response.data?.addresses || []);
    } catch (err: any) {
      console.error('Failed to load addresses:', err);
    }
  };

  const exportWallet = (walletId: string, walletName: string) => {
    setExportWalletId(walletId);
    setExportWalletName(walletName);
    setExportFormat('json');
    setExportIncludePrivate(false);
    setExportPassword('');
    setExportOutput(null);
    setShowExportModal(true);
  };

  const closeExportModal = () => {
    setShowExportModal(false);
    setExportWalletId(null);
    setExportWalletName(null);
    setExportFormat('json');
    setExportIncludePrivate(false);
    setExportPassword('');
    setExportOutput(null);
  };

  const performExport = async () => {
    try {
      if (!exportWalletId) {
        throw new Error('No wallet selected');
      }
      setError(null);

      const needsPassword =
        exportFormat === 'mnemonic' ||
        exportFormat === 'private_key' ||
        (exportFormat === 'json' && exportIncludePrivate);
      if (needsPassword && !exportPassword) {
        throw new Error('Password required');
      }

      const response = await personaAPI.walletExport({
        wallet_id: exportWalletId,
        format: exportFormat,
        include_private: exportFormat === 'json' ? exportIncludePrivate : false,
        password: needsPassword ? exportPassword : undefined,
      });
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to export wallet');
      }

      setExportOutput(response.data);

      if (exportFormat === 'json') {
        const blob = new Blob([response.data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wallet-${exportWalletId}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to export wallet');
    }
  };

  const createWallet = async () => {
    try {
      if (!currentIdentity) {
        throw new Error('Select an identity first');
      }
      setError(null);
      const response = await personaAPI.walletGenerate(currentIdentity.id, {
        name: createForm.name.trim(),
        network: createForm.network,
        wallet_type: 'hd',
        password: createForm.password,
        address_count: createForm.addressCount,
      });
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to create wallet');
      }
      setCreateResult(response.data);
      await loadWallets();
    } catch (err: any) {
      setError(err.message || 'Failed to create wallet');
    }
  };

  const importWallet = async () => {
    try {
      if (!currentIdentity) {
        throw new Error('Select an identity first');
      }
      setError(null);
      const response = await personaAPI.walletImport(currentIdentity.id, {
        name: importForm.name.trim(),
        network: importForm.network,
        import_type: importForm.importType,
        data: importForm.data,
        password: importForm.password,
        address_count: importForm.importType === 'mnemonic' ? importForm.addressCount : undefined,
      });
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to import wallet');
      }
      setShowImportModal(false);
      setImportForm({
        name: '',
        network: 'Ethereum',
        importType: 'mnemonic',
        data: '',
        password: '',
        addressCount: 5,
      });
      await loadWallets();
    } catch (err: any) {
      setError(err.message || 'Failed to import wallet');
    }
  };

  const addAddress = async () => {
    try {
      if (!selectedWallet) {
        throw new Error('Select a wallet first');
      }
      setError(null);
      const response = await personaAPI.walletAddAddress(selectedWallet.id, addAddressPassword);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to generate address');
      }
      setShowAddAddressModal(false);
      setAddAddressPassword('');
      await loadAddresses(selectedWallet.id);
      await loadWallets();
    } catch (err: any) {
      setError(err.message || 'Failed to generate address');
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
        {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}

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
                  {wallet.watch_only && (
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
                    <span className="font-medium">{wallet.wallet_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Addresses:</span>
                    <span className="font-medium">{wallet.address_count}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      exportWallet(wallet.id, wallet.name);
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
                  setShowAddAddressModal(true);
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
                        {address.address_type}
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
              {!createResult ? (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                    <input
                      value={createForm.name}
                      onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                      placeholder="My Wallet"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Network</label>
                      <select
                        value={createForm.network}
                        onChange={(e) => setCreateForm({ ...createForm, network: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg"
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
                      <label className="block text-sm font-medium text-gray-700 mb-1">Addresses</label>
                      <input
                        type="number"
                        min={1}
                        max={100}
                        value={createForm.addressCount}
                        onChange={(e) =>
                          setCreateForm({
                            ...createForm,
                            addressCount: Number(e.target.value || 5),
                          })
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Wallet Password</label>
                    <input
                      type="password"
                      value={createForm.password}
                      onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                      placeholder="At least 8 characters"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        setShowCreateModal(false);
                        setCreateResult(null);
                        setCreateForm({
                          name: '',
                          network: 'Ethereum',
                          password: '',
                          addressCount: 5,
                        });
                      }}
                      className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={createWallet}
                      className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                      disabled={!createForm.name.trim() || !createForm.password}
                    >
                      Create
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-gray-700">
                    Save this recovery phrase now. It will not be shown again.
                  </p>
                  <textarea
                    readOnly
                    value={createResult.mnemonic}
                    className="w-full h-28 px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm"
                  />
                  <div className="text-sm text-gray-600">
                    First address: <code className="font-mono">{createResult.first_address}</code>
                  </div>
                  <button
                    onClick={() => {
                      setShowCreateModal(false);
                      setCreateResult(null);
                      setCreateForm({
                        name: '',
                        network: 'Ethereum',
                        password: '',
                        addressCount: 5,
                      });
                    }}
                    className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                  >
                    Done
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Import Wallet Modal */}
        {showImportModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Import Wallet</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                  <input
                    value={importForm.name}
                    onChange={(e) => setImportForm({ ...importForm, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                    placeholder="Imported Wallet"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Network</label>
                    <select
                      value={importForm.network}
                      onChange={(e) => setImportForm({ ...importForm, network: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
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
                    <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                    <select
                      value={importForm.importType}
                      onChange={(e) =>
                        setImportForm({
                          ...importForm,
                          importType: e.target.value as 'mnemonic' | 'private_key',
                        })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                    >
                      <option value="mnemonic">Mnemonic</option>
                      <option value="private_key">Private Key</option>
                    </select>
                  </div>
                </div>
                {importForm.importType === 'mnemonic' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Addresses</label>
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={importForm.addressCount}
                      onChange={(e) =>
                        setImportForm({
                          ...importForm,
                          addressCount: Number(e.target.value || 5),
                        })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                    />
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    {importForm.importType === 'mnemonic' ? 'Mnemonic Phrase' : 'Private Key'}
                  </label>
                  <textarea
                    value={importForm.data}
                    onChange={(e) => setImportForm({ ...importForm, data: e.target.value })}
                    className="w-full h-24 px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm"
                    placeholder={
                      importForm.importType === 'mnemonic'
                        ? 'word1 word2 word3 ...'
                        : '0x... / hex'
                    }
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Wallet Password</label>
                  <input
                    type="password"
                    value={importForm.password}
                    onChange={(e) => setImportForm({ ...importForm, password: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                    placeholder="At least 8 characters"
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setShowImportModal(false);
                      setImportForm({
                        name: '',
                        network: 'Ethereum',
                        importType: 'mnemonic',
                        data: '',
                        password: '',
                        addressCount: 5,
                      });
                    }}
                    className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={importWallet}
                    className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                    disabled={!importForm.name.trim() || !importForm.data.trim() || !importForm.password}
                  >
                    Import
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Add Address Modal */}
        {showAddAddressModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Generate Address</h3>
              <div className="space-y-4">
                <div className="text-sm text-gray-600">
                  Enter the wallet password for <span className="font-medium">{selectedWallet?.name}</span>.
                </div>
                <input
                  type="password"
                  value={addAddressPassword}
                  onChange={(e) => setAddAddressPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  placeholder="Wallet password"
                />
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      setShowAddAddressModal(false);
                      setAddAddressPassword('');
                    }}
                    className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={addAddress}
                    className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                    disabled={!addAddressPassword}
                  >
                    Generate
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Export Modal */}
        {showExportModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Export Wallet</h3>
              <div className="text-sm text-gray-600 mb-4">
                {exportWalletName ? (
                  <>
                    Wallet: <span className="font-medium">{exportWalletName}</span>
                  </>
                ) : (
                  'Wallet export'
                )}
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Format</label>
                  <select
                    value={exportFormat}
                    onChange={(e) => {
                      const value = e.target.value as typeof exportFormat;
                      setExportFormat(value);
                      setExportOutput(null);
                      if (value !== 'json') {
                        setExportIncludePrivate(false);
                      }
                    }}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  >
                    <option value="json">JSON</option>
                    <option value="xpub">XPUB</option>
                    <option value="mnemonic">Mnemonic</option>
                    <option value="private_key">Private Key</option>
                  </select>
                </div>

                {exportFormat === 'json' && (
                  <label className="flex items-center gap-2 text-sm text-gray-700">
                    <input
                      type="checkbox"
                      checked={exportIncludePrivate}
                      onChange={(e) => setExportIncludePrivate(e.target.checked)}
                    />
                    Include private data (requires password)
                  </label>
                )}

                {(exportFormat === 'mnemonic' ||
                  exportFormat === 'private_key' ||
                  (exportFormat === 'json' && exportIncludePrivate)) && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Wallet Password</label>
                    <input
                      type="password"
                      value={exportPassword}
                      onChange={(e) => setExportPassword(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                      placeholder="Wallet password"
                    />
                  </div>
                )}

                {exportOutput && exportFormat !== 'json' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Exported Data</label>
                    <textarea
                      readOnly
                      value={exportOutput}
                      className="w-full h-28 px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm"
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(exportOutput).catch(() => {});
                      }}
                      className="mt-2 w-full px-4 py-2 bg-gray-100 text-gray-800 rounded-lg hover:bg-gray-200 transition-colors"
                    >
                      Copy
                    </button>
                  </div>
                )}

                <div className="flex gap-2">
                  <button
                    onClick={closeExportModal}
                    className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
                  >
                    Close
                  </button>
                  <button
                    onClick={performExport}
                    className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                  >
                    Export
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default WalletPanel;
