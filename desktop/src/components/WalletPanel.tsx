import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowDownTrayIcon,
  PlusIcon,
  WalletIcon,
} from '@heroicons/react/24/outline';
import { LoadingSpinner, ErrorDisplay, ErrorBoundary } from '@/components/ErrorHandling';
import { personaAPI } from '@/utils/api';
import { usePersonaService } from '@/hooks/usePersonaService';
import TransactionConfirmModal from '@/components/TransactionConfirmModal';
import WalletCard from './wallet/WalletCard';
import SelectedWalletAddresses from './wallet/SelectedWalletAddresses';
import AddressQrModal from './wallet/AddressQrModal';
import CreateWalletModal from './wallet/CreateWalletModal';
import type { CreateWalletForm } from './wallet/CreateWalletModal';
import ImportWalletModal from './wallet/ImportWalletModal';
import type { ImportWalletForm } from './wallet/ImportWalletModal';
import AddAddressModal from './wallet/AddAddressModal';
import ExportWalletModal from './wallet/ExportWalletModal';
import {
  getAvailableExportFormats,
  getExportRestrictionHint,
  type WalletExportFormat,
} from './wallet/walletExport';
import type { WalletAddress, WalletGenerateResponse, WalletSummary } from '@/types';

const WalletPanel: React.FC = () => {
  const { t } = useTranslation();
  const { currentIdentity } = usePersonaService();
  const [wallets, setWallets] = useState<WalletSummary[]>([]);
  const [selectedWallet, setSelectedWallet] = useState<WalletSummary | null>(null);
  const [addresses, setAddresses] = useState<WalletAddress[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showAddressQr, setShowAddressQr] = useState<string | null>(null);
  const [sendWallet, setSendWallet] = useState<WalletSummary | null>(null);
  const [showAddAddressModal, setShowAddAddressModal] = useState(false);
  const [addAddressPassword, setAddAddressPassword] = useState('');
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportWalletId, setExportWalletId] = useState<string | null>(null);
  const [exportWalletName, setExportWalletName] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<WalletExportFormat>('json');
  const [exportIncludePrivate, setExportIncludePrivate] = useState(false);
  const [exportPassword, setExportPassword] = useState('');
  const [exportOutput, setExportOutput] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState<CreateWalletForm>({
    name: '',
    network: 'Ethereum',
    password: '',
    addressCount: 5,
  });
  const [createResult, setCreateResult] = useState<WalletGenerateResponse | null>(null);
  const [importForm, setImportForm] = useState<ImportWalletForm>({
    name: '',
    network: 'Ethereum',
    importType: 'mnemonic',
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
        throw new Error(response.error || t('wallet.errors.loadWallets'));
      }
      setWallets(response.data?.wallets || []);
    } catch (err: any) {
      setError(err.message || t('wallet.errors.loadWallets'));
    } finally {
      setIsLoading(false);
    }
  };

  const loadAddresses = async (walletId: string) => {
    try {
      const response = await personaAPI.walletListAddresses(walletId);
      if (!response.success) {
        throw new Error(response.error || t('wallet.errors.loadAddresses'));
      }
      setAddresses(response.data?.addresses || []);
    } catch (err: any) {
      console.error('Failed to load addresses:', err);
    }
  };

  const exportWallet = (wallet: WalletSummary) => {
    setExportWalletId(wallet.id);
    setExportWalletName(wallet.name);
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

  const exportTargetWallet = wallets.find((wallet) => wallet.id === exportWalletId) ?? null;
  const availableExportFormats = getAvailableExportFormats(exportTargetWallet);

  useEffect(() => {
    if (!availableExportFormats.includes(exportFormat)) {
      setExportFormat(availableExportFormats[0] ?? 'json');
      setExportIncludePrivate(false);
      setExportOutput(null);
    }
  }, [availableExportFormats, exportFormat]);

  const exportRestrictionHint = getExportRestrictionHint(t, exportTargetWallet, exportFormat);

  const performExport = async () => {
    try {
      if (!exportWalletId) {
        throw new Error(t('wallet.errors.noWalletSelected'));
      }
      setError(null);

      const needsPassword =
        exportFormat === 'mnemonic' ||
        exportFormat === 'private_key' ||
        exportFormat === 'wif' ||
        exportFormat === 'keystore' ||
        (exportFormat === 'json' && exportIncludePrivate);
      if (needsPassword && !exportPassword) {
        throw new Error(t('wallet.errors.passwordRequired'));
      }

      const response = await personaAPI.walletExport({
        wallet_id: exportWalletId,
        format: exportFormat,
        include_private: exportFormat === 'json' ? exportIncludePrivate : false,
        password: needsPassword ? exportPassword : undefined,
      });
      if (!response.success || !response.data) {
        throw new Error(response.error || t('wallet.errors.exportFailed'));
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
      setError(err.message || t('wallet.errors.exportFailed'));
    }
  };

  const createWallet = async () => {
    try {
      if (!currentIdentity) {
        throw new Error(t('wallet.errors.selectIdentityFirst'));
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
        throw new Error(response.error || t('wallet.errors.createFailed'));
      }
      setCreateResult(response.data);
      await loadWallets();
    } catch (err: any) {
      setError(err.message || t('wallet.errors.createFailed'));
    }
  };

  const closeCreateModal = () => {
    setShowCreateModal(false);
    setCreateResult(null);
    setCreateForm({
      name: '',
      network: 'Ethereum',
      password: '',
      addressCount: 5,
    });
  };

  const importWallet = async () => {
    try {
      if (!currentIdentity) {
        throw new Error(t('wallet.errors.selectIdentityFirst'));
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
        throw new Error(response.error || t('wallet.errors.importFailed'));
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
      setError(err.message || t('wallet.errors.importFailed'));
    }
  };

  const closeImportModal = () => {
    setShowImportModal(false);
    setImportForm({
      name: '',
      network: 'Ethereum',
      importType: 'mnemonic',
      data: '',
      password: '',
      addressCount: 5,
    });
  };

  const addAddress = async () => {
    try {
      if (!selectedWallet) {
        throw new Error(t('wallet.errors.selectWalletFirst'));
      }
      setError(null);
      const response = await personaAPI.walletAddAddress(selectedWallet.id, addAddressPassword);
      if (!response.success || !response.data) {
        throw new Error(response.error || t('wallet.errors.generateAddressFailed'));
      }
      setShowAddAddressModal(false);
      setAddAddressPassword('');
      await loadAddresses(selectedWallet.id);
      await loadWallets();
    } catch (err: any) {
      setError(err.message || t('wallet.errors.generateAddressFailed'));
    }
  };

  const closeAddAddressModal = () => {
    setShowAddAddressModal(false);
    setAddAddressPassword('');
  };

  const deleteWallet = async (wallet: WalletSummary) => {
    const confirmed = window.confirm(t('wallet.errors.deleteConfirm', { name: wallet.name }));
    if (!confirmed) {
      return;
    }

    try {
      setError(null);
      const response = await personaAPI.walletDelete(wallet.id);
      if (!response.success) {
        throw new Error(response.error || t('wallet.errors.deleteFailed'));
      }

      if (selectedWallet?.id === wallet.id) {
        setSelectedWallet(null);
        setAddresses([]);
      }

      await loadWallets();
    } catch (err: any) {
      setError(err.message || t('wallet.errors.deleteFailed'));
    }
  };

  /** Card send button: selects first if unselected (triggering address loading for poisoning detection), then opens the signing modal */
  const sendFromCard = (wallet: WalletSummary) => {
    if (selectedWallet?.id !== wallet.id) {
      setSelectedWallet(wallet);
    }
    setSendWallet(wallet);
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 flex items-center gap-2">
              <WalletIcon className="h-8 w-8 text-indigo-600" />
              {t('wallet.title')}
            </h2>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {t('wallet.subtitle')}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowImportModal(true)}
              className="whitespace-nowrap flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              <ArrowDownTrayIcon className="h-5 w-5" />
              {t('wallet.import')}
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="whitespace-nowrap flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
            >
              <PlusIcon className="h-5 w-5" />
              {t('wallet.newWallet')}
            </button>
          </div>
        </div>

        {/* Error Display */}
        {error && <ErrorDisplay error={error} onDismiss={() => setError(null)} />}

        {/* Loading State */}
        {isLoading && wallets.length === 0 && (
          <div className="flex justify-center py-12">
            <LoadingSpinner message={t('wallet.loadingWallets')} />
          </div>
        )}

        {/* Wallet Grid */}
        {!isLoading && wallets.length === 0 && !error && (
          <div className="text-center py-12 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700">
            <WalletIcon className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
            <h3 className="mt-2 text-sm font-semibold text-gray-900 dark:text-gray-100">{t('wallet.noWallets')}</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {t('wallet.noWalletsHint')}
            </p>
            <div className="mt-6 flex justify-center gap-2">
              <button
                onClick={() => setShowCreateModal(true)}
                className="whitespace-nowrap px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
              >
                {t('wallet.createWallet')}
              </button>
              <button
                onClick={() => setShowImportModal(true)}
                className="px-4 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                {t('wallet.importWallet')}
              </button>
            </div>
          </div>
        )}

        {wallets.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {wallets.map((wallet) => (
              <WalletCard
                key={wallet.id}
                wallet={wallet}
                selected={selectedWallet?.id === wallet.id}
                onSelect={setSelectedWallet}
                onSend={sendFromCard}
                onExport={exportWallet}
                onRefresh={loadWallets}
                onDelete={deleteWallet}
              />
            ))}
          </div>
        )}

        {/* Selected Wallet Details */}
        {selectedWallet && (
          <SelectedWalletAddresses
            wallet={selectedWallet}
            addresses={addresses}
            onGenerate={() => setShowAddAddressModal(true)}
            onShowQr={setShowAddressQr}
          />
        )}

        {/* QR Code Modal */}
        {showAddressQr && (
          <AddressQrModal address={showAddressQr} onClose={() => setShowAddressQr(null)} />
        )}

        {/* Send / Sign Transaction Modal */}
        {sendWallet && (
          <TransactionConfirmModal
            isOpen
            onClose={() => setSendWallet(null)}
            wallet={sendWallet}
            fromAddress={addresses[0]?.address ?? t('wallet.loadingAddress')}
            knownAddresses={
              selectedWallet?.id === sendWallet.id
                ? addresses.map((a) => a.address)
                : []
            }
          />
        )}

        {/* Create Wallet Modal */}
        {showCreateModal && (
          <CreateWalletModal
            form={createForm}
            setForm={setCreateForm}
            result={createResult}
            onCreate={createWallet}
            onClose={closeCreateModal}
          />
        )}

        {/* Import Wallet Modal */}
        {showImportModal && (
          <ImportWalletModal
            form={importForm}
            setForm={setImportForm}
            onImport={importWallet}
            onClose={closeImportModal}
          />
        )}

        {/* Add Address Modal */}
        {showAddAddressModal && (
          <AddAddressModal
            walletName={selectedWallet?.name}
            password={addAddressPassword}
            setPassword={setAddAddressPassword}
            onGenerate={addAddress}
            onClose={closeAddAddressModal}
          />
        )}

        {/* Export Modal */}
        {showExportModal && (
          <ExportWalletModal
            walletName={exportWalletName}
            formats={availableExportFormats}
            restrictionHint={exportRestrictionHint}
            format={exportFormat}
            onFormatChange={(format) => {
              setExportFormat(format);
              setExportOutput(null);
              if (format !== 'json') {
                setExportIncludePrivate(false);
              }
            }}
            includePrivate={exportIncludePrivate}
            onIncludePrivateChange={setExportIncludePrivate}
            password={exportPassword}
            onPasswordChange={setExportPassword}
            output={exportOutput}
            onPerform={performExport}
            onClose={closeExportModal}
          />
        )}
      </div>
    </ErrorBoundary>
  );
};

export default WalletPanel;
