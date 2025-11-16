import React, { useState } from 'react';
import {
  KeyIcon,
  WalletIcon,
  ServerIcon,
  CreditCardIcon,
  ShieldCheckIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  EyeIcon,
  EyeSlashIcon,
  DocumentDuplicateIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { Credential } from '@/types';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';

const getCredentialIcon = (type: string) => {
  switch (type) {
    case 'Password':
      return KeyIcon;
    case 'CryptoWallet':
      return WalletIcon;
    case 'SshKey':
    case 'ServerConfig':
      return ServerIcon;
    case 'BankCard':
      return CreditCardIcon;
    case 'ApiKey':
    case 'Certificate':
    case 'TwoFactor':
    default:
      return ShieldCheckIcon;
  }
};

const getSecurityColor = (level: string) => {
  switch (level) {
    case 'Critical':
      return 'bg-red-100 text-red-800 border-red-200';
    case 'High':
      return 'bg-orange-100 text-orange-800 border-orange-200';
    case 'Medium':
      return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    case 'Low':
      return 'bg-green-100 text-green-800 border-green-200';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200';
  }
};

interface CredentialListProps {
  onCreateCredential: () => void;
}

const CredentialList: React.FC<CredentialListProps> = ({ onCreateCredential }) => {
  const { credentials, currentIdentity, getCredentialData } = usePersonaService();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCredential, setSelectedCredential] = useState<Credential | null>(null);
  const [showCredentialData, setShowCredentialData] = useState(false);
  const [credentialData, setCredentialData] = useState<any>(null);

  const filteredCredentials = credentials.filter(cred =>
    cred.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    cred.credential_type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleCredentialClick = async (credential: Credential) => {
    setSelectedCredential(credential);
    const data = await getCredentialData(credential.id);
    setCredentialData(data);
    setShowCredentialData(true);
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} copied to clipboard`);
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  if (!currentIdentity) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500">
        <div className="text-center">
          <KeyIcon className="w-12 h-12 mx-auto mb-4 text-gray-300" />
          <p>Select an identity to view credentials</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium text-gray-900">
            Credentials for {currentIdentity.name}
          </h2>
          <p className="text-sm text-gray-500">
            {filteredCredentials.length} credential{filteredCredentials.length !== 1 ? 's' : ''}
          </p>
        </div>
        <button
          onClick={onCreateCredential}
          className="btn-primary flex items-center"
        >
          <PlusIcon className="w-4 h-4 mr-2" />
          Add Credential
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="input pl-10"
          placeholder="Search credentials..."
        />
      </div>

      {/* Credentials Grid */}
      {filteredCredentials.length === 0 ? (
        <div className="text-center py-12">
          <KeyIcon className="w-12 h-12 mx-auto mb-4 text-gray-300" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No credentials found</h3>
          <p className="text-gray-500 mb-4">
            {searchQuery ? 'Try adjusting your search terms' : 'Get started by adding your first credential'}
          </p>
          {!searchQuery && (
            <button onClick={onCreateCredential} className="btn-primary">
              Add Your First Credential
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredCredentials.map((credential) => {
            const IconComponent = getCredentialIcon(credential.credential_type);
            return (
              <div
                key={credential.id}
                onClick={() => handleCredentialClick(credential)}
                className="card p-4 cursor-pointer hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center">
                    <div className="p-2 bg-primary-100 rounded-lg mr-3">
                      <IconComponent className="w-5 h-5 text-primary-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-medium text-gray-900 truncate">
                        {credential.name}
                      </h3>
                      <p className="text-xs text-gray-500">
                        {credential.credential_type}
                      </p>
                    </div>
                  </div>
                  {credential.is_favorite && (
                    <HeartSolidIcon className="w-4 h-4 text-red-500" />
                  )}
                </div>

                <div className="flex items-center justify-between">
                  <span className={clsx(
                    'px-2 py-1 text-xs font-medium rounded-full border',
                    getSecurityColor(credential.security_level)
                  )}>
                    {credential.security_level}
                  </span>
                  {credential.url && (
                    <span className="text-xs text-gray-400 truncate ml-2">
                      {new URL(credential.url).hostname}
                    </span>
                  )}
                </div>

                {credential.last_accessed && (
                  <p className="text-xs text-gray-400 mt-2">
                    Last used: {new Date(credential.last_accessed).toLocaleDateString()}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Credential Detail Modal */}
      {showCredentialData && selectedCredential && (
        <CredentialDetailModal
          credential={selectedCredential}
          credentialData={credentialData}
          onClose={() => {
            setShowCredentialData(false);
            setSelectedCredential(null);
            setCredentialData(null);
          }}
          onCopy={copyToClipboard}
        />
      )}
    </div>
  );
};

interface CredentialDetailModalProps {
  credential: Credential;
  credentialData: any;
  onClose: () => void;
  onCopy: (text: string, label: string) => void;
}

const CredentialDetailModal: React.FC<CredentialDetailModalProps> = ({
  credential,
  credentialData,
  onClose,
  onCopy,
}) => {
  const [showSensitive, setShowSensitive] = useState(false);
  const IconComponent = getCredentialIcon(credential.credential_type);

  const renderCredentialData = () => {
    if (!credentialData?.data) return null;

    const data = credentialData.data;

    switch (credentialData.credential_type) {
      case 'Password':
        return (
          <div className="space-y-3">
            {data.email && (
              <div>
                <label className="label text-gray-600">Email</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">{data.email}</span>
                  <button
                    onClick={() => onCopy(data.email, 'Email')}
                    className="p-1 hover:bg-gray-100 rounded"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                  </button>
                </div>
              </div>
            )}
            <div>
              <label className="label text-gray-600">Password</label>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono">
                  {showSensitive ? data.password : '••••••••••••'}
                </span>
                <button
                  onClick={() => setShowSensitive(!showSensitive)}
                  className="p-1 hover:bg-gray-100 rounded"
                >
                  {showSensitive ? (
                    <EyeSlashIcon className="w-4 h-4 text-gray-400" />
                  ) : (
                    <EyeIcon className="w-4 h-4 text-gray-400" />
                  )}
                </button>
                <button
                  onClick={() => onCopy(data.password, 'Password')}
                  className="p-1 hover:bg-gray-100 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                </button>
              </div>
            </div>
          </div>
        );

      case 'CryptoWallet':
        return (
          <div className="space-y-3">
            <div>
              <label className="label text-gray-600">Wallet Type</label>
              <span className="text-sm">{data.wallet_type}</span>
            </div>
            <div>
              <label className="label text-gray-600">Address</label>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono break-all">{data.address}</span>
                <button
                  onClick={() => onCopy(data.address, 'Address')}
                  className="p-1 hover:bg-gray-100 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                </button>
              </div>
            </div>
            <div>
              <label className="label text-gray-600">Network</label>
              <span className="text-sm">{data.network}</span>
            </div>
          </div>
        );

      default:
        return (
          <div className="text-sm text-gray-500">
            Credential data is encrypted and secure.
          </div>
        );
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <div className="p-2 bg-primary-100 rounded-lg mr-3">
              <IconComponent className="w-5 h-5 text-primary-600" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-gray-900">{credential.name}</h2>
              <p className="text-sm text-gray-500">{credential.credential_type}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg"
          >
            ✕
          </button>
        </div>

        <div className="space-y-4">
          {credential.url && (
            <div>
              <label className="label text-gray-600">URL</label>
              <div className="flex items-center gap-2">
                <span className="text-sm break-all">{credential.url}</span>
                <button
                  onClick={() => onCopy(credential.url!, 'URL')}
                  className="p-1 hover:bg-gray-100 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                </button>
              </div>
            </div>
          )}

          {credential.username && (
            <div>
              <label className="label text-gray-600">Username</label>
              <div className="flex items-center gap-2">
                <span className="text-sm">{credential.username}</span>
                <button
                  onClick={() => onCopy(credential.username!, 'Username')}
                  className="p-1 hover:bg-gray-100 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
                </button>
              </div>
            </div>
          )}

          {renderCredentialData()}

          {credential.notes && (
            <div>
              <label className="label text-gray-600">Notes</label>
              <p className="text-sm text-gray-700">{credential.notes}</p>
            </div>
          )}

          <div className="flex items-center justify-between pt-4 border-t">
            <span className={clsx(
              'px-2 py-1 text-xs font-medium rounded-full border',
              getSecurityColor(credential.security_level)
            )}>
              {credential.security_level}
            </span>
            <span className="text-xs text-gray-400">
              Created: {new Date(credential.created_at).toLocaleDateString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CredentialList;