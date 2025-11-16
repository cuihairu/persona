import React, { useState } from 'react';
import { usePersonaService } from '@/hooks/usePersonaService';
import type { CredentialType, SecurityLevel, CredentialDataRequest } from '@/types';
import { EyeIcon, EyeSlashIcon, KeyIcon } from '@heroicons/react/24/outline';

interface CreateCredentialModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const CreateCredentialModal: React.FC<CreateCredentialModalProps> = ({ isOpen, onClose }) => {
  const { currentIdentity, createCredential, generatePassword, isLoading } = usePersonaService();
  const [formData, setFormData] = useState({
    name: '',
    credential_type: 'Password' as CredentialType,
    security_level: 'High' as SecurityLevel,
    url: '',
    username: '',
    notes: '',
  });

  const [credentialData, setCredentialData] = useState<any>({
    password: '',
    email: '',
    security_questions: [],
  });

  const [showPassword, setShowPassword] = useState(false);

  const credentialTypes: CredentialType[] = [
    'Password',
    'CryptoWallet',
    'SshKey',
    'ApiKey',
    'BankCard',
    'ServerConfig',
    'Certificate',
    'TwoFactor',
  ];

  const securityLevels: SecurityLevel[] = ['Critical', 'High', 'Medium', 'Low'];

  const handleGeneratePassword = async () => {
    const password = await generatePassword(16, true);
    if (password) {
      setCredentialData({ ...credentialData, password });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentIdentity || !formData.name.trim()) return;

    let credentialDataRequest: CredentialDataRequest;

    switch (formData.credential_type) {
      case 'Password':
        credentialDataRequest = {
          type: 'Password',
          password: credentialData.password,
          email: credentialData.email || undefined,
          security_questions: credentialData.security_questions || [],
        };
        break;

      case 'CryptoWallet':
        credentialDataRequest = {
          type: 'CryptoWallet',
          wallet_type: credentialData.wallet_type || 'Bitcoin',
          mnemonic_phrase: credentialData.mnemonic_phrase || undefined,
          private_key: credentialData.private_key || undefined,
          public_key: credentialData.public_key || '',
          address: credentialData.address || '',
          network: credentialData.network || 'mainnet',
        };
        break;

      case 'SshKey':
        credentialDataRequest = {
          type: 'SshKey',
          private_key: credentialData.private_key || '',
          public_key: credentialData.public_key || '',
          key_type: credentialData.key_type || 'rsa',
          passphrase: credentialData.passphrase || undefined,
        };
        break;

      case 'ApiKey':
        credentialDataRequest = {
          type: 'ApiKey',
          api_key: credentialData.api_key || '',
          api_secret: credentialData.api_secret || undefined,
          token: credentialData.token || undefined,
          permissions: credentialData.permissions || [],
          expires_at: credentialData.expires_at || undefined,
        };
        break;

      default:
        credentialDataRequest = {
          type: 'Raw',
          data: Array.from(new TextEncoder().encode(credentialData.raw_data || '')),
        };
        break;
    }

    const result = await createCredential({
      identity_id: currentIdentity.id,
      name: formData.name,
      credential_type: formData.credential_type,
      security_level: formData.security_level,
      url: formData.url || undefined,
      username: formData.username || undefined,
      credential_data: credentialDataRequest,
    });

    if (result) {
      // Reset form
      setFormData({
        name: '',
        credential_type: 'Password',
        security_level: 'High',
        url: '',
        username: '',
        notes: '',
      });
      setCredentialData({
        password: '',
        email: '',
        security_questions: [],
      });
      onClose();
    }
  };

  const renderCredentialFields = () => {
    switch (formData.credential_type) {
      case 'Password':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">Email/Username</label>
              <input
                type="email"
                value={credentialData.email || ''}
                onChange={(e) => setCredentialData({ ...credentialData, email: e.target.value })}
                className="input"
                placeholder="user@example.com"
              />
            </div>
            <div>
              <label className="label mb-2 block">Password *</label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={credentialData.password || ''}
                    onChange={(e) => setCredentialData({ ...credentialData, password: e.target.value })}
                    className="input pr-10"
                    placeholder="Enter password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  >
                    {showPassword ? (
                      <EyeSlashIcon className="h-4 w-4 text-gray-400" />
                    ) : (
                      <EyeIcon className="h-4 w-4 text-gray-400" />
                    )}
                  </button>
                </div>
                <button
                  type="button"
                  onClick={handleGeneratePassword}
                  className="btn-secondary flex items-center"
                >
                  <KeyIcon className="w-4 h-4 mr-1" />
                  Generate
                </button>
              </div>
            </div>
          </div>
        );

      case 'CryptoWallet':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">Wallet Type *</label>
              <input
                type="text"
                value={credentialData.wallet_type || ''}
                onChange={(e) => setCredentialData({ ...credentialData, wallet_type: e.target.value })}
                className="input"
                placeholder="Bitcoin, Ethereum, etc."
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">Address *</label>
              <input
                type="text"
                value={credentialData.address || ''}
                onChange={(e) => setCredentialData({ ...credentialData, address: e.target.value })}
                className="input"
                placeholder="Wallet address"
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">Mnemonic Phrase</label>
              <textarea
                value={credentialData.mnemonic_phrase || ''}
                onChange={(e) => setCredentialData({ ...credentialData, mnemonic_phrase: e.target.value })}
                className="input h-20 resize-none"
                placeholder="12-24 word recovery phrase"
              />
            </div>
            <div>
              <label className="label mb-2 block">Network</label>
              <select
                value={credentialData.network || 'mainnet'}
                onChange={(e) => setCredentialData({ ...credentialData, network: e.target.value })}
                className="input"
              >
                <option value="mainnet">Mainnet</option>
                <option value="testnet">Testnet</option>
                <option value="regtest">Regtest</option>
              </select>
            </div>
          </div>
        );

      case 'SshKey':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">Key Type</label>
              <select
                value={credentialData.key_type || 'rsa'}
                onChange={(e) => setCredentialData({ ...credentialData, key_type: e.target.value })}
                className="input"
              >
                <option value="rsa">RSA</option>
                <option value="ed25519">Ed25519</option>
                <option value="ecdsa">ECDSA</option>
              </select>
            </div>
            <div>
              <label className="label mb-2 block">Public Key *</label>
              <textarea
                value={credentialData.public_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, public_key: e.target.value })}
                className="input h-20 resize-none font-mono text-xs"
                placeholder="ssh-rsa AAAAB3NzaC1yc2E..."
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">Private Key *</label>
              <textarea
                value={credentialData.private_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, private_key: e.target.value })}
                className="input h-32 resize-none font-mono text-xs"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">Passphrase</label>
              <input
                type="password"
                value={credentialData.passphrase || ''}
                onChange={(e) => setCredentialData({ ...credentialData, passphrase: e.target.value })}
                className="input"
                placeholder="Key passphrase (if any)"
              />
            </div>
          </div>
        );

      case 'ApiKey':
        return (
          <div className="space-y-4">
            <div>
              <label className="label mb-2 block">API Key *</label>
              <input
                type="text"
                value={credentialData.api_key || ''}
                onChange={(e) => setCredentialData({ ...credentialData, api_key: e.target.value })}
                className="input font-mono"
                placeholder="API key or token"
                required
              />
            </div>
            <div>
              <label className="label mb-2 block">API Secret</label>
              <input
                type="password"
                value={credentialData.api_secret || ''}
                onChange={(e) => setCredentialData({ ...credentialData, api_secret: e.target.value })}
                className="input font-mono"
                placeholder="API secret (if any)"
              />
            </div>
            <div>
              <label className="label mb-2 block">Permissions</label>
              <input
                type="text"
                value={(credentialData.permissions || []).join(', ')}
                onChange={(e) => setCredentialData({
                  ...credentialData,
                  permissions: e.target.value.split(',').map(p => p.trim()).filter(Boolean)
                })}
                className="input"
                placeholder="read, write, admin (comma-separated)"
              />
            </div>
          </div>
        );

      default:
        return (
          <div>
            <label className="label mb-2 block">Data</label>
            <textarea
              value={credentialData.raw_data || ''}
              onChange={(e) => setCredentialData({ ...credentialData, raw_data: e.target.value })}
              className="input h-32 resize-none"
              placeholder="Enter credential data"
            />
          </div>
        );
    }
  };

  if (!isOpen || !currentIdentity) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Add New Credential</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label mb-2 block">Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="input"
              placeholder="e.g., Gmail Account, Work SSH Key"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label mb-2 block">Type</label>
              <select
                value={formData.credential_type}
                onChange={(e) => {
                  setFormData({ ...formData, credential_type: e.target.value as CredentialType });
                  setCredentialData({}); // Reset credential data when type changes
                }}
                className="input"
              >
                {credentialTypes.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="label mb-2 block">Security Level</label>
              <select
                value={formData.security_level}
                onChange={(e) => setFormData({ ...formData, security_level: e.target.value as SecurityLevel })}
                className="input"
              >
                {securityLevels.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="label mb-2 block">URL</label>
            <input
              type="url"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
              className="input"
              placeholder="https://example.com"
            />
          </div>

          <div>
            <label className="label mb-2 block">Username</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="input"
              placeholder="Username or account identifier"
            />
          </div>

          {renderCredentialFields()}

          <div>
            <label className="label mb-2 block">Notes</label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              className="input h-20 resize-none"
              placeholder="Additional notes or information"
            />
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary flex-1"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !formData.name.trim()}
              className="btn-primary flex-1"
            >
              {isLoading ? 'Creating...' : 'Create Credential'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateCredentialModal;