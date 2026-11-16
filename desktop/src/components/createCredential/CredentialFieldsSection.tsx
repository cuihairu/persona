import React from 'react';
import { useTranslation } from 'react-i18next';
import type { CredentialType } from '@/types';
import { EyeIcon, EyeSlashIcon, KeyIcon } from '@heroicons/react/24/outline';
import { parseOtpauthUri } from './credentialFormModel';

/** 动态表单区：按凭据类型渲染专属字段。无内部状态——payload 草稿
 *  `credentialData` 与显隐开关都由父级持有，经 props 下发（名字与原闭包
 *  捕获一致，函数体逐字保留）。 */
const CredentialFieldsSection: React.FC<{
  credentialType: CredentialType;
  credentialData: any;
  setCredentialData: React.Dispatch<React.SetStateAction<any>>;
  showPassword: boolean;
  setShowPassword: (v: boolean) => void;
  handleGeneratePassword: () => void;
  mnemonicWordCount: number;
  setMnemonicWordCount: (n: number) => void;
  mnemonicCheck: { valid: boolean; wordCount: number | null; error: string | null } | null;
  handleGenerateMnemonic: () => void;
  showBip39Passphrase: boolean;
  setShowBip39Passphrase: (v: boolean) => void;
  showWalletPrivateKey: boolean;
  setShowWalletPrivateKey: (v: boolean) => void;
}> = ({
  credentialType,
  credentialData,
  setCredentialData,
  showPassword,
  setShowPassword,
  handleGeneratePassword,
  mnemonicWordCount,
  setMnemonicWordCount,
  mnemonicCheck,
  handleGenerateMnemonic,
  showBip39Passphrase,
  setShowBip39Passphrase,
  showWalletPrivateKey,
  setShowWalletPrivateKey,
}) => {
  const { t } = useTranslation();

  switch (credentialType) {
  case 'Password':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.emailUsername')}</label>
          <input
            type="email"
            value={credentialData.email || ''}
            onChange={(e) => setCredentialData({ ...credentialData, email: e.target.value })}
            className="input"
            placeholder="user@example.com"
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.passwordReq')}</label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                type={showPassword ? 'text' : 'password'}
                value={credentialData.password || ''}
                onChange={(e) => setCredentialData({ ...credentialData, password: e.target.value })}
                className="input pr-10"
                placeholder={t('credForm.passwordPlaceholder')}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center"
              >
                {showPassword ? (
                  <EyeSlashIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                ) : (
                  <EyeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                )}
              </button>
            </div>
            <button
              type="button"
              onClick={handleGeneratePassword}
              className="btn-secondary flex items-center"
            >
              <KeyIcon className="w-4 h-4 mr-1" />
              {t('credForm.generate')}
            </button>
          </div>
        </div>
      </div>
    );

  case 'CryptoWallet':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.walletTypeReq')}</label>
          <input
            type="text"
            value={credentialData.wallet_type || ''}
            onChange={(e) => setCredentialData({ ...credentialData, wallet_type: e.target.value })}
            className="input"
            placeholder={t('credForm.walletTypePlaceholder')}
            required
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.addressReq')}</label>
          <input
            type="text"
            value={credentialData.address || ''}
            onChange={(e) => setCredentialData({ ...credentialData, address: e.target.value })}
            className="input"
            placeholder={t('credForm.addressPlaceholder')}
            required
          />
        </div>
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="label">{t('credForm.mnemonic')}</label>
            <div className="flex items-center gap-2">
              <select
                value={mnemonicWordCount}
                onChange={(e) => setMnemonicWordCount(Number(e.target.value))}
                className="input h-8 w-auto py-0 text-xs"
                aria-label={t('credForm.mnemonicWords')}
              >
                {[12, 15, 18, 21, 24].map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
              <button
                type="button"
                onClick={handleGenerateMnemonic}
                className="btn-secondary text-xs flex items-center"
              >
                <KeyIcon className="w-3.5 h-3.5 mr-1" />
                {t('credForm.generateMnemonic')}
              </button>
            </div>
          </div>
          <textarea
            value={credentialData.mnemonic_phrase || ''}
            onChange={(e) => setCredentialData({ ...credentialData, mnemonic_phrase: e.target.value })}
            className="input h-20 resize-none"
            placeholder={t('credForm.mnemonicPlaceholder')}
          />
          {mnemonicCheck && (
            <p
              className={`mt-1 text-xs ${
                mnemonicCheck.valid
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-red-600 dark:text-red-400'
              }`}
            >
              {mnemonicCheck.valid
                ? `${t('credForm.mnemonicValid')} · ${mnemonicCheck.wordCount ?? '?'} ${t('credForm.mnemonicWords')}`
                : `${t('credForm.mnemonicInvalid')}${mnemonicCheck.error ? `：${mnemonicCheck.error}` : ''}`}
            </p>
          )}
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.bip39Passphrase')}</label>
          <div className="relative">
            <input
              type={showBip39Passphrase ? 'text' : 'password'}
              value={credentialData.bip39_passphrase || ''}
              onChange={(e) => setCredentialData({ ...credentialData, bip39_passphrase: e.target.value })}
              className="input pr-10"
              placeholder={t('credForm.bip39PassphrasePlaceholder')}
              autoComplete="off"
            />
            <button
              type="button"
              onClick={() => setShowBip39Passphrase(!showBip39Passphrase)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
            >
              {showBip39Passphrase ? (
                <EyeSlashIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
              ) : (
                <EyeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
              )}
            </button>
          </div>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t('credForm.bip39Hint')}</p>
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.privateKeyOpt')}</label>
          <div className="relative">
            <input
              type={showWalletPrivateKey ? 'text' : 'password'}
              value={credentialData.private_key || ''}
              onChange={(e) => setCredentialData({ ...credentialData, private_key: e.target.value })}
              className="input pr-10"
              placeholder={t('credForm.privateKeyPlaceholder')}
              autoComplete="off"
            />
            <button
              type="button"
              onClick={() => setShowWalletPrivateKey(!showWalletPrivateKey)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
            >
              {showWalletPrivateKey ? (
                <EyeSlashIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
              ) : (
                <EyeIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
              )}
            </button>
          </div>
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.publicKeyOpt')}</label>
          <textarea
            value={credentialData.public_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, public_key: e.target.value })}
            className="input h-16 resize-none"
            placeholder={t('credForm.publicKeyPlaceholder')}
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('detail.labels.network')}</label>
          <select
            value={credentialData.network || 'mainnet'}
            onChange={(e) => setCredentialData({ ...credentialData, network: e.target.value })}
            className="input"
          >
            <option value="mainnet">{t('credForm.networkMainnet')}</option>
            <option value="testnet">{t('credForm.networkTestnet')}</option>
            <option value="regtest">{t('credForm.networkRegtest')}</option>
          </select>
        </div>
      </div>
    );

  case 'SshKey':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('detail.labels.keyType')}</label>
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
          <label className="label mb-2 block">{t('credForm.publicKeyReq')}</label>
          <textarea
            value={credentialData.public_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, public_key: e.target.value })}
            className="input h-20 resize-none font-mono text-xs"
            placeholder="ssh-rsa AAAAB3NzaC1yc2E..."
            required
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.privateKeyReq')}</label>
          <textarea
            value={credentialData.private_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, private_key: e.target.value })}
            className="input h-32 resize-none font-mono text-xs"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            required
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('detail.labels.passphrase')}</label>
          <input
            type="password"
            value={credentialData.passphrase || ''}
            onChange={(e) => setCredentialData({ ...credentialData, passphrase: e.target.value })}
            className="input"
            placeholder={t('credForm.passphrasePlaceholder')}
          />
        </div>
      </div>
    );

  case 'ApiKey':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.apiKeyReq')}</label>
          <input
            type="text"
            value={credentialData.api_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, api_key: e.target.value })}
            className="input font-mono"
            placeholder={t('credForm.apiKeyPlaceholder')}
            required
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('detail.labels.apiSecret')}</label>
          <input
            type="password"
            value={credentialData.api_secret || ''}
            onChange={(e) => setCredentialData({ ...credentialData, api_secret: e.target.value })}
            className="input font-mono"
            placeholder={t('credForm.apiSecretPlaceholder')}
          />
        </div>
        <div>
          <label className="label mb-2 block">{t('detail.labels.permissions')}</label>
          <input
            type="text"
            value={(credentialData.permissions || []).join(', ')}
            onChange={(e) => setCredentialData({
              ...credentialData,
              permissions: e.target.value.split(',').map(p => p.trim()).filter(Boolean)
            })}
            className="input"
            placeholder={t('credForm.permissionsPlaceholder')}
          />
        </div>
      </div>
    );

  case 'TwoFactor':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.otpauthUri')}</label>
          <input
            type="text"
            value={credentialData.otpauth_uri || ''}
            onChange={(e) => {
              const value = e.target.value;
              const parsed = value.trim() ? parseOtpauthUri(value.trim()) : null;
              if (parsed) {
                setCredentialData({ ...credentialData, ...parsed, otpauth_uri: value });
              } else {
                setCredentialData({ ...credentialData, otpauth_uri: value });
              }
            }}
            className="input font-mono text-xs"
            placeholder="otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&digits=6&period=30"
          />
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {t('credForm.otpauthHint')}
          </p>
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.secretReq')}</label>
          <input
            type="text"
            value={credentialData.secret_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, secret_key: e.target.value })}
            className="input font-mono"
            placeholder="JBSWY3DPEHPK3PXP"
            required
          />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block">{t('detail.labels.issuer')}</label>
            <input
              type="text"
              value={credentialData.issuer || ''}
              onChange={(e) => setCredentialData({ ...credentialData, issuer: e.target.value })}
              className="input"
              placeholder="GitHub"
            />
          </div>
          <div>
            <label className="label mb-2 block">{t('detail.labels.account')}</label>
            <input
              type="text"
              value={credentialData.account_name || ''}
              onChange={(e) => setCredentialData({ ...credentialData, account_name: e.target.value })}
              className="input"
              placeholder="user@example.com"
            />
          </div>
        </div>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="label mb-2 block">{t('credForm.algorithm')}</label>
            <select
              value={credentialData.algorithm || 'SHA1'}
              onChange={(e) => setCredentialData({ ...credentialData, algorithm: e.target.value })}
              className="input"
            >
              <option value="SHA1">SHA1</option>
              <option value="SHA256">SHA256</option>
              <option value="SHA512">SHA512</option>
            </select>
          </div>
          <div>
            <label className="label mb-2 block">{t('credForm.digits')}</label>
            <select
              value={String(credentialData.digits || 6)}
              onChange={(e) => setCredentialData({ ...credentialData, digits: Number(e.target.value) })}
              className="input"
            >
              <option value="6">6</option>
              <option value="8">8</option>
            </select>
          </div>
          <div>
            <label className="label mb-2 block">{t('credForm.period')}</label>
            <input
              type="number"
              min={10}
              max={120}
              value={credentialData.period || 30}
              onChange={(e) => setCredentialData({ ...credentialData, period: Number(e.target.value) })}
              className="input"
            />
          </div>
        </div>
      </div>
    );

  case 'GameToken':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.providerReq')}</label>
          <input
            type="text"
            value={credentialData.provider || ''}
            onChange={(e) => setCredentialData({ ...credentialData, provider: e.target.value })}
            className="input font-mono"
            placeholder="steam_guard, tencent_security, netease_dashen, mihoyo"
            required
          />
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {t('credForm.providerHint')}
          </p>
        </div>
        <div>
          <label className="label mb-2 block">{t('credForm.sharedSecret')}</label>
          <input
            type="text"
            value={credentialData.secret_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, secret_key: e.target.value })}
            className="input font-mono"
            placeholder={t('credForm.sharedSecretPlaceholder')}
          />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block">{t('detail.labels.issuer')}</label>
            <input
              type="text"
              value={credentialData.issuer || ''}
              onChange={(e) => setCredentialData({ ...credentialData, issuer: e.target.value })}
              className="input"
              placeholder="Steam, Tencent, NetEase…"
            />
          </div>
          <div>
            <label className="label mb-2 block">{t('credForm.accountReq')}</label>
            <input
              type="text"
              value={credentialData.account_name || ''}
              onChange={(e) => setCredentialData({ ...credentialData, account_name: e.target.value })}
              className="input"
              placeholder="qq_123456"
              required
            />
          </div>
        </div>
      </div>
    );

  case 'SecureNote':
    return (
      <div>
        <label className="label mb-2 block">{t('credForm.noteReq')}</label>
        <textarea
          value={credentialData.note || ''}
          onChange={(e) => setCredentialData({ ...credentialData, note: e.target.value })}
          className="input h-40 resize-y font-mono text-sm"
          placeholder={t('credForm.notePlaceholder')}
          required
        />
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          {t('credForm.noteHint')}
        </p>
      </div>
    );

  case 'Identity':
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block" htmlFor="cred-first_name">{t('credForm.firstNameReq')}</label>
            <input
              id="cred-first_name"
              type="text"
              value={credentialData.first_name || ''}
              onChange={(e) => setCredentialData({ ...credentialData, first_name: e.target.value })}
              className="input"
              required
            />
          </div>
          <div>
            <label className="label mb-2 block" htmlFor="cred-last_name">{t('credForm.lastNameReq')}</label>
            <input
              id="cred-last_name"
              type="text"
              value={credentialData.last_name || ''}
              onChange={(e) => setCredentialData({ ...credentialData, last_name: e.target.value })}
              className="input"
              required
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block" htmlFor="cred-email">{t('detail.labels.email')}</label>
            <input
              id="cred-email"
              type="text"
              value={credentialData.email || ''}
              onChange={(e) => setCredentialData({ ...credentialData, email: e.target.value })}
              className="input"
            />
          </div>
          <div>
            <label className="label mb-2 block" htmlFor="cred-phone">{t('detail.labels.phone')}</label>
            <input
              id="cred-phone"
              type="text"
              value={credentialData.phone || ''}
              onChange={(e) => setCredentialData({ ...credentialData, phone: e.target.value })}
              className="input"
            />
          </div>
        </div>
        <div>
          <label className="label mb-2 block">{t('detail.labels.address')}</label>
          <textarea
            value={credentialData.address || ''}
            onChange={(e) => setCredentialData({ ...credentialData, address: e.target.value })}
            className="input h-20 resize-y"
          />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block" htmlFor="cred-id_number">{t('detail.labels.idNumber')}</label>
            <input
              id="cred-id_number"
              type="text"
              value={credentialData.id_number || ''}
              onChange={(e) => setCredentialData({ ...credentialData, id_number: e.target.value })}
              className="input font-mono"
            />
          </div>
          <div>
            <label className="label mb-2 block" htmlFor="cred-passport_number">{t('detail.labels.passportNo')}</label>
            <input
              id="cred-passport_number"
              type="text"
              value={credentialData.passport_number || ''}
              onChange={(e) => setCredentialData({ ...credentialData, passport_number: e.target.value })}
              className="input font-mono"
            />
          </div>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {t('credForm.identityDocHint')}
        </p>
      </div>
    );

  case 'SoftwareLicense':
    return (
      <div className="space-y-4">
        <div>
          <label className="label mb-2 block">{t('credForm.licenseKeyReq')}</label>
          <textarea
            value={credentialData.license_key || ''}
            onChange={(e) => setCredentialData({ ...credentialData, license_key: e.target.value })}
            className="input h-24 resize-y font-mono text-sm"
            placeholder="AAAA-BBBB-CCCC-DDDD"
            required
          />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block" htmlFor="cred-version">{t('detail.labels.version')}</label>
            <input
              id="cred-version"
              type="text"
              value={credentialData.version || ''}
              onChange={(e) => setCredentialData({ ...credentialData, version: e.target.value })}
              className="input"
              placeholder="2024.2"
            />
          </div>
          <div>
            <label className="label mb-2 block" htmlFor="cred-publisher">{t('detail.labels.publisher')}</label>
            <input
              id="cred-publisher"
              type="text"
              value={credentialData.publisher || ''}
              onChange={(e) => setCredentialData({ ...credentialData, publisher: e.target.value })}
              className="input"
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label mb-2 block" htmlFor="cred-seats">{t('detail.labels.seats')}</label>
            <input
              id="cred-seats"
              type="number"
              min={1}
              value={credentialData.seats || ''}
              onChange={(e) => setCredentialData({ ...credentialData, seats: e.target.value })}
              className="input"
            />
          </div>
          <div>
            <label className="label mb-2 block" htmlFor="cred-valid_until">{t('detail.labels.validUntil')}</label>
            <input
              id="cred-valid_until"
              type="text"
              value={credentialData.valid_until || ''}
              onChange={(e) => setCredentialData({ ...credentialData, valid_until: e.target.value })}
              className="input"
              placeholder="2027-05-01"
            />
          </div>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {t('credForm.licenseHint')}
        </p>
      </div>
    );

  default:
    return (
      <div>
        <label className="label mb-2 block">{t('credForm.data')}</label>
        <textarea
          value={credentialData.raw_data || ''}
          onChange={(e) => setCredentialData({ ...credentialData, raw_data: e.target.value })}
          className="input h-32 resize-none"
          placeholder={t('credForm.dataPlaceholder')}
        />
      </div>
    );
}
};

export default CredentialFieldsSection;
