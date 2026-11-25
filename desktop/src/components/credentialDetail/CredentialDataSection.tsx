import React from 'react';
import { useTranslation } from 'react-i18next';
import { DocumentDuplicateIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import RevealSecretButton from '@/components/RevealSecretButton';
import type { Credential } from '@/types';

/** Renders the detail payload per credential type (the former inline `renderCredentialData` closure moved as-is).
 *  Holds no internal state — the TOTP row, the wallet standalone password form and the copy callbacks are all
 *  owned by the parent and passed down as props (names match the original closure captures, body preserved verbatim). */
const CredentialDataSection: React.FC<{
  credential: Credential;
  credentialData: any;
  onCopy: (text: string, label: string) => void;
  refreshTotp: () => Promise<void>;
  totpCode: string | null;
  totpRemaining: number | null;
  isTotpLoading: boolean;
  itemPwdEnabled: boolean;
  itemPwdForm: 'set' | 'clear' | null;
  itemPwdValue: string;
  itemPwdHintValue: string;
  itemPwdError: string | null;
  isItemPwdBusy: boolean;
  handleItemPwdSubmit: () => Promise<void>;
  setItemPwdForm: React.Dispatch<React.SetStateAction<'set' | 'clear' | null>>;
  setItemPwdValue: React.Dispatch<React.SetStateAction<string>>;
  setItemPwdHintValue: React.Dispatch<React.SetStateAction<string>>;
}> = ({
  credential,
  credentialData,
  onCopy,
  refreshTotp,
  totpCode,
  totpRemaining,
  isTotpLoading,
  itemPwdEnabled,
  itemPwdForm,
  itemPwdValue,
  itemPwdHintValue,
  itemPwdError,
  isItemPwdBusy,
  handleItemPwdSubmit,
  setItemPwdForm,
  setItemPwdValue,
  setItemPwdHintValue,
}) => {
  const { t } = useTranslation();

  if (!credentialData?.data) return null;

  const data = credentialData.data;

  switch (credentialData.credential_type) {
    case 'Password':
      return (
        <div className="space-y-3">
          {data.email && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.email')}</label>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono">{data.email}</span>
                <button
                  onClick={() => onCopy(data.email, t('detail.labels.email'))}
                  aria-label={t('detail.copyLabel', { name: t('detail.labels.email') })}
                  className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
              </div>
            </div>
          )}
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.password')}</label>
            <RevealSecretButton credentialId={credential.id} field="password" label={t('detail.labels.password')} />
          </div>
        </div>
      );

    case 'CryptoWallet':
      return (
        <div className="space-y-3">
          <div className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
            <LockClosedIcon className="w-3.5 h-3.5" />
            <span>{t('detail.walletSensitiveHint')}</span>
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.walletType')}</label>
            <span className="text-sm">{data.wallet_type}</span>
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.address')}</label>
            <div className="flex items-center gap-2">
              <span className="text-sm font-mono break-all">{data.address}</span>
              <button
                onClick={() => onCopy(data.address, t('detail.labels.address'))}
                aria-label={t('detail.copyLabel', { name: t('detail.labels.address') })}
                className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
            </div>
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.network')}</label>
            <span className="text-sm">{data.network}</span>
          </div>
          {data.mnemonic_phrase && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.mnemonic')}</label>
              <RevealSecretButton
                credentialId={credential.id}
                field="wallet_mnemonic"
                label={t('detail.labels.mnemonic')}
              />
            </div>
          )}
          {data.bip39_passphrase && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">
                {t('detail.labels.bip39Passphrase')}
              </label>
              <RevealSecretButton
                credentialId={credential.id}
                field="wallet_bip39_passphrase"
                label={t('detail.labels.bip39Passphrase')}
              />
            </div>
          )}
          {data.private_key && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.privateKey')}</label>
              <RevealSecretButton
                credentialId={credential.id}
                field="wallet_private_key"
                label={t('detail.labels.privateKey')}
              />
            </div>
          )}
          {data.public_key && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.publicKey')}</label>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono break-all">{data.public_key}</span>
                <button
                  onClick={() => onCopy(data.public_key, t('detail.labels.publicKey'))}
                  aria-label={t('detail.copyLabel', { name: t('detail.labels.publicKey') })}
                  className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
              </div>
            </div>
          )}
          <div className="border-t border-gray-100 dark:border-gray-800 pt-3">
            <div className="flex items-center justify-between">
              <div>
                <label className="label text-gray-600 dark:text-gray-300">
                  {t('detail.itemPwdTitle')}
                </label>
                <span
                  className={`ml-2 inline-block rounded px-1.5 py-0.5 text-xs ${
                    itemPwdEnabled
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                      : 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400'
                  }`}
                >
                  {itemPwdEnabled ? t('detail.itemPwdEnabled') : t('detail.itemPwdNotEnabled')}
                </span>
              </div>
              {itemPwdForm === null && (
                <button
                  type="button"
                  onClick={() => setItemPwdForm(itemPwdEnabled ? 'clear' : 'set')}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  {itemPwdEnabled ? t('detail.itemPwdClear') : t('detail.itemPwdEnable')}
                </button>
              )}
            </div>
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t('detail.itemPwdDesc')}</p>
            {itemPwdError && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{itemPwdError}</p>
            )}
            {itemPwdForm !== null && (
              <form
                className="mt-2 space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleItemPwdSubmit();
                }}
              >
                <input
                  type="password"
                  value={itemPwdValue}
                  onChange={(e) => setItemPwdValue(e.target.value)}
                  className="input h-8 text-sm"
                  placeholder={
                    itemPwdForm === 'set'
                      ? t('detail.itemPwdNewPlaceholder')
                      : t('detail.itemPwdCurrentPlaceholder')
                  }
                  autoComplete="off"
                  required
                />
                {itemPwdForm === 'set' && (
                  <input
                    type="text"
                    value={itemPwdHintValue}
                    onChange={(e) => setItemPwdHintValue(e.target.value)}
                    className="input h-8 text-sm"
                    placeholder={t('detail.itemPwdHintPlaceholder')}
                    autoComplete="off"
                  />
                )}
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={isItemPwdBusy || !itemPwdValue}
                    className="btn-secondary text-xs disabled:opacity-50"
                  >
                    {itemPwdForm === 'set' ? t('detail.itemPwdEnable') : t('detail.itemPwdClear')}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setItemPwdForm(null);
                      setItemPwdValue('');
                      setItemPwdHintValue('');
                    }}
                    className="whitespace-nowrap text-xs text-gray-500 dark:text-gray-400 hover:underline"
                  >
                    {t('common.cancel')}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      );

    case 'TwoFactor':
      return (
        <div className="space-y-3">
          {credentialData?.data?.issuer && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.issuer')}</label>
              <span className="text-sm">{credentialData.data.issuer}</span>
            </div>
          )}
          {credentialData?.data?.account_name && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.account')}</label>
              <span className="text-sm">{credentialData.data.account_name}</span>
            </div>
          )}
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.totpCode')}</label>
            <div className="flex items-center gap-2">
              <span className="text-lg font-mono tracking-widest">
                {totpCode ?? '------'}
              </span>
              <button
                onClick={() => totpCode && onCopy(totpCode, t('detail.labels.totpCode'))}
                aria-label={t('detail.copyLabel', { name: t('detail.labels.totpCode') })}
                disabled={!totpCode}
                className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded disabled:opacity-50"
                title={t('detail.copyCode')}
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
              <button
                onClick={refreshTotp}
                disabled={isTotpLoading}
                className="px-2 py-1 text-xs rounded bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50"
              >
                {isTotpLoading ? t('detail.refreshing') : t('detail.refresh')}
              </button>
            </div>
            {totpRemaining !== null && (
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {t('detail.expiresIn', { seconds: totpRemaining })}
              </p>
            )}
          </div>
        </div>
      );

    case 'SshKey':
      return (
        <div className="space-y-3">
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.keyType')}</label>
            <span className="text-sm">{data.key_type}</span>
          </div>
          {data.public_key && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.publicKey')}</label>
              <div className="flex items-start gap-2">
                <span className="text-sm font-mono break-all">{data.public_key}</span>
                <button
                  onClick={() => onCopy(data.public_key, t('detail.labels.publicKey'))}
                  aria-label={t('detail.copyLabel', { name: t('detail.labels.publicKey') })}
                  className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
              </div>
            </div>
          )}
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.privateKey')}</label>
            <RevealSecretButton
              credentialId={credential.id}
              field="ssh_private_key"
              label={t('detail.labels.privateKey')}
            />
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.passphrase')}</label>
            <RevealSecretButton
              credentialId={credential.id}
              field="ssh_passphrase"
              label={t('detail.labels.passphrase')}
            />
          </div>
        </div>
      );

    case 'ApiKey':
      return (
        <div className="space-y-3">
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.apiKey')}</label>
            <RevealSecretButton credentialId={credential.id} field="api_key" label={t('detail.labels.apiKey')} />
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.apiSecret')}</label>
            <RevealSecretButton
              credentialId={credential.id}
              field="api_secret"
              label={t('detail.labels.apiSecret')}
            />
          </div>
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.token')}</label>
            <RevealSecretButton credentialId={credential.id} field="token" label={t('detail.labels.token')} />
          </div>
          {data.permissions?.length > 0 && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.permissions')}</label>
              <div className="flex flex-wrap gap-1">
                {data.permissions.map((perm: string) => (
                  <span
                    key={perm}
                    className="whitespace-nowrap px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full"
                  >
                    {perm}
                  </span>
                ))}
              </div>
            </div>
          )}
          {data.expires_at && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Expires</label>
              <span className="text-sm">
                {new Date(data.expires_at).toLocaleString()}
              </span>
            </div>
          )}
        </div>
      );

    case 'BankCard':
      return (
        <div className="space-y-3">
          {data.cardholder_name && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.cardholder')}</label>
              <span className="text-sm">{data.cardholder_name}</span>
            </div>
          )}
          {data.bank_name && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.bank')}</label>
              <span className="text-sm">{data.bank_name}</span>
            </div>
          )}
          {data.last4 && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.cardNumber')}</label>
              <span className="text-sm font-mono">•••• •••• •••• {data.last4}</span>
            </div>
          )}
          {data.expiry_date && (
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Expires</label>
              <span className="text-sm">{data.expiry_date}</span>
            </div>
          )}
        </div>
      );

    case 'SecureNote':
      return (
        <div>
          <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.note')}</label>
          <div className="flex items-start gap-2">
            <pre className="flex-1 text-sm font-mono whitespace-pre-wrap break-words bg-gray-50 dark:bg-gray-800 rounded p-2">
              {data.note}
            </pre>
            <button
              onClick={() => onCopy(data.note, t('detail.labels.note'))}
              aria-label={t('detail.copyLabel', { name: t('detail.labels.note') })}
              className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            >
              <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
            </button>
          </div>
        </div>
      );

    case 'Identity': {
      // Sensitive fields such as the ID number are encrypted with the per-item key; reading them back goes through the sensitive-action gate
      const fields: Array<[string, string | undefined, boolean]> = [
        [t('detail.labels.fullName'), [data.first_name, data.last_name].filter(Boolean).join(' '), false],
        [t('detail.labels.email'), data.email, false],
        [t('detail.labels.phone'), data.phone, false],
        [t('detail.labels.birthday'), data.birthday, false],
        [t('detail.labels.address'), data.address, false],
        [t('detail.labels.idNumber'), data.id_number, true],
        [t('detail.labels.passportNo'), data.passport_number, true],
        [t('detail.labels.driverLicense'), data.driver_license, true],
        [t('detail.labels.taxId'), data.tax_id, true],
        [t('detail.labels.organization'), data.organization, false],
        [t('detail.labels.jobTitle'), data.job_title, false],
      ];
      return (
        <div className="space-y-3">
          {fields
            .filter(([, value]) => value)
            .map(([label, value, mono]) => (
              <div key={label}>
                <label className="label text-gray-600 dark:text-gray-300">{label}</label>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-sm break-words whitespace-pre-wrap ${mono ? 'font-mono' : ''}`}
                  >
                    {value}
                  </span>
                  <button
                    onClick={() => onCopy(value!, label)}
                    aria-label={t('detail.copyLabel', { name: label })}
                    className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                  </button>
                </div>
              </div>
            ))}
        </div>
      );
    }

    case 'SoftwareLicense': {
      const fields: Array<[string, string | undefined, boolean]> = [
        [t('detail.labels.licenseKey'), data.license_key, true],
        [t('detail.labels.version'), data.version, false],
        [t('detail.labels.publisher'), data.publisher, false],
        [t('detail.labels.purchaseDate'), data.purchase_date, false],
        [t('detail.labels.orderNumber'), data.order_number, true],
        [t('detail.labels.supportEmail'), data.support_email, false],
        [t('detail.labels.downloadUrl'), data.download_url, false],
        [t('detail.labels.seats'), data.seats != null ? String(data.seats) : undefined, false],
        [t('detail.labels.validUntil'), data.valid_until, false],
      ];
      return (
        <div className="space-y-3">
          {fields
            .filter(([, value]) => value)
            .map(([label, value, mono]) => (
              <div key={label}>
                <label className="label text-gray-600 dark:text-gray-300">{label}</label>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-sm break-words whitespace-pre-wrap ${mono ? 'font-mono' : ''}`}
                  >
                    {value}
                  </span>
                  <button
                    onClick={() => onCopy(value!, label)}
                    aria-label={t('detail.copyLabel', { name: label })}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                  </button>
                </div>
              </div>
            ))}
        </div>
      );
    }

    default:
      return (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {t('detail.encryptedNote')}
        </div>
      );
  }
};

export default CredentialDataSection;
