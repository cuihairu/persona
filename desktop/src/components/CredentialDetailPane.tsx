import React, { useCallback, useEffect, useState } from 'react';
import {
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ClockIcon,
  DocumentDuplicateIcon,
  HeartIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import FaviconImg from './FaviconImg';
import { useFavicons } from '@/hooks/useFavicons';
import type { Credential, CredentialHistoryEntry } from '@/types';
import { clsx } from 'clsx';
import RevealSecretButton from '@/components/RevealSecretButton';
import { getCredentialIcon, getSecurityColor } from './credentialDisplay';

/**
 * 右侧常驻详情面板：原 CredentialDetailModal 平移，外壳从全屏 overlay
 * 换成双栏右栏的 card 容器（lg 下 sticky 跟随滚动）。
 */
interface CredentialDetailPaneProps {
  credential: Credential;
  /** 详情数据；null = 取数中（显示 loading 占位） */
  credentialData: any;
  onClose: () => void;
  onCopy: (text: string, label: string) => void;
}

const CredentialDetailPane: React.FC<CredentialDetailPaneProps> = ({
  credential,
  credentialData,
  onClose,
  onCopy,
}) => {
  const { toggleCredentialFavorite, deleteCredential, getTotpCode, fetchFavicon, getCredentialHistory } =
    usePersonaService();
  const faviconsEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  // 头部图标预取（列表页通常已拉好，这里幂等兜底）
  useFavicons([credential.url]);
  const [isFetchingIcon, setIsFetchingIcon] = useState(false);
  const [isFavorite, setIsFavorite] = useState(credential.is_favorite);
  const [isTogglingFavorite, setIsTogglingFavorite] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [totpCode, setTotpCode] = useState<string | null>(null);
  const [totpRemaining, setTotpRemaining] = useState<number | null>(null);
  const [isTotpLoading, setIsTotpLoading] = useState(false);
  // Item history：懒加载——展开时才查一次历史表，切换凭据即重置
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [history, setHistory] = useState<CredentialHistoryEntry[] | null>(null);
  const IconComponent = getCredentialIcon(credential.credential_type);

  useEffect(() => {
    setIsFavorite(credential.is_favorite);
  }, [credential.id, credential.is_favorite]);

  // 切换凭据时重置历史折叠态（不预取）
  useEffect(() => {
    setIsHistoryOpen(false);
    setHistory(null);
  }, [credential.id]);

  useEffect(() => {
    if (!isHistoryOpen || history !== null) return;
    let cancelled = false;
    getCredentialHistory(credential.id).then((entries) => {
      if (!cancelled) setHistory(entries);
    });
    return () => {
      cancelled = true;
    };
    // history 作为"已加载"标记参与依赖，避免重复拉取
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isHistoryOpen, credential.id, history]);

  const refreshTotp = useCallback(async () => {
    if (credential.credential_type !== 'TwoFactor') return;
    setIsTotpLoading(true);
    try {
      const res = await getTotpCode(credential.id);
      if (res) {
        setTotpCode(res.code);
        setTotpRemaining(res.remaining_seconds);
      }
    } finally {
      setIsTotpLoading(false);
    }
  }, [credential.credential_type, credential.id, getTotpCode]);

  useEffect(() => {
    if (credential.credential_type !== 'TwoFactor') {
      setTotpCode(null);
      setTotpRemaining(null);
      return;
    }
    refreshTotp();
  }, [credential.id, credential.credential_type, refreshTotp]);

  useEffect(() => {
    if (credential.credential_type !== 'TwoFactor') return;
    if (totpRemaining === null) return;
    const interval = window.setInterval(() => {
      setTotpRemaining((prev) => (prev === null ? null : Math.max(prev - 1, 0)));
    }, 1000);
    return () => window.clearInterval(interval);
  }, [credential.id, credential.credential_type, totpCode]);

  useEffect(() => {
    if (credential.credential_type !== 'TwoFactor') return;
    if (totpRemaining !== 0) return;
    refreshTotp();
  }, [credential.credential_type, refreshTotp, totpRemaining]);

  const handleFetchIcon = async () => {
    if (isFetchingIcon) return;
    setIsFetchingIcon(true);
    try {
      await fetchFavicon(credential.id);
    } finally {
      setIsFetchingIcon(false);
    }
  };

  const handleToggleFavorite = async () => {
    if (isTogglingFavorite) return;
    setIsTogglingFavorite(true);
    try {
      const updated = await toggleCredentialFavorite(credential.id);
      if (updated) setIsFavorite(updated.is_favorite);
    } finally {
      setIsTogglingFavorite(false);
    }
  };

  const handleDelete = async () => {
    if (isDeleting) return;
    const confirmed = window.confirm(`Delete "${credential.name}"? This cannot be undone.`);
    if (!confirmed) return;
    setIsDeleting(true);
    try {
      const ok = await deleteCredential(credential.id);
      if (ok) onClose();
    } finally {
      setIsDeleting(false);
    }
  };

  const renderCredentialData = () => {
    if (!credentialData?.data) return null;

    const data = credentialData.data;

    switch (credentialData.credential_type) {
      case 'Password':
        return (
          <div className="space-y-3">
            {data.email && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Email</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">{data.email}</span>
                  <button
                    onClick={() => onCopy(data.email, 'Email')}
                    aria-label="Copy Email"
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                  </button>
                </div>
              </div>
            )}
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Password</label>
              <RevealSecretButton credentialId={credential.id} field="password" label="password" />
            </div>
          </div>
        );

      case 'CryptoWallet':
        return (
          <div className="space-y-3">
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Wallet Type</label>
              <span className="text-sm">{data.wallet_type}</span>
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Address</label>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono break-all">{data.address}</span>
                <button
                  onClick={() => onCopy(data.address, 'Address')}
                  aria-label="Copy Address"
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
              </div>
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Network</label>
              <span className="text-sm">{data.network}</span>
            </div>
          </div>
        );

      case 'TwoFactor':
        return (
          <div className="space-y-3">
            {credentialData?.data?.issuer && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Issuer</label>
                <span className="text-sm">{credentialData.data.issuer}</span>
              </div>
            )}
            {credentialData?.data?.account_name && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Account</label>
                <span className="text-sm">{credentialData.data.account_name}</span>
              </div>
            )}
            <div>
              <label className="label text-gray-600 dark:text-gray-300">TOTP Code</label>
              <div className="flex items-center gap-2">
                <span className="text-lg font-mono tracking-widest">
                  {totpCode ?? '------'}
                </span>
                <button
                  onClick={() => totpCode && onCopy(totpCode, 'TOTP')}
                  aria-label="Copy TOTP"
                  disabled={!totpCode}
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded disabled:opacity-50"
                  title="Copy code"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
                <button
                  onClick={refreshTotp}
                  disabled={isTotpLoading}
                  className="px-2 py-1 text-xs rounded bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-50"
                >
                  {isTotpLoading ? 'Refreshing…' : 'Refresh'}
                </button>
              </div>
              {totpRemaining !== null && (
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Expires in {totpRemaining}s
                </p>
              )}
            </div>
          </div>
        );

      case 'SshKey':
        return (
          <div className="space-y-3">
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Key Type</label>
              <span className="text-sm">{data.key_type}</span>
            </div>
            {data.public_key && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Public Key</label>
                <div className="flex items-start gap-2">
                  <span className="text-sm font-mono break-all">{data.public_key}</span>
                  <button
                    onClick={() => onCopy(data.public_key, 'Public key')}
                    aria-label="Copy Public key"
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
                  >
                    <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                  </button>
                </div>
              </div>
            )}
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Private Key</label>
              <RevealSecretButton
                credentialId={credential.id}
                field="ssh_private_key"
                label="private key"
              />
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Passphrase</label>
              <RevealSecretButton
                credentialId={credential.id}
                field="ssh_passphrase"
                label="passphrase"
              />
            </div>
          </div>
        );

      case 'ApiKey':
        return (
          <div className="space-y-3">
            <div>
              <label className="label text-gray-600 dark:text-gray-300">API Key</label>
              <RevealSecretButton credentialId={credential.id} field="api_key" label="API key" />
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">API Secret</label>
              <RevealSecretButton
                credentialId={credential.id}
                field="api_secret"
                label="API secret"
              />
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">Token</label>
              <RevealSecretButton credentialId={credential.id} field="token" label="token" />
            </div>
            {data.permissions?.length > 0 && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Permissions</label>
                <div className="flex flex-wrap gap-1">
                  {data.permissions.map((perm: string) => (
                    <span
                      key={perm}
                      className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full"
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
                <label className="label text-gray-600 dark:text-gray-300">Cardholder</label>
                <span className="text-sm">{data.cardholder_name}</span>
              </div>
            )}
            {data.bank_name && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Bank</label>
                <span className="text-sm">{data.bank_name}</span>
              </div>
            )}
            {data.last4 && (
              <div>
                <label className="label text-gray-600 dark:text-gray-300">Card Number</label>
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
            <label className="label text-gray-600 dark:text-gray-300">Note</label>
            <div className="flex items-start gap-2">
              <pre className="flex-1 text-sm font-mono whitespace-pre-wrap break-words bg-gray-50 dark:bg-gray-800 rounded p-2">
                {data.note}
              </pre>
              <button
                onClick={() => onCopy(data.note, 'Note')}
                aria-label="Copy Note"
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
            </div>
          </div>
        );

      default:
        return (
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Credential data is encrypted and secure.
          </div>
        );
    }
  };

  return (
    <div
      className="card p-6 max-h-[calc(100vh-8rem)] overflow-y-auto lg:sticky lg:top-6"
      data-testid="detail-pane"
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <div className="p-2 bg-primary-50 dark:bg-primary-500/10 rounded-lg mr-3">
            <FaviconImg
              url={credential.url}
              fallbackIcon={IconComponent}
              className="text-primary-600 dark:text-primary-400"
            />
          </div>
          <div>
            <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100">{credential.name}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{credential.credential_type}</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={handleToggleFavorite}
            disabled={isTogglingFavorite}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
            title={isFavorite ? 'Unfavorite' : 'Favorite'}
          >
            {isFavorite ? (
              <HeartSolidIcon className="w-5 h-5 text-red-500" />
            ) : (
              <HeartIcon className="w-5 h-5 text-gray-400 dark:text-gray-500" />
            )}
          </button>
          <button
            onClick={handleDelete}
            disabled={isDeleting}
            className="p-2 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg"
            title="Delete"
          >
            <TrashIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
          </button>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg" title="Close">
            ✕
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {credential.url && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">URL</label>
            <div className="flex items-center gap-2">
              <span className="text-sm break-all">{credential.url}</span>
              <button
                onClick={() => onCopy(credential.url!, 'URL')}
                aria-label="Copy URL"
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
              {faviconsEnabled && (
                <button
                  onClick={handleFetchIcon}
                  disabled={isFetchingIcon}
                  aria-label="Fetch icon"
                  title="Fetch icon"
                  data-testid="fetch-favicon"
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded disabled:opacity-50"
                >
                  <ArrowPathIcon
                    className={`w-4 h-4 text-gray-400 dark:text-gray-500 ${
                      isFetchingIcon ? 'animate-spin' : ''
                    }`}
                  />
                </button>
              )}
            </div>
          </div>
        )}

        {credential.username && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">Username</label>
            <div className="flex items-center gap-2">
              <span className="text-sm">{credential.username}</span>
              <button
                onClick={() => onCopy(credential.username!, 'Username')}
                aria-label="Copy Username"
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
            </div>
          </div>
        )}

        {credentialData ? (
          renderCredentialData()
        ) : (
          <div className="text-sm text-gray-400 dark:text-gray-500" data-testid="detail-loading">
            Loading details…
          </div>
        )}

        {credential.notes && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">Notes</label>
            <p className="text-sm text-gray-700 dark:text-gray-300">{credential.notes}</p>
          </div>
        )}

        {credential.tags?.length > 0 && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">Tags</label>
            <div className="flex flex-wrap gap-1">
              {credential.tags.map((tag) => (
                <span
                  key={tag}
                  className="px-2 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Item history（1Password 对齐）：懒加载的变更时间线 */}
        <div className="border-t pt-3">
          <button
            type="button"
            onClick={() => setIsHistoryOpen(!isHistoryOpen)}
            data-testid="history-toggle"
            className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-100"
          >
            <ClockIcon className="w-4 h-4" />
            Item History
            {isHistoryOpen ? (
              <ChevronUpIcon className="w-4 h-4" />
            ) : (
              <ChevronDownIcon className="w-4 h-4" />
            )}
          </button>

          {isHistoryOpen && (
            <div className="mt-2" data-testid="history-list">
              {history === null ? (
                <p className="text-xs text-gray-400 dark:text-gray-500">Loading…</p>
              ) : history.length === 0 ? (
                <p className="text-xs text-gray-400 dark:text-gray-500">
                  No recorded changes.
                </p>
              ) : (
                <ul className="space-y-2">
                  {history.map((entry) => (
                    <li
                      key={entry.id}
                      className="text-xs bg-gray-50 dark:bg-gray-800 rounded p-2"
                      data-testid="history-entry"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-gray-700 dark:text-gray-200">
                          v{entry.version} · {entry.change_type}
                        </span>
                        <span className="text-gray-400 dark:text-gray-500">
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </div>
                      {entry.changes.length > 0 && (
                        <ul className="mt-1 space-y-0.5 font-mono text-gray-600 dark:text-gray-300">
                          {entry.changes.map((change) => (
                            <li key={change.field}>
                              {change.field}:{' '}
                              <span className="text-red-500 dark:text-red-400">
                                {change.old_value || '(empty)'}
                              </span>{' '}
                              →{' '}
                              <span className="text-green-600 dark:text-green-400">
                                {change.new_value || '(empty)'}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between pt-4 border-t">
          <span className={clsx(
            'px-2 py-1 text-xs font-medium rounded-full border',
            getSecurityColor(credential.security_level)
          )}>
            {credential.security_level}
          </span>
          <div className="text-right text-xs text-gray-400 dark:text-gray-500">
            {credential.last_accessed && (
              <p>Last used: {new Date(credential.last_accessed).toLocaleDateString()}</p>
            )}
            <p>Created: {new Date(credential.created_at).toLocaleDateString()}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CredentialDetailPane;
