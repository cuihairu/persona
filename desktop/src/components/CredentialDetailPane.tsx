import React, { useCallback, useEffect, useState } from 'react';
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ClockIcon,
  DocumentDuplicateIcon,
  HeartIcon,
  PaperClipIcon,
  PencilIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { open as openFileDialog, save as saveFileDialog } from '@tauri-apps/plugin-dialog';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAppStore } from '@/stores/appStore';
import FaviconImg from './FaviconImg';
import { useFavicons } from '@/hooks/useFavicons';
import type { AttachmentEntry, Credential, CredentialHistoryEntry } from '@/types';
import { clsx } from 'clsx';
import RevealSecretButton from '@/components/RevealSecretButton';
import {
  credentialTypeLabel,
  getCredentialIcon,
  getSecurityColor,
  securityLevelLabel,
} from './credentialDisplay';

/** 人类可读的附件大小（B → KB → MB） */
function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

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
  const { t } = useTranslation();
  const {
    toggleCredentialFavorite,
    deleteCredential,
    getTotpCode,
    fetchFavicon,
    getCredentialHistory,
    listAttachments,
    attachFileToCredential,
    saveAttachmentToFile,
    deleteAttachment,
  } = usePersonaService();
  const faviconsEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);
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
  // Attachments：主功能，选中即拉取；切换凭据重置后重拉
  const [attachments, setAttachments] = useState<AttachmentEntry[]>([]);
  const [isAttachmentBusy, setIsAttachmentBusy] = useState(false);
  const IconComponent = getCredentialIcon(credential.credential_type);

  useEffect(() => {
    setIsFavorite(credential.is_favorite);
  }, [credential.id, credential.is_favorite]);

  useEffect(() => {
    let cancelled = false;
    setAttachments([]);
    listAttachments(credential.id).then((entries) => {
      if (!cancelled) setAttachments(entries);
    });
    return () => {
      cancelled = true;
    };
    // listAttachments 来自 context hook，返回值每渲染重建但仅作启动调用
  }, [credential.id]);

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
    const confirmed = window.confirm(t('detail.deleteConfirm', { name: credential.name }));
    if (!confirmed) return;
    setIsDeleting(true);
    try {
      const ok = await deleteCredential(credential.id);
      if (ok) onClose();
    } finally {
      setIsDeleting(false);
    }
  };

  /** 添加附件：原生文件选择 → 恒走加密封存（凭据 item key）→ 追加进列表 */
  const handleAttachFile = async () => {
    if (isAttachmentBusy) return;
    const selected = await openFileDialog({ multiple: false, title: t('detail.attachFileTitle') });
    const filePath = Array.isArray(selected) ? selected[0] : selected;
    if (!filePath) return; // 用户取消
    setIsAttachmentBusy(true);
    try {
      const attachment = await attachFileToCredential(credential.id, filePath, true);
      if (attachment) setAttachments((prev) => [...prev, attachment]);
    } finally {
      setIsAttachmentBusy(false);
    }
  };

  /** 保存附件：原生保存对话框 → 解密写出 */
  const handleSaveAttachment = async (attachment: AttachmentEntry) => {
    if (isAttachmentBusy) return;
    const outputPath = await saveFileDialog({
      title: t('detail.saveAttachmentTitle'),
      defaultPath: attachment.filename,
    });
    if (!outputPath) return; // 用户取消
    setIsAttachmentBusy(true);
    try {
      await saveAttachmentToFile(attachment.id, outputPath);
    } finally {
      setIsAttachmentBusy(false);
    }
  };

  const handleDeleteAttachment = async (attachment: AttachmentEntry) => {
    if (isAttachmentBusy) return;
    const confirmed = window.confirm(
      t('detail.deleteAttachmentConfirm', { name: attachment.filename })
    );
    if (!confirmed) return;
    setIsAttachmentBusy(true);
    try {
      const ok = await deleteAttachment(attachment.id);
      if (ok) {
        setAttachments((prev) => prev.filter((a) => a.id !== attachment.id));
      }
    } finally {
      setIsAttachmentBusy(false);
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
                <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.email')}</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">{data.email}</span>
                  <button
                    onClick={() => onCopy(data.email, t('detail.labels.email'))}
                    aria-label={t('detail.copyLabel', { name: t('detail.labels.email') })}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
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
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                >
                  <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                </button>
              </div>
            </div>
            <div>
              <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.network')}</label>
              <span className="text-sm">{data.network}</span>
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
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded disabled:opacity-50"
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
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded shrink-0"
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
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
            </div>
          </div>
        );

      case 'Identity': {
        // 证件号等敏感字段随 per-item key 加密，读回走敏感操作门禁
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
                      aria-label={`Copy ${label}`}
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
                      aria-label={`Copy ${label}`}
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
            <p className="text-sm text-gray-500 dark:text-gray-400">{credentialTypeLabel(t, credential.credential_type)}</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setEditingCredential({ credential, data: credentialData })}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
            title={t('common.edit')}
            aria-label={t('detail.editItem')}
            data-testid="edit-credential-button"
          >
            <PencilIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
          <button
            onClick={handleToggleFavorite}
            disabled={isTogglingFavorite}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
            title={isFavorite ? t('detail.unfavorite') : t('detail.favorite')}
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
            title={t('common.delete')}
          >
            <TrashIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
          </button>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg" title={t('common.close')}>
            ✕
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {credential.url && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.url')}</label>
            <div className="flex items-center gap-2">
              <span className="text-sm break-all">{credential.url}</span>
              <button
                onClick={() => onCopy(credential.url!, t('detail.labels.url'))}
                aria-label={t('detail.copyLabel', { name: t('detail.labels.url') })}
                className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              >
                <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
              </button>
              {faviconsEnabled && (
                <button
                  onClick={handleFetchIcon}
                  disabled={isFetchingIcon}
                  aria-label={t('common.fetchIcon')}
                  title={t('common.fetchIcon')}
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
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.username')}</label>
            <div className="flex items-center gap-2">
              <span className="text-sm">{credential.username}</span>
              <button
                onClick={() => onCopy(credential.username!, t('detail.labels.username'))}
                aria-label={t('detail.copyLabel', { name: t('detail.labels.username') })}
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
            {t('detail.loadingDetails')}
          </div>
        )}

        {credential.notes && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.notes')}</label>
            <p className="text-sm text-gray-700 dark:text-gray-300">{credential.notes}</p>
          </div>
        )}

        {credential.tags?.length > 0 && (
          <div>
            <label className="label text-gray-600 dark:text-gray-300">{t('detail.labels.tags')}</label>
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

        {/* Attachments（1Password 对齐）：附件经凭据 item key 加密封存 */}
        <div className="border-t pt-3">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300">
              <PaperClipIcon className="w-4 h-4" />
              {t('detail.attachments')}
            </span>
            <button
              type="button"
              onClick={handleAttachFile}
              disabled={isAttachmentBusy}
              data-testid="attachment-add"
              className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
            >
              <PlusIcon className="w-3.5 h-3.5" />
              {t('detail.addFile')}
            </button>
          </div>

          <div className="mt-2" data-testid="attachment-list">
            {attachments.length === 0 ? (
              <p className="text-xs text-gray-400 dark:text-gray-500">
                {t('detail.noAttachments')}
              </p>
            ) : (
              <ul className="space-y-1.5">
                {attachments.map((attachment) => (
                  <li
                    key={attachment.id}
                    className="flex items-center justify-between gap-2 text-xs bg-gray-50 dark:bg-gray-800 rounded p-2"
                    data-testid="attachment-entry"
                  >
                    <div className="min-w-0">
                      <p
                        className="truncate font-medium text-gray-700 dark:text-gray-200"
                        data-testid="attachment-filename"
                      >
                        {attachment.filename}
                      </p>
                      <p className="text-gray-400 dark:text-gray-500">
                        {formatFileSize(attachment.size)}
                        {attachment.is_encrypted && t('detail.encryptedBadge')}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        onClick={() => handleSaveAttachment(attachment)}
                        disabled={isAttachmentBusy}
                        title={t('detail.saveToDisk', { name: attachment.filename })}
                        data-testid={`attachment-save-${attachment.id}`}
                        className="p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                      >
                        <ArrowDownTrayIcon className="w-4 h-4" />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeleteAttachment(attachment)}
                        disabled={isAttachmentBusy}
                        title={t('detail.deleteFile', { name: attachment.filename })}
                        data-testid={`attachment-delete-${attachment.id}`}
                        className="p-1 rounded text-gray-500 dark:text-gray-400 hover:bg-red-50 dark:hover:bg-red-900/30 hover:text-red-600 dark:hover:text-red-400 disabled:opacity-50"
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Item history（1Password 对齐）：懒加载的变更时间线 */}
        <div className="border-t pt-3">
          <button
            type="button"
            onClick={() => setIsHistoryOpen(!isHistoryOpen)}
            data-testid="history-toggle"
            className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-100"
          >
            <ClockIcon className="w-4 h-4" />
            {t('detail.itemHistory')}
            {isHistoryOpen ? (
              <ChevronUpIcon className="w-4 h-4" />
            ) : (
              <ChevronDownIcon className="w-4 h-4" />
            )}
          </button>

          {isHistoryOpen && (
            <div className="mt-2" data-testid="history-list">
              {history === null ? (
                <p className="text-xs text-gray-400 dark:text-gray-500">{t('common.loading')}</p>
              ) : history.length === 0 ? (
                <p className="text-xs text-gray-400 dark:text-gray-500">
                  {t('detail.noChanges')}
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
                                {change.old_value || t('detail.emptyValue')}
                              </span>{' '}
                              →{' '}
                              <span className="text-green-600 dark:text-green-400">
                                {change.new_value || t('detail.emptyValue')}
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
            {securityLevelLabel(t, credential.security_level)}
          </span>
          <div className="text-right text-xs text-gray-400 dark:text-gray-500">
            {credential.last_accessed && (
              <p>{t('detail.lastUsed')}：{new Date(credential.last_accessed).toLocaleDateString()}</p>
            )}
            <p>{t('detail.created')}：{new Date(credential.created_at).toLocaleDateString()}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CredentialDetailPane;
