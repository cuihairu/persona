import React, { useCallback, useEffect, useState } from 'react';
import {
  ArrowPathIcon,
  DocumentDuplicateIcon,
  HeartIcon,
  PencilIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { HeartIcon as HeartSolidIcon } from '@heroicons/react/24/solid';
import { open as openFileDialog, save as saveFileDialog } from '@tauri-apps/plugin-dialog';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';
import FaviconImg from './FaviconImg';
import { useFavicons } from '@/hooks/useFavicons';
import type { AttachmentEntry, Credential, CredentialHistoryEntry, CustomField } from '@/types';
import { clsx } from 'clsx';
import {
  credentialTypeLabel,
  getCredentialIcon,
  getSecurityColor,
  securityLevelLabel,
} from './credentialDisplay';

import AttachmentsSection from './credentialDetail/AttachmentsSection';
import CredentialDataSection from './credentialDetail/CredentialDataSection';
import CustomFieldsSection from './credentialDetail/CustomFieldsSection';
import HistorySection from './credentialDetail/HistorySection';

/**
 * The right-hand resident detail panel: the former CredentialDetailModal moved as-is, with the shell
 * swapped from a full-screen overlay for a card container in the right column of the two-column layout
 * (sticky-following the scroll at the lg breakpoint).
 */
interface CredentialDetailPaneProps {
  credential: Credential;
  /** Detail data; null = a fetch is in progress (shows a loading placeholder) */
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
    restoreCredentialVersion,
    listAttachments,
    attachFileToCredential,
    saveAttachmentToFile,
    deleteAttachment,
    getCredentialCustomFields,
  } = usePersonaService();
  const faviconsEnabled = useAppStore((s) => s.featureFlags.fetch_favicons);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);
  // Prefetch the header icon (the list page has usually already fetched it; this is an idempotent backstop)
  useFavicons([credential.url]);
  const [isFetchingIcon, setIsFetchingIcon] = useState(false);
  const [isFavorite, setIsFavorite] = useState(credential.is_favorite);
  const [isTogglingFavorite, setIsTogglingFavorite] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [totpCode, setTotpCode] = useState<string | null>(null);
  const [totpRemaining, setTotpRemaining] = useState<number | null>(null);
  const [isTotpLoading, setIsTotpLoading] = useState(false);
  // Item history: lazy load — the history table is queried only once when expanded, and reset when the credential switches
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [history, setHistory] = useState<CredentialHistoryEntry[] | null>(null);
  const [isRestoringVersion, setIsRestoringVersion] = useState(false);
  // Wallet item standalone password management: the enabled state is initialized from the payload and maintained locally (the hash does not need to be echoed back)
  const [itemPwdEnabled, setItemPwdEnabled] = useState(
    !!credentialData?.data?.item_password_hash,
  );
  const [itemPwdForm, setItemPwdForm] = useState<'set' | 'clear' | null>(null);
  const [itemPwdValue, setItemPwdValue] = useState('');
  const [itemPwdHintValue, setItemPwdHintValue] = useState('');
  const [isItemPwdBusy, setIsItemPwdBusy] = useState(false);
  const [itemPwdError, setItemPwdError] = useState<string | null>(null);
  // Attachments: a primary feature — fetched on selection; re-fetched after a reset on credential switch
  const [attachments, setAttachments] = useState<AttachmentEntry[]>([]);
  const [isAttachmentBusy, setIsAttachmentBusy] = useState(false);
  // Structured custom fields (1Password parity): sealed with the per-item key, only readable in the unlocked state;
  // null = a read failure (an error row is displayed as-is, not impersonating an empty table)
  const [customFields, setCustomFields] = useState<CustomField[] | null>(null);
  const [customFieldsError, setCustomFieldsError] = useState<string | null>(null);
  // UI-layer masking for concealed rows (the values are already decrypted with the list; hiding is only to prevent shoulder-surfing)
  const [revealedFieldIds, setRevealedFieldIds] = useState<Set<string>>(new Set());
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
    // listAttachments comes from the context hook; its return value is rebuilt on every render but is only used as a kickoff call
  }, [credential.id]);

  // Custom fields are re-read as the credential switches; a read failure leaves an error row (not impersonating an empty table)
  useEffect(() => {
    const cancelled = { flag: false };
    setCustomFields(null);
    setCustomFieldsError(null);
    setRevealedFieldIds(new Set());
    getCredentialCustomFields(credential.id).then((fields) => {
      if (cancelled.flag) return;
      if (fields === null) {
        setCustomFieldsError(t('detail.customFieldsLoadFailed'));
      } else {
        setCustomFields(fields);
      }
    });
    return () => {
      cancelled.flag = true;
    };
    // getCredentialCustomFields comes from the context hook; its return value is rebuilt on every render but is only used as a kickoff call
  }, [credential.id]);

  // Reset the history collapse state when the credential switches (no prefetch)
  useEffect(() => {
    setIsHistoryOpen(false);
    setHistory(null);
  }, [credential.id]);

  // Reset the item standalone password form when the credential switches (the enabled state is decided by the credentialData initial value)
  useEffect(() => {
    setItemPwdForm(null);
    setItemPwdValue('');
    setItemPwdHintValue('');
    setItemPwdError(null);
    setIsItemPwdBusy(false);
  }, [credential.id]);

  // After the fetch completes / the entry switches, the enabled state follows the payload's hash field
  useEffect(() => {
    setItemPwdEnabled(!!credentialData?.data?.item_password_hash);
  }, [credentialData]);

  useEffect(() => {
    if (!isHistoryOpen || history !== null) return;
    let cancelled = false;
    getCredentialHistory(credential.id).then((entries) => {
      if (!cancelled) setHistory(entries);
    });
    return () => {
      cancelled = true;
    };
    // history participates in the dependency array as an "already loaded" flag to avoid duplicate fetches
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

  // Enabling and clearing the item standalone password share one submit: a backend validation failure (e.g. a wrong current password) reports inline on the row
  const handleItemPwdSubmit = useCallback(async () => {
    if (itemPwdForm === null || isItemPwdBusy || !itemPwdValue) return;
    setIsItemPwdBusy(true);
    setItemPwdError(null);
    try {
      const res =
        itemPwdForm === 'set'
          ? await personaAPI.walletSetItemPassword(
              credential.id,
              itemPwdValue,
              itemPwdHintValue || undefined,
            )
          : await personaAPI.walletClearItemPassword(credential.id, itemPwdValue);
      if (res.success) {
        toast.success(itemPwdForm === 'set' ? t('detail.itemPwdSetOk') : t('detail.itemPwdClearOk'));
        setItemPwdEnabled(itemPwdForm === 'set');
        setItemPwdForm(null);
        setItemPwdValue('');
        setItemPwdHintValue('');
      } else {
        setItemPwdError(res.error ?? t('detail.itemPwdFailed'));
      }
    } catch (e) {
      setItemPwdError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsItemPwdBusy(false);
    }
  }, [itemPwdForm, isItemPwdBusy, itemPwdValue, itemPwdHintValue, credential.id, t]);

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

  /** Add attachment: native file picker → always a sealed save (with the credential item key) → appended to the list */
  const handleAttachFile = async () => {
    if (isAttachmentBusy) return;
    const selected = await openFileDialog({ multiple: false, title: t('detail.attachFileTitle') });
    const filePath = Array.isArray(selected) ? selected[0] : selected;
    if (!filePath) return; // the user cancelled
    setIsAttachmentBusy(true);
    try {
      const attachment = await attachFileToCredential(credential.id, filePath, true);
      if (attachment) setAttachments((prev) => [...prev, attachment]);
    } finally {
      setIsAttachmentBusy(false);
    }
  };

  /** Save attachment: native save dialog → decrypt and write out */
  const handleSaveAttachment = async (attachment: AttachmentEntry) => {
    if (isAttachmentBusy) return;
    const outputPath = await saveFileDialog({
      title: t('detail.saveAttachmentTitle'),
      defaultPath: attachment.filename,
    });
    if (!outputPath) return; // the user cancelled
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

  const handleRestoreVersion = async (entry: CredentialHistoryEntry) => {
    if (isRestoringVersion) return;
    const confirmed = window.confirm(
      t('detail.restoreConfirm', { name: credential.name, version: entry.version })
    );
    if (!confirmed) return;
    setIsRestoringVersion(true);
    try {
      const restored = await restoreCredentialVersion(credential.id, entry.version);
      if (restored) {
        setHistory(null);
      }
    } finally {
      setIsRestoringVersion(false);
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
            className="whitespace-nowrap p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
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
                className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
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
          <CredentialDataSection
            credential={credential}
            credentialData={credentialData}
            onCopy={onCopy}
            refreshTotp={refreshTotp}
            totpCode={totpCode}
            totpRemaining={totpRemaining}
            isTotpLoading={isTotpLoading}
            itemPwdEnabled={itemPwdEnabled}
            itemPwdForm={itemPwdForm}
            itemPwdValue={itemPwdValue}
            itemPwdHintValue={itemPwdHintValue}
            itemPwdError={itemPwdError}
            isItemPwdBusy={isItemPwdBusy}
            handleItemPwdSubmit={handleItemPwdSubmit}
            setItemPwdForm={setItemPwdForm}
            setItemPwdValue={setItemPwdValue}
            setItemPwdHintValue={setItemPwdHintValue}
          />
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
                  className="whitespace-nowrap px-2 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
        <AttachmentsSection
          attachments={attachments}
          isAttachmentBusy={isAttachmentBusy}
          handleAttachFile={handleAttachFile}
          handleSaveAttachment={handleSaveAttachment}
          handleDeleteAttachment={handleDeleteAttachment}
        />

        <CustomFieldsSection
          customFields={customFields}
          customFieldsError={customFieldsError}
          revealedFieldIds={revealedFieldIds}
          setRevealedFieldIds={setRevealedFieldIds}
          onCopy={onCopy}
        />

        <HistorySection
          isHistoryOpen={isHistoryOpen}
          setIsHistoryOpen={setIsHistoryOpen}
          history={history}
          isRestoringVersion={isRestoringVersion}
          handleRestoreVersion={handleRestoreVersion}
        />

        <div className="flex items-center justify-between pt-4 border-t">
          <span className={clsx(
            'whitespace-nowrap px-2 py-1 text-xs font-medium rounded-full border',
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
