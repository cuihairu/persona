import React, { useCallback, useEffect, useRef, useState } from 'react';
import { EyeIcon, EyeSlashIcon, DocumentDuplicateIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import { useReauth } from '@/hooks/useReauth';
import type { SecretField } from '@/types';
import ReauthModal from '@/components/ReauthModal';

export interface RevealSecretButtonProps {
  credentialId: string;
  /** The sensitive field to reveal */
  field: SecretField;
  /** Display name of the field (Password / Private Key …) */
  label: string;
  /** Seconds before auto-hide after revealing (default 30) */
  autoHideSeconds?: number;
  /** Custom copy behavior (defaults to copyWithAutoClear, which clears the clipboard after 30s) */
  onCopy?: (value: string) => void;
}

/**
 * Unified sensitive-field reveal button:
 * click → reveal_credential_secret (backend includes sensitivity checks + audit)
 *   - REAUTH_REQUIRED → open ReauthModal; after successful verification, retry once automatically
 *   - success → show the plaintext and start the auto-hide countdown
 * Copying goes through copyWithAutoClear (clipboard auto-cleared after 30s).
 */
const RevealSecretButton: React.FC<RevealSecretButtonProps> = ({
  credentialId,
  field,
  label,
  autoHideSeconds = 30,
  onCopy,
}) => {
  const { t } = useTranslation();
  const [revealed, setRevealed] = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reauth = useReauth();
  const retryRef = useRef(false);
  // Wallet item's standalone password (second factor): when the backend returns ITEM_PASSWORD_REQUIRED,
  // expand the input row; once verified it is remembered within the component (forgotten when switching
  // items or closing the panel unmounts it)
  const [rememberedItemPwd, setRememberedItemPwd] = useState<string | null>(null);
  const [needsItemPassword, setNeedsItemPassword] = useState(false);
  const [itemPwdInput, setItemPwdInput] = useState('');

  const doReveal = useCallback(
    async (itemPassword?: string) => {
      setIsLoading(true);
      setError(null);
      try {
        const res = await personaAPI.revealCredentialSecret(credentialId, field, itemPassword);
        if (res.success && res.data) {
          setRevealed(res.data.value);
          setRemaining(autoHideSeconds);
          // Remember a verified item password within the component: later reveals of the same item skip re-entry
          if (itemPassword) setRememberedItemPwd(itemPassword);
          setNeedsItemPassword(false);
          setItemPwdInput('');
        } else if (res.error_code === 'REAUTH_REQUIRED') {
          // Open re-verification; on success, if not retried yet, replay once automatically
          if (!retryRef.current && (await reauth.requestReauth())) {
            retryRef.current = true;
            await doReveal(itemPassword);
          }
        } else if (res.error_code === 'ITEM_PASSWORD_REQUIRED') {
          setNeedsItemPassword(true);
        } else if (res.error_code === 'ITEM_PASSWORD_WRONG') {
          setNeedsItemPassword(true);
          setError(t('reveal.itemPasswordWrong'));
        } else if (res.error_code === 'SERVICE_LOCKED') {
          setError(t('common.serviceLocked'));
        } else {
          setError(res.error ?? t('reveal.failed'));
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setIsLoading(false);
      }
    },
    [credentialId, field, autoHideSeconds, reauth, t],
  );

  const handleHide = () => {
    setRevealed(null);
    setRemaining(null);
    retryRef.current = false;
    setNeedsItemPassword(false);
    setItemPwdInput('');
  };

  // Auto-hide countdown
  useEffect(() => {
    if (remaining === null) return;
    if (remaining <= 0) {
      handleHide();
      return;
    }
    const timer = window.setTimeout(() => setRemaining((r) => (r === null ? null : r - 1)), 1000);
    return () => window.clearTimeout(timer);
  }, [remaining]);

  const handleCopy = () => {
    if (revealed === null) return;
    if (onCopy) {
      onCopy(revealed);
    } else {
      void copyWithAutoClear(revealed);
    }
  };

  return (
    <div className="flex items-center gap-2" data-testid={`reveal-${field}`}>
      {revealed !== null ? (
        <>
          <span className="text-sm font-mono break-all" data-testid="revealed-value">
            {revealed}
          </span>
          {remaining !== null && remaining > 0 && (
            <span className="text-xs text-gray-400 dark:text-gray-500 shrink-0" data-testid="reveal-countdown">
              {t('reveal.hidesIn', { seconds: remaining })}
            </span>
          )}
          <button onClick={handleHide} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" aria-label={t('reveal.hide', { label })}>
            <EyeSlashIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
          </button>
        </>
      ) : (
        <button
          onClick={() => doReveal(rememberedItemPwd ?? undefined)}
          disabled={isLoading}
          className="whitespace-nowrap flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 disabled:opacity-50"
          data-testid="reveal-trigger"
        >
          {isLoading ? (
            <ArrowPathIcon className="w-4 h-4 animate-spin" />
          ) : (
            <EyeIcon className="w-4 h-4" />
          )}
          {t('reveal.trigger', { label })}
        </button>
      )}

      {needsItemPassword && revealed === null && (
        <form
          className="flex w-full items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (itemPwdInput) doReveal(itemPwdInput);
          }}
        >
          <input
            type="password"
            value={itemPwdInput}
            onChange={(e) => setItemPwdInput(e.target.value)}
            className="input h-8 flex-1 text-sm"
            placeholder={t('reveal.itemPasswordPrompt')}
            aria-label={t('reveal.itemPasswordPrompt')}
            autoComplete="off"
            data-testid="item-password-input"
            autoFocus
          />
          <button
            type="submit"
            disabled={isLoading || !itemPwdInput}
            className="btn-secondary text-xs shrink-0 disabled:opacity-50"
            data-testid="item-password-submit"
          >
            {t('reveal.itemPasswordSubmit')}
          </button>
        </form>
      )}

      {revealed !== null && (
        <button onClick={handleCopy} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" aria-label={t('reveal.copy', { label })}>
          <DocumentDuplicateIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
        </button>
      )}

      {error && (
        <span className="text-xs text-red-600 dark:text-red-400" data-testid="reveal-error">
          {error}
        </span>
      )}

      <ReauthModal
        isOpen={reauth.isOpen}
        error={reauth.error}
        isVerifying={reauth.isVerifying}
        onSubmit={reauth.submit}
        onClose={reauth.cancel}
      />
    </div>
  );
};

export default RevealSecretButton;
