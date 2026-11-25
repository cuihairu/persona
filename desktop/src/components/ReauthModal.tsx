import React, { useEffect, useRef, useState } from 'react';
import { XMarkIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

export interface ReauthModalProps {
  isOpen: boolean;
  error?: string | null;
  isVerifying?: boolean;
  onSubmit: (masterPassword: string) => void;
  onClose: () => void;
}

/**
 * Re-authentication modal for sensitive operations: enter the master password
 * → reauth_verify. Driven by useReauth; Esc/cancel/close all settle the
 * pending Promise as a failure.
 */
const ReauthModal: React.FC<ReauthModalProps> = ({
  isOpen,
  error,
  isVerifying,
  onSubmit,
  onClose,
}) => {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPassword('');
      // Focus after mount
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [isOpen]);

  // Esc closes immediately (shared useEscapeToClose implementation; with stacked modals the top one takes over the lower one's listener)
  useEscapeToClose(isOpen, onClose);
  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || isVerifying) return;
    onSubmit(password);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="reauth-modal"
      onMouseDown={(e) => {
        // Click on backdrop = close, same as Esc/the close button
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">{t('reauth.title')}</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded" aria-label={t('common.close')}>
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-5 py-4 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              {t('reauth.description')}
            </p>
            <input
              ref={inputRef}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('reauth.passwordPlaceholder')}
              className="w-full input"
              autoComplete="current-password"
            />
            {error && (
              <div
                className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded px-3 py-2"
                data-testid="reauth-error"
              >
                <ShieldExclamationIcon className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}
          </div>

          <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
            <button type="button" onClick={onClose} className="btn-ghost">
              {t('common.cancel')}
            </button>
            <button type="submit" disabled={!password || isVerifying} className="btn-primary">
              {isVerifying ? t('reauth.verifying') : t('reauth.confirm')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ReauthModal;
