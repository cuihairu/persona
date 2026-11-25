import React, { useEffect, useRef, useState } from 'react';
import { XMarkIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';
import { usePersonaService } from '@/hooks/usePersonaService';

export interface UnlockGateModalProps {
  isOpen: boolean;
  /** Resolves the pending original operation: continue (true) / abandon (false) */
  onResolve: (unlocked: boolean) => void;
}

/**
 * SERVICE_LOCKED guided-unlock modal: with the backend's lazy auto-lock (no
 * locked event leaves a race window), an operation hitting "Session is
 * auto-locked" triggers the invoke gate in utils/api — enter the master
 * password to unlock, and on success the pending original operation retries
 * automatically. Unlike the lock screen (UnlockScreen), this is an in-flight
 * guided flow that doesn't interrupt the current page context.
 */
const UnlockGateModal: React.FC<UnlockGateModalProps> = ({ isOpen, onResolve }) => {
  const { t } = useTranslation();
  const { initializeService } = usePersonaService();
  const [password, setPassword] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPassword('');
      setIsVerifying(false);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [isOpen]);

  const close = (unlocked: boolean) => onResolve(unlocked);
  useEscapeToClose(isOpen, () => close(false));
  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || isVerifying) return;
    setIsVerifying(true);
    // On success initializeService restores the store's unlocked state and reloads identities; failure is already toasted
    const ok = await initializeService(password);
    setIsVerifying(false);
    if (ok) close(true);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="unlock-gate-modal"
      onMouseDown={(e) => {
        // Click on backdrop = cancel (the original operation returns with its original error), same as Esc
        if (e.target === e.currentTarget) close(false);
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            {t('unlockGate.title')}
          </h2>
          <button
            onClick={() => close(false)}
            className="whitespace-nowrap p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            aria-label={t('common.close')}
          >
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-5 py-4 space-y-3">
            <p className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-300">
              <LockClosedIcon className="w-4 h-4 shrink-0 mt-0.5 text-gray-400 dark:text-gray-500" />
              {t('unlockGate.description')}
            </p>
            <input
              ref={inputRef}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('unlockGate.passwordPlaceholder')}
              className="w-full input"
              autoComplete="current-password"
              data-testid="unlock-gate-password"
            />
          </div>

          <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
            <button type="button" onClick={() => close(false)} className="btn-ghost">
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={!password || isVerifying}
              className="btn-primary"
              data-testid="unlock-gate-submit"
            >
              {isVerifying ? t('unlockGate.verifying') : t('unlockGate.submit')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default UnlockGateModal;
