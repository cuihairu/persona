import React, { useEffect, useRef, useState } from 'react';
import { XMarkIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

export interface TravelPassphraseModalProps {
  isOpen: boolean;
  /** 'set' = enter 前设定 travel 口令（双录）；'enter' = exit 时输既有口令（单录） */
  mode: 'set' | 'enter';
  /** 标题下的一句话说明（已标记身份数等上下文由调用方拼好传入） */
  description?: string;
  error?: string | null;
  isBusy?: boolean;
  onSubmit: (passphrase: string) => void;
  onClose: () => void;
}

/**
 * 旅行模式口令弹窗。travel 口令与主密码相互独立：enter 设定（双录）、
 * exit 验证（单录）。错口令/校验失败留在弹窗内原地重试（error 驱动错误条）。
 */
const TravelPassphraseModal: React.FC<TravelPassphraseModalProps> = ({
  isOpen,
  mode,
  description,
  error,
  isBusy,
  onSubmit,
  onClose,
}) => {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPassphrase('');
      setConfirm('');
      setMismatch(false);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [isOpen]);

  useEscapeToClose(isOpen, onClose);
  if (!isOpen) return null;

  const isSet = mode === 'set';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase || isBusy) return;
    if (isSet) {
      if (passphrase !== confirm) {
        setMismatch(true);
        return;
      }
      setMismatch(false);
    }
    onSubmit(passphrase);
  };

  const shownError = mismatch ? t('settings.travel.passphraseMismatch') : error;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="travel-passphrase-modal"
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            {t(isSet ? 'settings.travel.setTitle' : 'settings.travel.enterTitle')}
          </h2>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
            aria-label={t('common.close')}
          >
            <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-5 py-4 space-y-3">
            {description && (
              <p className="text-sm text-gray-600 dark:text-gray-300">{description}</p>
            )}
            <input
              ref={inputRef}
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder={t('settings.travel.passphrasePlaceholder')}
              className="w-full input"
              autoComplete={isSet ? 'new-password' : 'current-password'}
              data-testid="travel-passphrase-input"
            />
            {isSet && (
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder={t('settings.travel.confirmPlaceholder')}
                className="w-full input"
                autoComplete="new-password"
                data-testid="travel-passphrase-confirm-input"
              />
            )}
            {shownError && (
              <div
                className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded px-3 py-2"
                data-testid="travel-passphrase-error"
              >
                <ShieldExclamationIcon className="w-4 h-4 shrink-0" />
                {shownError}
              </div>
            )}
            {isSet && (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                {t('settings.travel.noFallbackWarning')}
              </p>
            )}
          </div>

          <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
            <button type="button" onClick={onClose} className="btn-ghost">
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={!passphrase || isBusy || (isSet && !confirm)}
              data-testid="travel-passphrase-submit"
              className="btn-primary"
            >
              {t(isSet ? 'settings.travel.setConfirm' : 'settings.travel.enterConfirm')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default TravelPassphraseModal;
