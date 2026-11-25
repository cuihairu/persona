import React, { useEffect } from 'react';
import { FingerPrintIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import type { PasskeyApprovalRequest } from '@/types';

export interface PasskeyApprovalModalProps {
  request: PasskeyApprovalRequest | null;
  /** Total number of requests the backend is still awaiting a response for (when >1, a queue hint is shown) */
  pendingCount?: number;
  onRespond: (requestId: string, allow: boolean) => void;
}

/** Hostname of the origin (null when parsing fails) */
const hostnameOf = (origin: string): string | null => {
  try {
    return new URL(origin).hostname;
  } catch {
    return null;
  }
};

/** Title i18n key (rendered via t()) */
const titleFor = (request: PasskeyApprovalRequest): string =>
  request.operation === 'passkey_create' ? 'passkeyApproval.createTitle' : 'passkeyApproval.assertTitle';

/**
 * Passkey approval modal: shown when the bridge (browser extension over a Unix
 * socket) requests registration/assertion. Displays the full origin / rp_id /
 * account; after Deny the bridge rejects the request. When rp_id differs from
 * the origin hostname, an explanation is shown — this is a visible signal for
 * cross-domain requests (following the cross-domain hint precedent in the
 * extension's content.ts).
 */
const PasskeyApprovalModal: React.FC<PasskeyApprovalModalProps> = ({
  request,
  pendingCount = 0,
  onRespond,
}) => {
  const { t } = useTranslation();
  useEffect(() => {
    if (!request) return;
    const onKey = (e: KeyboardEvent) => {
      // Esc = deny: safe default
      if (e.key === 'Escape') onRespond(request.request_id, false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [request, onRespond]);

  if (!request) return null;

  const isCreate = request.operation === 'passkey_create';
  const crossDomain =
    request.rp_id !== null && hostnameOf(request.origin) !== request.rp_id;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="passkey-approval-modal"
      role="alertdialog"
      aria-label={t('passkeyApproval.ariaLabel')}
      onMouseDown={(e) => {
        // Click on backdrop = deny (safe default, same as Esc); approval must be explicit
        if (e.target === e.currentTarget) onRespond(request.request_id, false);
      }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">{t(titleFor(request))}</h2>
          <FingerPrintIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
        </div>

        <div className="px-5 py-4 space-y-3">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {isCreate
              ? t('passkeyApproval.createDescription')
              : t('passkeyApproval.assertDescription')}
          </p>

          <dl className="text-sm space-y-2">
            <div className="flex gap-2">
              <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('passkeyApproval.site')}</dt>
              <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="approval-origin">
                {request.origin}
              </dd>
            </div>
            {request.rp_id !== null && (
              <div className="flex gap-2">
                <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('passkeyApproval.passkeyFor')}</dt>
                <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="approval-rp-id">
                  {request.rp_id}
                </dd>
              </div>
            )}
            {request.user_name !== null && (
              <div className="flex gap-2">
                <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('passkeyApproval.account')}</dt>
                <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="approval-user">
                  {request.user_name}
                </dd>
              </div>
            )}
            <div className="flex gap-2">
              <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('approval.operation')}</dt>
              <dd className="font-mono text-gray-900 dark:text-gray-100" data-testid="approval-operation">
                {request.operation}
              </dd>
            </div>
          </dl>

          {crossDomain && (
            <div className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 rounded px-3 py-2">
              <ShieldExclamationIcon className="w-4 h-4 shrink-0 mt-0.5" />
              <span data-testid="approval-warning">
                {t('passkeyApproval.crossDomainWarning', { rpId: request.rp_id })}
              </span>
            </div>
          )}

          {pendingCount > 1 && (
            <p className="text-xs text-gray-500 dark:text-gray-400" data-testid="approval-queue-count">
              {t('approval.moreWaiting', { count: pendingCount - 1 })}
            </p>
          )}
        </div>

        <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => onRespond(request.request_id, false)}
            className="btn-ghost"
            data-testid="approval-deny"
          >
            {t('approval.deny')}
          </button>
          <button
            type="button"
            onClick={() => onRespond(request.request_id, true)}
            className="btn-primary"
            data-testid="approval-allow"
          >
            {t('approval.allow')}
          </button>
        </div>
      </div>
    </div>
  );
};

export default PasskeyApprovalModal;
