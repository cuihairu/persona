import React, { useEffect } from 'react';
import { FingerPrintIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import type { PasskeyApprovalRequest } from '@/types';

export interface PasskeyApprovalModalProps {
  request: PasskeyApprovalRequest | null;
  /** 后端仍在等待应答的请求总数（>1 时提示还有排队） */
  pendingCount?: number;
  onRespond: (requestId: string, allow: boolean) => void;
}

/** origin 的 hostname（解析失败返回 null） */
const hostnameOf = (origin: string): string | null => {
  try {
    return new URL(origin).hostname;
  } catch {
    return null;
  }
};

/** 标题 i18n key（渲染处 t()） */
const titleFor = (request: PasskeyApprovalRequest): string =>
  request.operation === 'passkey_create' ? 'passkeyApproval.createTitle' : 'passkeyApproval.assertTitle';

/**
 * Passkey 审批弹窗：bridge（浏览器扩展经 Unix socket）请求注册/断言时弹出。
 * 显示完整 origin / rp_id / 账号；Deny 后 bridge 拒绝该请求。
 * rp_id 与 origin hostname 不一致时给出解释——这是跨域请求的可见信号
 * （照扩展 content.ts 的跨域提示先例）。
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
      // Esc = 拒绝：安全默认
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
