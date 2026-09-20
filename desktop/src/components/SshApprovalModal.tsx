import React, { useEffect } from 'react';
import { KeyIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import type { SshApprovalRequest } from '@/types';

export interface SshApprovalModalProps {
  request: SshApprovalRequest | null;
  /** 后端仍在等待应答的请求总数（>1 时提示还有排队） */
  pendingCount?: number;
  onRespond: (requestId: string, allow: boolean) => void;
}

/**
 * SSH 签名审批弹窗：内嵌 agent 需要用户确认时弹出。
 * 显示公钥指纹 / 目标主机 / 触发原因；Deny 后 agent 拒签。
 * 无密码输入——审批只决定"允许用已解锁的钥匙签名"。
 */
const SshApprovalModal: React.FC<SshApprovalModalProps> = ({
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

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="ssh-approval-modal"
      role="alertdialog"
      aria-label={t('sshApproval.ariaLabel')}
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">{t('sshApproval.title')}</h2>
          <KeyIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
        </div>

        <div className="px-5 py-4 space-y-3">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {t('sshApproval.description')}
          </p>

          <dl className="text-sm space-y-2">
            <div className="flex gap-2">
              <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('sshApproval.targetHost')}</dt>
              <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="approval-peer">
                {request.peer ?? t('approval.unknown')}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('sshApproval.key')}</dt>
              <dd className="font-mono text-gray-900 dark:text-gray-100 break-all" data-testid="approval-fingerprint">
                {request.fingerprint}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-gray-500 dark:text-gray-400 w-24 shrink-0">{t('approval.operation')}</dt>
              <dd className="font-mono text-gray-900 dark:text-gray-100" data-testid="approval-operation">
                {request.operation}
              </dd>
            </div>
          </dl>

          <div className="flex items-start gap-2 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 rounded px-3 py-2">
            <ShieldExclamationIcon className="w-4 h-4 shrink-0 mt-0.5" />
            <span data-testid="approval-reason">{request.reason}</span>
          </div>

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

export default SshApprovalModal;
