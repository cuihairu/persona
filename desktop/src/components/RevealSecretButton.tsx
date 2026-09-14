import React, { useCallback, useEffect, useRef, useState } from 'react';
import { EyeIcon, EyeSlashIcon, DocumentDuplicateIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { personaAPI } from '@/utils/api';
import { copyWithAutoClear } from '@/utils/clipboard';
import { useReauth } from '@/hooks/useReauth';
import type { SecretField } from '@/types';
import ReauthModal from '@/components/ReauthModal';

export interface RevealSecretButtonProps {
  credentialId: string;
  /** 要揭示的敏感字段 */
  field: SecretField;
  /** 字段显示名（Password / Private Key …） */
  label: string;
  /** 揭示后自动隐藏秒数（默认 30） */
  autoHideSeconds?: number;
  /** 自定义复制行为（默认 copyWithAutoClear，30s 自动清空剪贴板） */
  onCopy?: (value: string) => void;
}

/**
 * 统一敏感字段揭示按钮：
 * 点击 → reveal_credential_secret（后端含敏感检查 + 审计）
 *   - 返回 REAUTH_REQUIRED → 弹 ReauthModal，验证通过后自动重试一次
 *   - 成功 → 明文展示并启动自动隐藏倒计时
 * 复制走 copyWithAutoClear（剪贴板 30s 自动清空）。
 */
const RevealSecretButton: React.FC<RevealSecretButtonProps> = ({
  credentialId,
  field,
  label,
  autoHideSeconds = 30,
  onCopy,
}) => {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reauth = useReauth();
  const retryRef = useRef(false);

  const doReveal = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await personaAPI.revealCredentialSecret(credentialId, field);
      if (res.success && res.data) {
        setRevealed(res.data.value);
        setRemaining(autoHideSeconds);
      } else if (res.error_code === 'REAUTH_REQUIRED') {
        // 弹重新认证；成功且未重试过则自动重放一次
        if (!retryRef.current && (await reauth.requestReauth())) {
          retryRef.current = true;
          await doReveal();
        }
      } else if (res.error_code === 'SERVICE_LOCKED') {
        setError('Service is locked. Unlock and try again.');
      } else {
        setError(res.error ?? 'Failed to reveal secret');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  }, [credentialId, field, autoHideSeconds, reauth]);

  const handleHide = () => {
    setRevealed(null);
    setRemaining(null);
    retryRef.current = false;
  };

  // 自动隐藏倒计时
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
            <span className="text-xs text-gray-400 shrink-0" data-testid="reveal-countdown">
              hides in {remaining}s
            </span>
          )}
          <button onClick={handleHide} className="p-1 hover:bg-gray-100 rounded" aria-label={`Hide ${label}`}>
            <EyeSlashIcon className="w-4 h-4 text-gray-400" />
          </button>
        </>
      ) : (
        <button
          onClick={doReveal}
          disabled={isLoading}
          className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 disabled:opacity-50"
          data-testid="reveal-trigger"
        >
          {isLoading ? (
            <ArrowPathIcon className="w-4 h-4 animate-spin" />
          ) : (
            <EyeIcon className="w-4 h-4" />
          )}
          Reveal {label}
        </button>
      )}

      {revealed !== null && (
        <button onClick={handleCopy} className="p-1 hover:bg-gray-100 rounded" aria-label={`Copy ${label}`}>
          <DocumentDuplicateIcon className="w-4 h-4 text-gray-400" />
        </button>
      )}

      {error && (
        <span className="text-xs text-red-600" data-testid="reveal-error">
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
