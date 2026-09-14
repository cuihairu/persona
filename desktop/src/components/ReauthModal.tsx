import React, { useEffect, useRef, useState } from 'react';
import { XMarkIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';

export interface ReauthModalProps {
  isOpen: boolean;
  error?: string | null;
  isVerifying?: boolean;
  onSubmit: (masterPassword: string) => void;
  onClose: () => void;
}

/**
 * 敏感操作重新认证弹窗：输入主密码 → reauth_verify。
 * 由 useReauth 驱动；Esc/取消/关闭都会以失败结束挂起的 Promise。
 */
const ReauthModal: React.FC<ReauthModalProps> = ({
  isOpen,
  error,
  isVerifying,
  onSubmit,
  onClose,
}) => {
  const [password, setPassword] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPassword('');
      // 等挂载后聚焦
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

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
    >
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <h2 className="text-base font-semibold text-gray-900">Re-authentication required</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded" aria-label="Close">
            <XMarkIcon className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-5 py-4 space-y-3">
            <p className="text-sm text-gray-600">
              This operation is security-sensitive. Confirm your master password to continue.
            </p>
            <input
              ref={inputRef}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              className="w-full input"
              autoComplete="current-password"
            />
            {error && (
              <div
                className="flex items-center gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2"
                data-testid="reauth-error"
              >
                <ShieldExclamationIcon className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}
          </div>

          <div className="px-5 py-4 border-t border-gray-200 flex justify-end gap-2">
            <button type="button" onClick={onClose} className="btn-ghost">
              Cancel
            </button>
            <button type="submit" disabled={!password || isVerifying} className="btn-primary">
              {isVerifying ? 'Verifying…' : 'Confirm'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ReauthModal;
