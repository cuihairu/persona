import React, { useEffect, useRef, useState } from 'react';
import { XMarkIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';
import { personaAPI } from '@/utils/api';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

export interface ChangeMasterPasswordModalProps {
  isOpen: boolean;
  /**
   * 强制模式（解锁屏引导）：隐藏取消/关闭/Esc——轮换完成前不能离开；
   * 旧密码经 initialOldPassword 预填（仅存在于 React state，不落盘）
   */
  forced?: boolean;
  initialOldPassword?: string;
  /** 自定义 vault 路径（解锁屏自定义路径时透传；缺省用后端 state 记录的路径） */
  dbPath?: string;
  /** 轮换成功回调（携带新密码，供宿主重新 init 建会话） */
  onDone: (newPassword: string) => void;
  onCancel: () => void;
}

/**
 * 修改主密码弹窗：解锁屏强引导（forced）与 Settings 手动改密共用。
 * 客户端校验（非空/两次一致/新旧不同）→ change_master_password；
 * 成功后由宿主决定建新会话（解锁屏）或回锁屏（Settings）。
 */
const ChangeMasterPasswordModal: React.FC<ChangeMasterPasswordModalProps> = ({
  isOpen,
  forced = false,
  initialOldPassword,
  dbPath,
  onDone,
  onCancel,
}) => {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setOldPassword(initialOldPassword ?? '');
      setNewPassword('');
      setConfirmPassword('');
      setError(null);
      setIsSubmitting(false);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [isOpen, initialOldPassword]);

  // 非 forced 才可 Esc 离开；forced 模式轮换完成前不能逃逸
  useEscapeToClose(isOpen && !forced, onCancel);

  if (!isOpen) return null;

  const validate = (): string | null => {
    if (!oldPassword || !newPassword || !confirmPassword) {
      return 'All fields are required.';
    }
    if (newPassword !== confirmPassword) {
      return 'New passwords do not match.';
    }
    if (newPassword === oldPassword) {
      return 'New password must be different from the current password.';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      const resp = await personaAPI.changeMasterPassword(oldPassword, newPassword, dbPath);
      if (resp.success) {
        onDone(newPassword);
      } else {
        setError(resp.error || 'Failed to change master password');
        setIsSubmitting(false);
      }
    } catch {
      setError('Failed to change master password');
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      data-testid="change-password-modal"
    >
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
            {forced ? 'Master password change required' : 'Change master password'}
          </h2>
          {!forced && (
            <button
              onClick={onCancel}
              className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
              aria-label="Close"
            >
              <XMarkIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            </button>
          )}
        </div>

        <form onSubmit={handleSubmit}>
          <div className="px-5 py-4 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              {forced
                ? 'Your master password has expired per your security policy. Choose a new one to continue — your data stays untouched.'
                : 'All entries are re-encrypted under the new password. This may take a moment.'}
            </p>
            <div>
              <label htmlFor="change-pw-old" className="label mb-1 block">
                Current password
              </label>
              <input
                ref={inputRef}
                id="change-pw-old"
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                className="w-full input"
                autoComplete="current-password"
              />
            </div>
            <div>
              <label htmlFor="change-pw-new" className="label mb-1 block">
                New password
              </label>
              <input
                id="change-pw-new"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full input"
                autoComplete="new-password"
              />
            </div>
            <div>
              <label htmlFor="change-pw-confirm" className="label mb-1 block">
                Confirm new password
              </label>
              <input
                id="change-pw-confirm"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full input"
                autoComplete="new-password"
              />
            </div>
            {error && (
              <div
                className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded px-3 py-2"
                data-testid="change-password-error"
              >
                <ShieldExclamationIcon className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}
          </div>

          <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
            {!forced && (
              <button type="button" onClick={onCancel} className="btn-ghost">
                Cancel
              </button>
            )}
            <button
              type="submit"
              disabled={!oldPassword || !newPassword || !confirmPassword || isSubmitting}
              className="btn-primary"
            >
              {isSubmitting ? 'Changing…' : forced ? 'Change and unlock' : 'Change password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ChangeMasterPasswordModal;
