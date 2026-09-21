import React, { useEffect, useState } from 'react';
import { EyeIcon, EyeSlashIcon, FingerPrintIcon, KeyIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import type { BiometricStatus } from '@/types';
import ChangeMasterPasswordModal from './ChangeMasterPasswordModal';

interface UnlockScreenProps {
  onUnlock: () => void;
}

const UnlockScreen: React.FC<UnlockScreenProps> = ({ onUnlock }) => {
  const { t } = useTranslation();
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [dbPath, setDbPath] = useState('');
  const [useCustomPath, setUseCustomPath] = useState(false);
  // 强制改密弹窗需要旧密码预填（提交过的那次输入）；轮换提交后收起弹窗
  const [submittedPassword, setSubmittedPassword] = useState('');
  const [rotationSubmitted, setRotationSubmitted] = useState(false);
  // biometric 状态（available+enabled 才渲染指纹按钮）；null = 未配置/查询失败
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [biometricBusy, setBiometricBusy] = useState(false);

  const {
    initializeService,
    unlockWithBiometric,
    isLoading,
    error,
    passwordChangeRequired,
  } = usePersonaService();

  const effectiveDbPath = useCustomPath ? dbPath : undefined;

  // mount / 自定义路径变更时查 status（防抖 200ms：每键一击不轰 keyring 探测）
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      personaAPI
        .biometricStatus(useCustomPath ? dbPath || undefined : undefined)
        .then((resp) => {
          if (!cancelled && resp.success && resp.data && resp.data.enabled) {
            setBiometric(resp.data);
          } else if (!cancelled) {
            // 未配置 / 后端判断不可用：无指纹按钮（fail-closed 静默降级）
            setBiometric(null);
          }
        })
        .catch(() => {
          if (!cancelled) setBiometric(null);
        });
    }, 200);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [useCustomPath, dbPath]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterPassword.trim()) return;

    const password = masterPassword;
    setSubmittedPassword(password);
    const ok = await initializeService(password, useCustomPath ? dbPath : undefined);
    if (ok) {
      onUnlock();
    }
  };

  // 指纹解锁：成功直接进应用（后端已建会话）；RESET 后条目已删，刷新
  // status 隐藏按钮；其余错误由 hook 的 error 驱动错误条
  const handleBiometricUnlock = async () => {
    setBiometricBusy(true);
    try {
      const resp = await unlockWithBiometric(effectiveDbPath);
      if (resp.success) {
        onUnlock();
      } else if (resp.error_code === 'BIOMETRIC_RESET') {
        setBiometric(null);
      }
    } finally {
      setBiometricBusy(false);
    }
  };

  // 轮换完成：用新密码重新 init 建会话（成功后 App 切走，本屏卸载）
  const handleRotationDone = async (newPassword: string) => {
    setRotationSubmitted(true);
    const ok = await initializeService(newPassword, useCustomPath ? dbPath : undefined);
    if (ok) {
      onUnlock();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-50 dark:from-primary-900/40 dark:to-secondary-900 flex items-center justify-center p-4">
      {passwordChangeRequired && !rotationSubmitted && (
        <ChangeMasterPasswordModal
          isOpen
          forced
          initialOldPassword={submittedPassword}
          dbPath={effectiveDbPath}
          onDone={handleRotationDone}
          onCancel={() => {}}
        />
      )}
      <div className="max-w-md w-full">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="mx-auto w-20 h-20 bg-primary-600 rounded-full flex items-center justify-center mb-4">
            <KeyIcon className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-secondary-900 dark:text-secondary-100 mb-2">Persona</h1>
          <p className="text-secondary-600 dark:text-secondary-400">{t('unlock.tagline')}</p>
        </div>

        {/* Unlock Form */}
        <div className="card p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="master-password" className="label text-secondary-700 dark:text-secondary-300 mb-2 block">
                {t('unlock.masterPassword')}
              </label>
              <div className="relative">
                <input
                  id="master-password"
                  type={showPassword ? 'text' : 'password'}
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="input pr-10"
                  placeholder={t('unlock.enterPassword')}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                >
                  {showPassword ? (
                    <EyeSlashIcon className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-gray-400 dark:text-gray-500" />
                  )}
                </button>
              </div>
            </div>

            {/* Advanced Options */}
            <div>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={useCustomPath}
                  onChange={(e) => setUseCustomPath(e.target.checked)}
                  className="rounded border-gray-300 dark:border-gray-600 text-primary-600 dark:text-primary-400 focus:ring-primary-500"
                />
                <span className="ml-2 text-sm text-secondary-700 dark:text-secondary-300">{t('unlock.useCustomPath')}</span>
              </label>
            </div>

            {useCustomPath && (
              <div>
                <label htmlFor="db-path" className="label text-secondary-700 dark:text-secondary-300 mb-2 block">
                  {t('unlock.dbPath')}
                </label>
                <input
                  id="db-path"
                  type="text"
                  value={dbPath}
                  onChange={(e) => setDbPath(e.target.value)}
                  className="input"
                  placeholder="/path/to/persona.db"
                />
              </div>
            )}

            {error && (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-md p-3">
                <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !masterPassword.trim()}
              className="btn-primary w-full"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  {t('unlock.unlocking')}
                </div>
              ) : (
                t('unlock.unlock')
              )}
            </button>
          </form>

          {/* biometric 解锁（配置过才渲染；REJECT 路径走上方通用错误条） */}
          {biometric && biometric.available && biometric.enabled && (
            <button
              type="button"
              data-testid="biometric-unlock-button"
              onClick={handleBiometricUnlock}
              disabled={biometricBusy || isLoading}
              className="btn-secondary w-full mt-3 flex items-center justify-center gap-2"
            >
              {biometricBusy ? (
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-500 dark:border-gray-300" />
              ) : (
                <FingerPrintIcon className="h-5 w-5" />
              )}
              {t('unlock.biometricUnlock')}
            </button>
          )}

          <div className="mt-6 text-center">
            <p className="text-xs text-secondary-500 dark:text-secondary-400">
              {t('unlock.firstUseHint')}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UnlockScreen;
