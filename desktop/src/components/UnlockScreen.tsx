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
  // The forced rotation modal needs the old password prefilled (the input that
  // was submitted); the modal collapses after the rotation is submitted
  const [submittedPassword, setSubmittedPassword] = useState('');
  const [rotationSubmitted, setRotationSubmitted] = useState(false);
  // biometric status (the fingerprint button renders only when available+enabled);
  // null = not configured / lookup failed
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

  // Query status on mount / when the custom path changes (debounced 200ms: one
  // keystroke per probe instead of hammering the keyring lookup)
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      personaAPI
        .biometricStatus(useCustomPath ? dbPath || undefined : undefined)
        .then((resp) => {
          if (!cancelled && resp.success && resp.data && resp.data.enabled) {
            setBiometric(resp.data);
          } else if (!cancelled) {
            // Not configured / backend says unavailable: no fingerprint button (fail-closed silent degradation)
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

  // Fingerprint unlock: on success go straight into the app (the backend has
  // already created the session); after a RESET the entry is gone, so refresh
  // the status to hide the button; other errors drive the error bar via the hook
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

  // Rotation done: re-init with the new password to establish a session (on success App switches away and this screen unmounts)
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

          {/* biometric unlock (rendered only when configured; the REJECT path goes through the generic error bar above) */}
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
