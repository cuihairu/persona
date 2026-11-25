import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import type { BiometricStatus, TravelStatus } from '@/types';
import ChangeMasterPasswordModal from '../ChangeMasterPasswordModal';
import ReauthModal from '../ReauthModal';
import TravelPassphraseModal from '../TravelPassphraseModal';
import TravelModeSection from './TravelModeSection';

/** Password security block of the General pane: expiry policy (NIST-leaning default of no expiry) + manual password change. */
const SECURITY_EXPIRY_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'settings.security.expiryNever' },
  { value: '90', label: 'settings.security.expiry90' },
  { value: '180', label: 'settings.security.expiry180' },
  { value: '365', label: 'settings.security.expiry365' },
];

const SecurityPane: React.FC<{
  changingPassword: boolean;
  setChangingPassword: (open: boolean) => void;
}> = ({ changingPassword, setChangingPassword }) => {
  const { t } = useTranslation();
  const { lockService, loadIdentities } = usePersonaService();
  const [expiryDays, setExpiryDays] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  // biometric: enabled = the keyring holds an escrow entry (queried live; not derived from
  // the settings JSON, two sources of truth would drift). null = not yet queried (toggle disabled).
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [showEnableModal, setShowEnableModal] = useState(false);
  const [enabling, setEnabling] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);

  // Travel mode: status is readable without unlocking; enter/exit opens a passphrase modal.
  // On REAUTH_REQUIRED verify the master password first, then reopen the passphrase modal
  // (the plaintext passphrase is never kept across modals).
  const [travelStatus, setTravelStatus] = useState<TravelStatus | null>(null);
  const [travelModalMode, setTravelModalMode] = useState<null | 'set' | 'enter'>(null);
  // Original intent before REAUTH interrupted (the passphrase modal reopens accordingly after reauth succeeds)
  const [travelPendingMode, setTravelPendingMode] = useState<'set' | 'enter'>('set');
  const [travelBusy, setTravelBusy] = useState(false);
  const [travelError, setTravelError] = useState<string | null>(null);
  const [travelReauthOpen, setTravelReauthOpen] = useState(false);

  const refreshTravelStatus = async () => {
    try {
      const resp = await personaAPI.getTravelStatus();
      if (resp.success && resp.data) setTravelStatus(resp.data);
    } catch {
      // A status read failure doesn't disrupt the pane; keep the last value
    }
  };

  // Initial value comes from server truth (missing key in old JSON → null = no expiry)
  useEffect(() => {
    let cancelled = false;
    personaAPI
      .getWorkspaceSettings()
      .then((resp) => {
        if (cancelled || !resp.success || !resp.data) return;
        setExpiryDays(resp.data.password_expiry_days ?? null);
      })
      .catch(() => {});
    personaAPI
      .biometricStatus()
      .then((resp) => {
        if (!cancelled && resp.success && resp.data) setBiometric(resp.data);
      })
      .catch(() => {});
    void refreshTravelStatus();
    return () => {
      cancelled = true;
    };
  }, []);

  const changeExpiry = async (raw: string) => {
    const days = raw === '' ? null : Number(raw);
    setSaving(true);
    try {
      const resp = await personaAPI.setPasswordExpiry(days);
      if (resp.success && resp.data) {
        setExpiryDays(resp.data.password_expiry_days ?? null);
        toast.success(t('settings.security.policySaved'));
      } else {
        toast.error(resp.error || t('settings.security.policySaveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.security.policySaveFailed'));
    } finally {
      setSaving(false);
    }
  };

  // After a successful password change in the unlocked state, return to the lock screen:
  // the old session key in state.service is already invalidated, and unlocking again builds
  // a session with the new password (simplest safe semantics)
  const handleRotationDone = async () => {
    setChangingPassword(false);
    toast.success(t('settings.security.changedRelock'));
    await lockService();
  };

  // On = verify the master password first (ReauthModal) → the backend then raises the OS auth
  // prompt; off = idempotent delete (tightening operations get no password gate). Enable's
  // success/failure closes the loop inside the modal, so it can be retried in place.
  const handleBiometricToggle = () => {
    if (biometric?.enabled) {
      void disableBiometric();
    } else {
      setEnableError(null);
      setShowEnableModal(true);
    }
  };

  const disableBiometric = async () => {
    setSaving(true);
    try {
      const resp = await personaAPI.biometricDisable();
      if (resp.success && resp.data) {
        setBiometric(resp.data);
        toast.success(t('settings.security.biometricDisabled'));
      } else {
        toast.error(resp.error || t('settings.security.biometricOperationFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.security.biometricOperationFailed'));
    } finally {
      setSaving(false);
    }
  };

  // The plaintext password the ReauthModal receives is the request body; failures stay in the
  // modal (enableError drives the modal's error bar) and closing is not swallowed
  const handleBiometricEnable = async (masterPassword: string) => {
    setEnabling(true);
    try {
      const resp = await personaAPI.biometricEnable(masterPassword);
      if (resp.success && resp.data) {
        setBiometric(resp.data);
        setShowEnableModal(false);
        toast.success(t('settings.security.biometricEnabled'));
      } else {
        setEnableError(resp.error || t('settings.security.biometricOperationFailed'));
      }
    } catch {
      setEnableError(t('settings.security.biometricOperationFailed'));
    } finally {
      setEnabling(false);
    }
  };

  // ---------------------------------------------------------------------
  // Travel mode: enter (passphrase modal mode='set') / exit (mode='enter').
  // REAUTH_REQUIRED → close the passphrase modal, open ReauthModal; once verified, reopen
  // the passphrase modal per the original intent and enter the travel passphrase (the
  // passphrase is not kept across modals). On success refresh the status and reload the
  // identity list.
  // ---------------------------------------------------------------------
  const submitTravelPassphrase = async (passphrase: string) => {
    const mode = travelModalMode;
    if (!mode) return;
    setTravelBusy(true);
    setTravelError(null);
    try {
      const resp =
        mode === 'set'
          ? await personaAPI.enterTravelMode(passphrase)
          : await personaAPI.exitTravelMode(passphrase);
      if (resp.success && resp.data) {
        setTravelModalMode(null);
        await refreshTravelStatus();
        await loadIdentities();
        toast.success(
          t(mode === 'set' ? 'settings.travel.entered' : 'settings.travel.exited', {
            count: resp.data.identities,
          }),
        );
      } else if (resp.error_code === 'REAUTH_REQUIRED') {
        setTravelPendingMode(mode);
        setTravelModalMode(null);
        setTravelReauthOpen(true);
      } else {
        setTravelError(resp.error || t('settings.travel.operationFailed'));
      }
    } catch {
      setTravelError(t('settings.travel.operationFailed'));
    } finally {
      setTravelBusy(false);
    }
  };

  // A reauth failure is shown in ReauthModal's error bar too (travelError only feeds it at that point)
  const handleTravelReauth = async (masterPassword: string) => {
    setTravelBusy(true);
    try {
      const resp = await personaAPI.reauthVerify(masterPassword);
      if (resp.success && resp.data) {
        setTravelError(null);
        setTravelReauthOpen(false);
        setTravelModalMode(travelPendingMode);
      } else {
        setTravelError(resp.error || t('settings.travel.operationFailed'));
      }
    } catch {
      setTravelError(t('settings.travel.operationFailed'));
    } finally {
      setTravelBusy(false);
    }
  };

  return (
    <div>
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.security.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        {t('settings.security.description')}
      </p>
      <div className="border border-gray-200 rounded-lg p-4 space-y-4 dark:border-gray-700">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{t('settings.security.expiresAfter')}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.security.expiresHint')}
            </p>
          </div>
          <select
            data-testid="password-expiry-select"
            aria-label={t('settings.security.expiresAfter')}
            value={expiryDays === null ? '' : String(expiryDays)}
            onChange={(e) => changeExpiry(e.target.value)}
            disabled={saving}
            className="input max-w-[10rem]"
          >
            {SECURITY_EXPIRY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(opt.label)}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.security.changePassword')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.security.changePasswordHint')}
            </p>
          </div>
          <button
            type="button"
            data-testid="change-password-button"
            onClick={() => setChangingPassword(true)}
            className="btn-secondary flex-shrink-0"
          >
            Change…
          </button>
        </div>
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{t('settings.security.biometricUnlock')}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {biometric && !biometric.available
                ? t('settings.security.biometricUnavailable')
                : t('settings.security.biometricHint')}
            </p>
            {biometric?.enabled && (
              <p className="text-xs text-gray-500 dark:text-gray-400" data-testid="biometric-tier">
                {biometric.wrap_tier === 'hardware-bound'
                  ? t('settings.security.biometricHardwareBound')
                  : t('settings.security.biometricOsGate')}
              </p>
            )}
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={biometric?.enabled ?? false}
            aria-label={t('settings.security.biometricUnlock')}
            data-testid="biometric-toggle"
            disabled={saving || enabling || !biometric || !biometric.available}
            onClick={handleBiometricToggle}
            className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              biometric?.enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                biometric?.enabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
        <TravelModeSection
          status={travelStatus}
          busy={travelBusy}
          onEnter={() => {
            setTravelError(null);
            setTravelModalMode('set');
          }}
          onExit={() => {
            setTravelError(null);
            setTravelModalMode('enter');
          }}
        />
      </div>

      {changingPassword && (
        <ChangeMasterPasswordModal
          isOpen
          onDone={() => {
            void handleRotationDone();
          }}
          onCancel={() => setChangingPassword(false)}
        />
      )}

      {/* Use the component directly instead of the useReauth hook: enable needs the password
          itself as the request body, not the "验证通过" result */}
      {showEnableModal && (
        <ReauthModal
          isOpen
          error={enableError}
          isVerifying={enabling}
          onSubmit={handleBiometricEnable}
          onClose={() => setShowEnableModal(false)}
        />
      )}

      {travelModalMode && (
        <TravelPassphraseModal
          isOpen
          mode={travelModalMode}
          description={t(
            travelModalMode === 'set'
              ? 'settings.travel.setDescription'
              : 'settings.travel.enterDescription',
          )}
          error={travelError}
          isBusy={travelBusy}
          onSubmit={submitTravelPassphrase}
          onClose={() => {
            setTravelModalMode(null);
            setTravelError(null);
          }}
        />
      )}

      {travelReauthOpen && (
        <ReauthModal
          isOpen
          error={travelError}
          isVerifying={travelBusy}
          onSubmit={handleTravelReauth}
          onClose={() => {
            setTravelReauthOpen(false);
            setTravelError(null);
          }}
        />
      )}
    </div>
  );
};


export default SecurityPane;
