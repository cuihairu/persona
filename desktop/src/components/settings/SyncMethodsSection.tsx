import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';

/** Sync methods section: two independent toggles (cross-device sync on by default / account sync off by default).
 *
 * Semantic red line (2026-11-23 user directive "the settings page needs the matching options for which sync methods are on"):
 * - Independent of `settings.sync.enabled` (audit event reporting) — **two independent semantics, never merged**.
 * - The toggles only control settings-page entry availability, **never delete the keyring and never trigger
 *   network** — off ≠ leaving the sync group; the group key stays in the keychain.
 * - The derived state (actually joined or not) is a runtime keyring fact, shown read-only; read failures are silent.
 * - No optimistic flip on disable: a successful save is backfilled from server truth; on failure the real state stays.
 */
const SyncMethodsSection: React.FC = () => {
  const { t } = useTranslation();
  // Preferences come from server truth (a missing key in old JSON falls back to the backend serde defaults:
  // cross-device on, account off)
  const [crossDevice, setCrossDevice] = useState<boolean | null>(null);
  const [account, setAccount] = useState<boolean | null>(null);
  // Derived state (read-only, no unlock needed): keyring facts
  const [crossJoined, setCrossJoined] = useState<boolean | null>(null);
  const [accountJoined, setAccountJoined] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const loadPreferences = async (): Promise<void> => {
      try {
        const resp = await personaAPI.getWorkspaceSettings();
        if (cancelled || !resp.success) return;
        const sm = resp.data?.sync_methods;
        setCrossDevice(sm ? sm.cross_device_sync : true);
        setAccount(sm ? sm.account_sync : false);
      } catch {
        // Read failures are silent: toggles stay disabled, the settings page is not disrupted (same policy as SyncDevicesSection)
      }
    };
    const loadCrossJoined = async (): Promise<void> => {
      try {
        // Cross-device derived state = the keyring group key entry (sync_group_status)
        const resp = await personaAPI.syncGroupStatus();
        if (!cancelled && resp.success) setCrossJoined(Boolean(resp.data));
      } catch {
        // Read-only without unlock; failures are silent (the derived state just isn't shown, the preference toggles are unaffected)
      }
    };
    const loadAccountJoined = async (): Promise<void> => {
      try {
        const resp = await personaAPI.syncDeviceStatus();
        if (!cancelled && resp.success) setAccountJoined(Boolean(resp.data?.joined));
      } catch {
        // Same as above
      }
    };
    void loadPreferences();
    void loadCrossJoined();
    void loadAccountJoined();
    return () => {
      cancelled = true;
    };
  }, []);

  /** Narrow preference write; backfill server truth on success, keep the real state on failure (no optimistic flip). */
  const save = async (nextCross: boolean, nextAccount: boolean) => {
    setSaving(true);
    try {
      const resp = await personaAPI.setSyncMethods(nextCross, nextAccount);
      if (resp.success && resp.data) {
        const sm = resp.data.sync_methods;
        setCrossDevice(sm.cross_device_sync);
        setAccount(sm.account_sync);
        toast.success(t('settings.syncMode.saved'));
      } else {
        toast.error(resp.error || t('settings.syncMode.saveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncMode.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const toggleCrossDevice = () => {
    if (crossDevice === null) return;
    const next = !crossDevice;
    // Disabling while still in the group: say it honestly — this only disables the entry, it doesn't leave the sync group or delete the group key.
    if (!next && crossJoined) {
      const ok = window.confirm(
        `${t('settings.syncMode.disableConfirmTitle')}\n\n${t('settings.syncMode.disableConfirmBody')}`,
      );
      if (!ok) return;
    }
    void save(next, account ?? false);
  };

  const toggleAccount = () => {
    if (account === null) return;
    void save(crossDevice ?? true, !account);
  };

  const switchClasses = (on: boolean) =>
    `relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
      on ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
    }`;

  const knobClasses = (on: boolean) =>
    `inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
      on ? 'translate-x-6' : 'translate-x-1'
    }`;

  return (
    <div data-testid="sync-methods-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
        {t('settings.syncMode.title')}
      </h3>
      <div className="border border-gray-200 rounded-lg divide-y divide-gray-100 dark:border-gray-700 dark:divide-gray-800">
        <div className="flex items-center justify-between gap-4 px-4 py-3">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.syncMode.crossDeviceSync')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.syncMode.crossDeviceSyncDesc')}
            </p>
            {crossJoined !== null && (
              <p
                className="text-xs text-gray-400 dark:text-gray-500"
                data-testid="sync-method-cross-device-state"
              >
                {crossJoined ? t('settings.syncMode.joined') : t('settings.syncMode.notEnabled')}
              </p>
            )}
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={crossDevice === true}
            aria-label={t('settings.syncMode.crossDeviceSync')}
            data-testid="sync-method-cross-device-toggle"
            disabled={saving || crossDevice === null}
            onClick={toggleCrossDevice}
            className={switchClasses(crossDevice === true)}
          >
            <span className={knobClasses(crossDevice === true)} />
          </button>
        </div>
        <div className="flex items-center justify-between gap-4 px-4 py-3">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.syncMode.accountSync')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.syncMode.accountSyncDesc')}
            </p>
            {accountJoined !== null && (
              <p
                className="text-xs text-gray-400 dark:text-gray-500"
                data-testid="sync-method-account-state"
              >
                {accountJoined ? t('settings.syncMode.joined') : t('settings.syncMode.notEnabled')}
              </p>
            )}
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={account === true}
            aria-label={t('settings.syncMode.accountSync')}
            data-testid="sync-method-account-toggle"
            disabled={saving || account === null}
            onClick={toggleAccount}
            className={switchClasses(account === true)}
          >
            <span className={knobClasses(account === true)} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default SyncMethodsSection;
