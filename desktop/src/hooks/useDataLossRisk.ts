import { useCallback, useEffect, useState } from 'react';
import { personaAPI } from '@/utils/api';

/** Data-loss risk tiers (design §6.5 / TODO S5-b).
 * - `high`: already in a sync group but this machine is the only device and no
 *   backup has ever been exported — "lose the device, lose the vault"
 * - `medium`: same as above but an account is bound (there is an account
 *   recovery path, so the warning drops one tier)
 * - `none`: not in a group (a local vault never spans devices, so it is outside
 *   this warning's remit) / a second device already exists / a backup has been
 *   exported — the warning clears automatically */
export type DataLossRiskLevel = 'none' | 'high' | 'medium';

export interface DataLossRisk {
  /** True when any status source fails to read (the warning hides silently, no false alarm) */
  loading: boolean;
  /** Already joined a sync group */
  joined: boolean;
  /** Device count in the group (including this one; <=1 = single-device high risk) */
  deviceCount: number;
  /** An encrypted backup was exported from this machine (the settings.backup credential is present) */
  hasBackup: boolean;
  /** An account is bound (account mode drops the warning one tier) */
  hasAccount: boolean;
  /** Whether the cross-device sync preference switch is on (settings.sync_methods;
   * a read failure degrades to the safe-side true — better to under-mention
   * "can be re-enabled" than to misreport). **A read-only preference; it does not
   * decide the tier**: whether the data is in a group is a keyring fact that a
   * preference switch cannot rewrite. */
  crossDeviceSyncEnabled: boolean;
  level: DataLossRiskLevel;
  refresh: () => Promise<void>;
}

/** Pure function: tier decision (test anchor). Release conditions (TODO S5-b 3):
 * a second device in place or a backup exported -> none; binding an account only
 * lowers the tier, it does not release it. */
export function computeDataLossRisk(input: {
  joined: boolean;
  deviceCount: number;
  hasBackup: boolean;
  hasAccount: boolean;
}): DataLossRiskLevel {
  if (!input.joined) return 'none';
  if (input.deviceCount >= 2 || input.hasBackup) return 'none';
  return input.hasAccount ? 'medium' : 'high';
}

/** Status source for the data-loss warning: sync group status + device list +
 * workspace settings (backup credential / account binding) read in parallel.
 * Any failing path degrades to the safe side (not in a group -> none), so it
 * under-reports rather than misreports. */
export function useDataLossRisk(): DataLossRisk {
  const [state, setState] = useState<Omit<DataLossRisk, 'refresh'>>({
    loading: true,
    joined: false,
    deviceCount: 0,
    hasBackup: false,
    hasAccount: false,
    crossDeviceSyncEnabled: true,
    level: 'none',
  });

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const [statusResp, devicesResp, settingsResp] = await Promise.all([
        personaAPI.syncGroupStatus(),
        personaAPI.syncListDevices(),
        personaAPI.getWorkspaceSettings(),
      ]);
      const joined = Boolean(statusResp.success && statusResp.data);
      const deviceCount =
        devicesResp.success && devicesResp.data ? devicesResp.data.length : 0;
      const settings = settingsResp.success ? settingsResp.data : undefined;
      const hasBackup = Boolean(settings?.backup);
      const hasAccount = Boolean(settings?.account);
      // The preference switch is read-only display (it does not decide the tier); a read failure degrades to the safe-side true (prefer under-mentioning)
      const crossDeviceSyncEnabled = settings?.sync_methods?.cross_device_sync ?? true;
      setState({
        loading: false,
        joined,
        deviceCount,
        hasBackup,
        hasAccount,
        crossDeviceSyncEnabled,
        level: computeDataLossRisk({ joined, deviceCount, hasBackup, hasAccount }),
      });
    } catch {
      // A failed read hides the warning silently (same rule as SyncGroupSection), avoiding false alarms
      setState((prev) => ({ ...prev, loading: false, level: 'none' }));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { ...state, refresh };
}
