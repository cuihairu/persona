import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';
import type { SyncDeviceStatus, SyncDeviceView, SyncNowReport, SyncStatusReport } from '@/types';
import SyncConflictsModal from '../SyncConflictsModal';
import DataScopeConsentModal from '../DataScopeConsentModal';

/** E2EE sync devices section: status row (joined / corrupted, three states) + join/leave +
 *  device list (authorize/revoke). After joining, authorization must be completed on
 *  another authorized device (pending hint) — this device's group key envelope is
 *  sealed and uploaded by the peer; this device cannot seal it itself. */
const SyncDevicesSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<SyncDeviceStatus | null>(null);
  const [devices, setDevices] = useState<SyncDeviceView[]>([]);
  const [deviceName, setDeviceName] = useState('');
  const [busy, setBusy] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  // Latest sync report (lights up the conflicts entry when conflicts > 0) + arbitration modal toggle
  const [lastReport, setLastReport] = useState<SyncNowReport | null>(null);
  const [conflictsOpen, setConflictsOpen] = useState(false);
  // Sync watermark snapshot (group version / N behind / N pending push / last sync time;
  // read-only, the row stays hidden if the query fails)
  const [syncStatus, setSyncStatus] = useState<SyncStatusReport | null>(null);
  // Privacy red line: join E2EE sync only after the data-scope disclosure is confirmed; only then run sync_join
  const [consentOpen, setConsentOpen] = useState(false);
  // Inline editing of this device's remark (S4: only the device itself may write its remark;
  // the server locks this by token ownership)
  const [editingRemark, setEditingRemark] = useState(false);
  const [remarkDraft, setRemarkDraft] = useState('');

  const refreshStatus = async (): Promise<SyncDeviceStatus | null> => {
    try {
      const resp = await personaAPI.syncDeviceStatus();
      if (resp.success && resp.data) {
        setStatus(resp.data);
        setLoadFailed(false);
        return resp.data;
      }
      setLoadFailed(true);
    } catch {
      setLoadFailed(true);
    }
    return null;
  };

  const refreshDevices = async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncListDevices();
      if (resp.success && resp.data) {
        setDevices(resp.data);
        setLoadFailed(false);
      }
    } catch {
      // On list fetch failure keep the old value (empty list on first load); don't disrupt the status row
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  // Only fetch the list and watermark snapshot when joined (the command reports "not joined" otherwise)
  useEffect(() => {
    if (!status?.joined) return;
    void refreshDevices();
    personaAPI
      .syncStatus()
      .then((resp) => {
        if (resp.success && resp.data) setSyncStatus(resp.data);
      })
      .catch(() => {
        // Watermark query failure (server unreachable / old server without the route) keeps the row hidden, no false reporting
      });
  }, [status?.joined]);

  const join = async (): Promise<void> => {
    if (!deviceName.trim()) {
      toast.error(t('settings.syncDevices.nameRequired'));
      return;
    }
    setConsentOpen(true);
  };

  /** The actual join after disclosure confirmation (the former join body; decoupled from disclosure so the backend is called only on confirm) */
  const confirmJoin = async (): Promise<void> => {
    setConsentOpen(false);
    setBusy(true);
    try {
      const resp = await personaAPI.syncJoin(deviceName.trim());
      if (resp.success && resp.data) {
        setDeviceName('');
        toast.success(
          resp.data.pending
            ? t('settings.syncDevices.joinPending')
            : t('settings.syncDevices.joinDone'),
        );
        await refreshStatus();
        await refreshDevices();
      } else {
        toast.error(resp.error || t('settings.syncDevices.joinFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.joinFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** Sync now: run one cycle; open the arbitration modal automatically when conflicts > 0 */
  const syncNow = async (): Promise<void> => {
    setBusy(true);
    try {
      const resp = await personaAPI.syncNow();
      if (resp.success && resp.data) {
        setLastReport(resp.data);
        toast.success(
          t('settings.syncDevices.syncDone', {
            pulled: resp.data.pulled,
            pushed: resp.data.pushed,
          }),
        );
        // The cycle moved the watermark; re-fetch the snapshot (fail silently, keep the old value)
        personaAPI
          .syncStatus()
          .then((r) => {
            if (r.success && r.data) setSyncStatus(r.data);
          })
          .catch(() => {});
        if (resp.data.conflicts > 0) setConflictsOpen(true);
      } else if (resp.error_code === 'SYNC_SERVER_UNREACHABLE') {
        // CLOUD_DRIVE_SYNC §9.4: server side unreachable
        toast.error(t('settings.syncDevices.serverUnreachable'));
      } else if (resp.error_code === 'SYNC_CLOUD_FOLDER_UNAVAILABLE') {
        // CLOUD_DRIVE_SYNC §9.4: cloud drive folder unavailable (remedied differently from an unreachable server)
        toast.error(t('settings.syncDevices.cloudFolderUnavailable'));
      } else {
        toast.error(resp.error || t('settings.syncDevices.syncFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.syncFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** group key rotation (phase 3d): new envelopes + full rewrap. The honest-boundary
   *  confirmation prompt comes before any call (same window.confirm pattern as leave/revoke). */
  const rotate = async (): Promise<void> => {
    if (!window.confirm(t('settings.syncDevices.rotateConfirm'))) return;
    setBusy(true);
    try {
      const resp = await personaAPI.syncRotate();
      if (resp.success && resp.data) {
        toast.success(
          t('settings.syncDevices.rotateDone', {
            rewrapped: resp.data.rewrapped,
            skipped: resp.data.skipped,
            pushed: resp.data.pushed,
          }),
        );
        await refreshDevices();
      } else if (resp.error_code === 'CONCURRENT_CONFLICT') {
        // Concurrent rotation stopped by the epoch optimistic lock (another device got there
        // first) — local state is intact (no envelopes written, no rewrap), just prompt a retry
        toast.error(t('settings.syncDevices.rotateConcurrentConflict'));
      } else {
        toast.error(resp.error || t('settings.syncDevices.rotateFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.rotateFailed'));
    } finally {
      setBusy(false);
    }
  };

  const leave = async (): Promise<void> => {    if (!window.confirm(t('settings.syncDevices.leaveConfirm'))) return;
    setBusy(true);
    try {
      const resp = await personaAPI.syncLeave();
      if (resp.success) {
        setStatus({ joined: false, corrupted: false, device_id: null, device_name: null });
        setDevices([]);
        toast.success(t('settings.syncDevices.left'));
      } else {
        toast.error(resp.error || t('settings.syncDevices.leaveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.leaveFailed'));
    } finally {
      setBusy(false);
    }
  };

  const authorize = async (device: SyncDeviceView): Promise<void> => {
    setBusy(true);
    try {
      const resp = await personaAPI.syncAuthorize(device.id);
      if (resp.success) {
        toast.success(t('settings.syncDevices.authorized', { name: device.device_name }));
        await refreshDevices();
      } else {
        toast.error(resp.error || t('settings.syncDevices.authorizeFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.authorizeFailed'));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (device: SyncDeviceView): Promise<void> => {
    if (!window.confirm(t('settings.syncDevices.revokeConfirm', { name: device.device_name })))
      return;
    setBusy(true);
    try {
      const resp = await personaAPI.syncRevoke(device.id);
      if (resp.success) {
        toast.success(t('settings.syncDevices.revoked'));
        await refreshDevices();
      } else {
        toast.error(resp.error || t('settings.syncDevices.revokeFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.revokeFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** Save this device's remark: backfill the row with the server-normalized value (trimmed) on success and leave edit mode */
  const saveRemark = async (): Promise<void> => {
    setBusy(true);
    try {
      const resp = await personaAPI.syncSetDeviceRemark(remarkDraft);
      if (resp.success && resp.data !== undefined) {
        const stored = resp.data;
        setDevices((prev) => prev.map((d) => (d.this_device ? { ...d, remark: stored } : d)));
        setEditingRemark(false);
        toast.success(t('settings.syncDevices.remarkSaved'));
      } else {
        toast.error(resp.error || t('settings.syncDevices.remarkFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.remarkFailed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="sync-devices-section">
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.syncDevices.title')}
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.syncDevices.description')}
          </p>
        </div>
      </div>

      {loadFailed && (
        <p className="mt-2 text-xs text-red-600 dark:text-red-400" data-testid="sync-devices-error">
          {t('settings.syncDevices.loadFailed')}
        </p>
      )}

      {status?.corrupted && (
        <p
          className="mt-2 text-xs text-red-600 dark:text-red-400"
          data-testid="sync-devices-corrupted"
        >
          {t('settings.syncDevices.corrupted')}
        </p>
      )}

      {status?.joined ? (
        <div className="mt-3 space-y-3" data-testid="sync-devices-joined">
          <div className="flex items-center justify-between gap-4 text-sm">
            <span className="text-gray-700 dark:text-gray-300">
              {t('settings.syncDevices.joinedAs', { name: status.device_name ?? '' })}
            </span>
            <div className="flex flex-shrink-0 gap-2">
              <button
                type="button"
                data-testid="sync-now-button"
                onClick={syncNow}
                disabled={busy}
                className="btn-primary"
              >
                {busy ? t('settings.saving') : t('settings.syncDevices.syncNow')}
              </button>
              <button
                type="button"
                data-testid="sync-rotate-button"
                onClick={rotate}
                disabled={busy}
                className="btn-secondary"
              >
                {t('settings.syncDevices.rotate')}
              </button>
              <button
                type="button"
                data-testid="sync-leave-button"
                onClick={leave}
                disabled={busy}
                className="btn-secondary"
              >
                {t('settings.syncDevices.leave')}
              </button>
            </div>
          </div>

          {syncStatus && (
            <div
              className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-gray-400 px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg"
              data-testid="sync-status-row"
            >
              <span data-testid="sync-status-head">
                {t('settings.syncDevices.statusHead', { head: syncStatus.headSeq })}
              </span>
              {syncStatus.behind > 0 ? (
                <span
                  className="text-amber-600 dark:text-amber-400"
                  data-testid="sync-status-behind"
                >
                  {t('settings.syncDevices.statusBehind', { count: syncStatus.behind })}
                </span>
              ) : syncStatus.pendingPush > 0 ? (
                <span
                  className="text-amber-600 dark:text-amber-400"
                  data-testid="sync-status-pending"
                >
                  {t('settings.syncDevices.statusPending', { count: syncStatus.pendingPush })}
                </span>
              ) : (
                <span className="text-green-600 dark:text-green-400" data-testid="sync-status-uptodate">
                  {t('settings.syncDevices.statusUpToDate')}
                </span>
              )}
              <span data-testid="sync-status-last-sync">
                {syncStatus.lastSyncAt
                  ? t('settings.syncDevices.statusLastSync', {
                      time: new Date(syncStatus.lastSyncAt).toLocaleString(),
                    })
                  : t('settings.syncDevices.statusNever')}
              </span>
            </div>
          )}

          {lastReport && lastReport.conflicts > 0 && (
            <div
              className="flex items-center justify-between gap-4 border border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 rounded-lg px-3 py-2 text-sm"
              data-testid="sync-conflicts-banner"
            >
              <span className="text-amber-700 dark:text-amber-400">
                {t('settings.syncDevices.conflictsFound', { count: lastReport.conflicts })}
              </span>
              <button
                type="button"
                data-testid="sync-view-conflicts-button"
                onClick={() => setConflictsOpen(true)}
                disabled={busy}
                className="btn-secondary text-xs"
              >
                {t('settings.syncDevices.viewConflicts')}
              </button>
            </div>
          )}

          {devices.length > 0 && (
            <ul className="divide-y divide-gray-200 dark:divide-gray-700 border border-gray-200 rounded-lg dark:border-gray-700">
              {devices.map((device) => (
                <li
                  key={device.id}
                  className="flex items-center justify-between gap-4 px-3 py-2"
                  data-testid={`sync-device-row-${device.id}`}
                >
                  <div className="min-w-0">
                    {editingRemark && device.this_device ? (
                      <div className="flex items-center gap-2">
                        <input
                          className="input py-1 text-sm"
                          data-testid="sync-remark-input"
                          value={remarkDraft}
                          onChange={(e) => setRemarkDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') void saveRemark();
                            if (e.key === 'Escape') setEditingRemark(false);
                          }}
                          placeholder={t('settings.syncDevices.remarkPlaceholder')}
                        />
                        <button
                          type="button"
                          data-testid="sync-remark-save"
                          onClick={() => void saveRemark()}
                          disabled={busy}
                          className="btn-primary text-xs"
                        >
                          {t('settings.syncDevices.remarkSave')}
                        </button>
                        <button
                          type="button"
                          data-testid="sync-remark-cancel"
                          onClick={() => setEditingRemark(false)}
                          disabled={busy}
                          className="btn-secondary text-xs"
                        >
                          {t('settings.syncDevices.remarkCancel')}
                        </button>
                      </div>
                    ) : (
                      <>
                        <p className="text-sm text-gray-900 dark:text-gray-100 truncate">
                          {device.device_name}
                          {device.this_device && (
                            <span
                              className="ml-2 text-xs text-blue-600 dark:text-blue-400"
                              data-testid="sync-device-this-badge"
                            >
                              {t('settings.syncDevices.thisDevice')}
                            </span>
                          )}
                          {!device.authorized && (
                            <span
                              className="ml-2 text-xs text-amber-600 dark:text-amber-400"
                              data-testid="sync-device-pending-badge"
                            >
                              {t('settings.syncDevices.pendingBadge')}
                            </span>
                          )}
                        </p>
                        {(device.remark || device.this_device) && (
                          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                            {device.remark || t('settings.syncDevices.remarkEmpty')}
                            {device.this_device && (
                              <button
                                type="button"
                                data-testid="sync-remark-edit"
                                onClick={() => {
                                  setRemarkDraft(device.remark);
                                  setEditingRemark(true);
                                }}
                                disabled={busy}
                                className="whitespace-nowrap ml-2 text-blue-600 dark:text-blue-400 hover:underline"
                              >
                                {t('settings.syncDevices.remarkEdit')}
                              </button>
                            )}
                          </p>
                        )}
                      </>
                    )}
                  </div>
                  <div className="flex-shrink-0 flex gap-2">
                    {!device.authorized && !device.this_device && (
                      <button
                        type="button"
                        data-testid={`sync-authorize-${device.id}`}
                        onClick={() => authorize(device)}
                        disabled={busy}
                        className="btn-secondary text-xs"
                      >
                        {t('settings.syncDevices.authorize')}
                      </button>
                    )}
                    {!device.this_device && (
                      <button
                        type="button"
                        data-testid={`sync-revoke-${device.id}`}
                        onClick={() => revoke(device)}
                        disabled={busy}
                        className="btn-secondary text-xs text-red-600 dark:text-red-400"
                      >
                        {t('settings.syncDevices.revoke')}
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-3 border border-gray-200 rounded-lg p-4 dark:border-gray-700">
          <label className="label mb-1 block" htmlFor="sync-device-name">
            {t('settings.syncDevices.deviceNameLabel')}
          </label>
          <input
            id="sync-device-name"
            className="input"
            data-testid="sync-device-name-input"
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
            placeholder={t('settings.syncDevices.deviceNamePlaceholder')}
          />
          <div className="flex justify-end">
            <button
              type="button"
              data-testid="sync-join-button"
              onClick={join}
              disabled={busy}
              className="btn-primary"
            >
              {busy ? t('settings.saving') : t('settings.syncDevices.join')}
            </button>
          </div>
        </div>
      )}

      {conflictsOpen && (
        <SyncConflictsModal onClose={() => setConflictsOpen(false)} />
      )}

      {consentOpen && (
        <DataScopeConsentModal
          scope="e2ee"
          onConfirm={confirmJoin}
          onCancel={() => setConsentOpen(false)}
        />
      )}
    </div>
  );
};


export default SyncDevicesSection;
