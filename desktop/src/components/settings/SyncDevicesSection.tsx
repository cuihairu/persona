import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';
import type { SyncDeviceStatus, SyncDeviceView, SyncNowReport, SyncStatusReport } from '@/types';
import SyncConflictsModal from '../SyncConflictsModal';
import DataScopeConsentModal from '../DataScopeConsentModal';

/** E2EE sync 设备区块：状态行（joined / corrupted 三态）+ 加入/离开 +
 *  设备列表（授权/吊销）。加入后需在另一台已授权设备上完成授权
 *  （pending 提示）——本机 group key 信封由对方密封上传，本机无从自封。 */
const SyncDevicesSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<SyncDeviceStatus | null>(null);
  const [devices, setDevices] = useState<SyncDeviceView[]>([]);
  const [deviceName, setDeviceName] = useState('');
  const [busy, setBusy] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  // 最近一轮同步报告（conflicts > 0 时亮冲突入口）+ 裁决弹窗开关
  const [lastReport, setLastReport] = useState<SyncNowReport | null>(null);
  const [conflictsOpen, setConflictsOpen] = useState(false);
  // 同步水位快照（组版本号/落后 N/待推 N/最近同步时间；只读，查询失败不亮行）
  const [syncStatus, setSyncStatus] = useState<SyncStatusReport | null>(null);
  // 隐私红线：加入 E2EE 同步前先过数据范围披露，确认才执行 sync_join
  const [consentOpen, setConsentOpen] = useState(false);
  // 本机备注行内编辑（S4：备注只允许设备本人写，服务端按令牌归属锁定）
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
      // 列表拉取失败保持旧值（首次 = 空列表），不打断状态行展示
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  // joined 才拉列表与水位快照（未加入时命令会报「未加入」）
  useEffect(() => {
    if (!status?.joined) return;
    void refreshDevices();
    personaAPI
      .syncStatus()
      .then((resp) => {
        if (resp.success && resp.data) setSyncStatus(resp.data);
      })
      .catch(() => {
        // 水位查询失败（服务器不可达/旧版 server 无路由）保持隐藏，不谎报
      });
  }, [status?.joined]);

  const join = async (): Promise<void> => {
    if (!deviceName.trim()) {
      toast.error(t('settings.syncDevices.nameRequired'));
      return;
    }
    setConsentOpen(true);
  };

  /** 披露确认后的实际加入（原 join 主体；与披露解耦以便确认才调后端） */
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

  /** 立即同步：跑一轮周期；conflicts > 0 时自动打开裁决弹窗 */
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
        // 周期跑完水位已变，重取快照（失败静默，保留旧值）
        personaAPI
          .syncStatus()
          .then((r) => {
            if (r.success && r.data) setSyncStatus(r.data);
          })
          .catch(() => {});
        if (resp.data.conflicts > 0) setConflictsOpen(true);
      } else {
        toast.error(resp.error || t('settings.syncDevices.syncFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncDevices.syncFailed'));
    } finally {
      setBusy(false);
    }
  };

  /** group key 轮换（阶段 3d）：换信封 + 全量重包。诚实边界的确认文案
   *  先于任何调用（与 leave/revoke 同 window.confirm 模式）。 */
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
        // 并发轮换被 epoch 乐观锁拦下（另一台设备已抢先）——本地状态
        // 无损（未写信封未重包），提示重试即可
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

  /** 保存本机备注：成功后用服务端规整值（trim）回填行，退出编辑态 */
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
                                className="ml-2 text-blue-600 dark:text-blue-400 hover:underline"
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
