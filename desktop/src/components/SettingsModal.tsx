import React, { useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import i18n from '@/i18n';
import { usePersonaService } from '@/hooks/usePersonaService';
import { personaAPI } from '@/utils/api';
import { useAppStore } from '@/stores/appStore';
import type {
  BiometricStatus,
  FeatureFlags,
  Identity,
  IdentityType,
  SyncDeviceStatus,
  SyncDeviceView,
  SyncNowReport,
  ThemePreference,
  TravelStatus,
} from '@/types';
import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline';
import ChangeMasterPasswordModal from './ChangeMasterPasswordModal';
import ReauthModal from './ReauthModal';
import TravelPassphraseModal from './TravelPassphraseModal';
import ConnectAutomationSection from './ConnectAutomationSection';
import QuickAccessSection from './QuickAccessSection';
import SyncConflictsModal from './SyncConflictsModal';
import { useEscapeToClose } from '@/hooks/useEscapeToClose';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type SettingsTab = 'general' | 'identities';

const identityTypes: IdentityType[] = ['Personal', 'Work', 'Social', 'Financial', 'Gaming'];

// label 存 i18n key（模块级常量不能调 hook，渲染处 t()）
const THEME_OPTIONS: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'settings.themeSystem' },
  { value: 'light', label: 'settings.themeLight' },
  { value: 'dark', label: 'settings.themeDark' },
];

/** General 面板的高级功能开关行（1Password 式默认关、opt-in 开） */
const FEATURE_ROWS: {
  key: keyof FeatureFlags;
  label: string;
  hint: string;
  /** 开关生效需要重新解锁等额外说明 */
  note?: string;
}[] = [
  { key: 'ssh_agent', label: 'settings.advanced.sshAgentLabel', hint: 'settings.advanced.sshAgentHint' },
  { key: 'wallet', label: 'settings.advanced.walletLabel', hint: 'settings.advanced.walletHint' },
  {
    key: 'passkeys',
    label: 'settings.advanced.passkeysLabel',
    hint: 'settings.advanced.passkeysHint',
    note: 'settings.advanced.passkeysNote',
  },
  {
    key: 'fetch_favicons',
    label: 'settings.advanced.fetchFaviconsLabel',
    hint: 'settings.advanced.fetchFaviconsHint',
    note: 'settings.advanced.fetchFaviconsNote',
  },
];

/** 同步服务器区块：审计事件上报到 persona-server（enabled + url + token）。 */
const SyncServerPane: React.FC = () => {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [tokenPlaceholder, setTokenPlaceholder] = useState('API token');
  const [saving, setSaving] = useState(false);

  // token 真值存 OS keyring（后端 sync.server_token 恒回空串），placeholder
  // 由 sync_token_present 驱动；token 不回填（避免既有令牌常驻前端内存，
  // 空串提交 = 后端保留 keyring 旧 token）
  const refreshTokenPlaceholder = async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncTokenPresent();
      setTokenPlaceholder(
        resp.success && resp.data ? t('settings.sync.tokenSavedPlaceholder') : t('settings.sync.tokenPlaceholder'),
      );
    } catch {
      setTokenPlaceholder(t('settings.sync.tokenPlaceholder'));
    }
  };

  // 初始值来自服务端真相
  useEffect(() => {
    let cancelled = false;
    personaAPI
      .getWorkspaceSettings()
      .then((resp) => {
        if (cancelled || !resp.success || !resp.data?.sync) return;
        setEnabled(resp.data.sync.enabled);
        setUrl(resp.data.sync.server_url);
      })
      .catch(() => {});
    refreshTokenPlaceholder();
    return () => {
      cancelled = true;
    };
  }, []);

  const save = async (nextEnabled: boolean) => {
    if (nextEnabled && !url.trim()) {
      toast.error(t('settings.sync.urlRequired'));
      return;
    }
    setSaving(true);
    try {
      const resp = await personaAPI.setSyncConfig({
        enabled: nextEnabled,
        server_url: url.trim(),
        server_token: token,
      });
      if (resp.success && resp.data) {
        // 回填服务端真相；token 输入框清空（空串提交 = 后端保留 keyring 旧值，
        // 关闭 = 后端清除令牌）。placeholder 重查 keyring 存在性。
        const sync = resp.data.sync;
        if (sync) {
          setEnabled(sync.enabled);
          setUrl(sync.server_url);
        }
        setToken('');
        await refreshTokenPlaceholder();
        toast.success(t('settings.sync.saved'));
      } else {
        toast.error(resp.error || t('settings.sync.saveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.sync.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">{t('settings.sync.title')}</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.sync.description')}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label={t('settings.sync.enable')}
          data-testid="sync-toggle"
          onClick={() => {
            const next = !enabled;
            setEnabled(next);
            if (!next) save(false);
          }}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
            enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
              enabled ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
      </div>

      {enabled && (
        <div className="space-y-3 border border-gray-200 rounded-lg p-4 dark:border-gray-700">
          <div>
            <label className="label mb-1 block" htmlFor="sync-server-url">
              {t('settings.sync.serverUrl')}
            </label>
            <input
              id="sync-server-url"
              className="input"
              data-testid="sync-url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://sync.example.com"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div>
            <label className="label mb-1 block" htmlFor="sync-server-token">
              {t('settings.sync.apiToken')}
            </label>
            <input
              id="sync-server-token"
              className="input"
              data-testid="sync-token-input"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={tokenPlaceholder}
              autoComplete="new-password"
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              data-testid="sync-save"
              onClick={() => save(true)}
              disabled={saving}
              className="btn-primary"
            >
              {saving ? t('settings.saving') : t('common.save')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

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

  // joined 才拉列表（未加入时命令会报「未加入」）
  useEffect(() => {
    if (status?.joined) void refreshDevices();
  }, [status?.joined]);

  const join = async (): Promise<void> => {
    if (!deviceName.trim()) {
      toast.error(t('settings.syncDevices.nameRequired'));
      return;
    }
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
    </div>
  );
};

/** General 面板的密码安全区块：过期策略（NIST 取向默认不过期）+ 手动改密。 */
const SECURITY_EXPIRY_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'settings.security.expiryNever' },
  { value: '90', label: 'settings.security.expiry90' },
  { value: '180', label: 'settings.security.expiry180' },
  { value: '365', label: 'settings.security.expiry365' },
];

/** 旅行模式状态行（SecurityPane 底部）：inactive 显 enter 入口、active 显
 *  exit 入口；inconsistent（旗标在但 sidecar 没了）红警告诚实告知数据已丢 */
const TravelModeSection: React.FC<{
  status: TravelStatus | null;
  busy: boolean;
  onEnter: () => void;
  onExit: () => void;
}> = ({ status, busy, onEnter, onExit }) => {
  const { t } = useTranslation();
  const identities = useAppStore((s) => s.identities);
  const markedCount = identities.filter((i) => i.travel_marked).length;

  return (
    <div className="flex items-start justify-between gap-4" data-testid="travel-section">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
          {t('settings.travel.title')}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {status?.active
            ? t('settings.travel.activeHint', {
                time: status.entered_at ?? '',
              })
            : t('settings.travel.inactiveHint', { count: markedCount })}
        </p>
        {status?.inconsistent && (
          <p
            className="mt-2 text-xs text-red-600 dark:text-red-400"
            data-testid="travel-inconsistent-warning"
          >
            {t('settings.travel.inconsistentWarning')}
          </p>
        )}
      </div>
      {status?.active ? (
        <button
          type="button"
          data-testid="travel-exit-button"
          onClick={onExit}
          disabled={busy}
          className="btn-secondary flex-shrink-0"
        >
          {t('settings.travel.exitButton')}
        </button>
      ) : (
        <button
          type="button"
          data-testid="travel-enter-button"
          onClick={onEnter}
          disabled={busy}
          className="btn-secondary flex-shrink-0"
        >
          {t('settings.travel.enterButton')}
        </button>
      )}
    </div>
  );
};

const SecurityPane: React.FC<{
  changingPassword: boolean;
  setChangingPassword: (open: boolean) => void;
}> = ({ changingPassword, setChangingPassword }) => {
  const { t } = useTranslation();
  const { lockService, loadIdentities } = usePersonaService();
  const [expiryDays, setExpiryDays] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  // biometric：enabled = keyring 有托管条目（活查；不随 settings JSON 走，
  // 双真相源会漂移）。null = 尚未查到（toggle 禁用）。
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [showEnableModal, setShowEnableModal] = useState(false);
  const [enabling, setEnabling] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);

  // 旅行模式：状态免解锁可读；enter/exit 弹口令窗。REAUTH_REQUIRED 时先
  // 验主密码再重开口令窗（不保存明文口令跨弹窗）。
  const [travelStatus, setTravelStatus] = useState<TravelStatus | null>(null);
  const [travelModalMode, setTravelModalMode] = useState<null | 'set' | 'enter'>(null);
  // REAUTH 打断前的原意图（reauth 成功后据此重开口令窗）
  const [travelPendingMode, setTravelPendingMode] = useState<'set' | 'enter'>('set');
  const [travelBusy, setTravelBusy] = useState(false);
  const [travelError, setTravelError] = useState<string | null>(null);
  const [travelReauthOpen, setTravelReauthOpen] = useState(false);

  const refreshTravelStatus = async () => {
    try {
      const resp = await personaAPI.getTravelStatus();
      if (resp.success && resp.data) setTravelStatus(resp.data);
    } catch {
      // 状态读取失败不打断面板，保持上次值
    }
  };

  // 初始值来自服务端真相（旧 JSON 缺键 → null = 不过期）
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

  // 已解锁态改密成功后回锁屏：state.service 里的旧会话密钥已作废，
  // 锁屏重新解锁以新密码建会话（最简安全语义）
  const handleRotationDone = async () => {
    setChangingPassword(false);
    toast.success(t('settings.security.changedRelock'));
    await lockService();
  };

  // 开 = 先验主密码（ReauthModal）→ 后端再弹 OS 认证框；关 = 幂等删
  //（收紧操作不设密码门禁）。enable 的成败在弹窗内闭环，可原地重试。
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

  // ReauthModal 收到的明文密码即请求体；失败留在弹窗内（enableError 驱动
  // 弹窗错误条），不吞掉关闭
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
  // 旅行模式：enter（口令窗 mode='set'）/ exit（mode='enter'）。
  // REAUTH_REQUIRED → 关口令窗、弹 ReauthModal；验证过后按原意图重开
  // 口令窗再输 travel 口令（口令不跨弹窗保留）。成功后刷新状态 + 重载
  // 身份列表。
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

  // reauth 失败也显示在 ReauthModal 的错误条（travelError 此时只喂它）
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

      {/* 直接用组件而非 useReauth hook：enable 需要密码本身作请求体，
          而非"验证通过"这一结果 */}
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

const GeneralPane: React.FC<{
  changingPassword: boolean;
  setChangingPassword: (open: boolean) => void;
}> = ({ changingPassword, setChangingPassword }) => {
  const { t } = useTranslation();
  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);
  const theme = useAppStore((s) => s.theme);
  const setTheme = useAppStore((s) => s.setTheme);

  const [locale, setLocale] = useState(i18n.language.startsWith('en') ? 'en' : 'zh-CN');

  // 语言切换：optimistic 先换渲染语言再持久化；失败回滚（UI + i18n 双回退）
  const changeLocale = async (next: string) => {
    const previous = locale;
    setLocale(next);
    void i18n.changeLanguage(next);
    try {
      const resp = await personaAPI.setLocale(next);
      if (!resp.success) {
        setLocale(previous);
        void i18n.changeLanguage(previous);
        toast.error(resp.error || t('settings.saveFailed'));
      }
    } catch (err) {
      setLocale(previous);
      void i18n.changeLanguage(previous);
      toast.error(err instanceof Error ? err.message : t('settings.saveFailed'));
    }
  };

  // optimistic 写入 → 服务端真相回填；失败回滚并 toast
  const toggle = async (key: keyof FeatureFlags) => {
    const previous = featureFlags;
    const next = { ...previous, [key]: !previous[key] };
    setFeatureFlags(next);

    try {
      const resp = await personaAPI.setFeatureFlags(next);
      if (resp.success && resp.data) {
        setFeatureFlags(resp.data.features);
      } else {
        setFeatureFlags(previous);
        toast.error(resp.error || t('settings.saveFailed'));
      }
    } catch (err) {
      setFeatureFlags(previous);
      toast.error(err instanceof Error ? err.message : t('settings.saveFailed'));
    }
  };

  return (
    <div>
      <section className="mb-5">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{t('settings.theme')}</h3>
        <div
          className="flex bg-gray-100 rounded-lg p-1 dark:bg-gray-800"
          role="radiogroup"
          aria-label={t('settings.theme')}
        >
          {THEME_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              role="radio"
              aria-checked={theme === opt.value}
              data-testid={`theme-option-${opt.value}`}
              onClick={() => setTheme(opt.value)}
              className={`flex-1 px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                theme === opt.value
                  ? 'bg-white text-gray-900 shadow-sm dark:bg-gray-700 dark:text-gray-100'
                  : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              {t(opt.label)}
            </button>
          ))}
        </div>
      </section>

      <section className="mb-5">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">{t('settings.language')}</h3>
        <select
          data-testid="locale-select"
          aria-label={t('settings.language')}
          value={locale}
          onChange={(e) => changeLocale(e.target.value)}
          className="input max-w-[14rem]"
        >
          {/* 语言名用各自语言的固有名书写（i18n 惯例，不随界面语言翻译） */}
          <option value="zh-CN">简体中文</option>
          <option value="en">English</option>
        </select>
      </section>

      <section className="mb-5">
        <QuickAccessSection />
      </section>

      <section className="mb-5">
        <SyncServerPane />
      </section>

      <section className="mb-5">
        <SyncDevicesSection />
      </section>

      <section className="mb-5">
        <SecurityPane
          changingPassword={changingPassword}
          setChangingPassword={setChangingPassword}
        />
      </section>

      <section className="mb-5">
        <ConnectAutomationSection />
      </section>

      <section>
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
          {t('settings.advanced.title')}
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
          {t('settings.advanced.description')}
        </p>
        <div className="border border-gray-200 rounded-lg divide-y divide-gray-100 dark:border-gray-700 dark:divide-gray-800">
          {FEATURE_ROWS.map((row) => (
            <div key={row.key} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{t(row.label)}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">{t(row.hint)}</p>
                {row.note && (
                  <p className="text-xs text-gray-400 dark:text-gray-500">{t(row.note)}</p>
                )}
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={featureFlags[row.key]}
                aria-label={t(row.label)}
                data-testid={`feature-toggle-${row.key}`}
                onClick={() => toggle(row.key)}
                className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
                  featureFlags[row.key] ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                    featureFlags[row.key] ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { t } = useTranslation();
  const { identities, currentIdentity, updateIdentity, deleteIdentity, isLoading, loadIdentities } =
    usePersonaService();

  const [tab, setTab] = useState<SettingsTab>('general');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Identity>>({});
  const [draftTags, setDraftTags] = useState<string>('');
  // travel 标记开关是即时生效（非草稿字段）：请求中锁行防双击
  const [markBusyId, setMarkBusyId] = useState<string | null>(null);
  // 改密弹窗开关提升到本层：SettingsModal 的 Esc 在其叠开时让位上层
  const [changingPassword, setChangingPassword] = useState(false);
  useEscapeToClose(isOpen && !changingPassword, onClose);

  const toggleTravelMark = async (identity: Identity) => {
    setMarkBusyId(identity.id);
    try {
      const resp = await personaAPI.setTravelMarked(identity.id, !identity.travel_marked);
      if (resp.success) {
        await loadIdentities();
      } else {
        toast.error(resp.error || t('settings.travel.markFailed'));
      }
    } catch {
      toast.error(t('settings.travel.markFailed'));
    } finally {
      setMarkBusyId(null);
    }
  };

  const editingIdentity = useMemo(
    () => identities.find((id) => id.id === editingId) ?? null,
    [editingId, identities],
  );

  const startEdit = (identity: Identity) => {
    setEditingId(identity.id);
    setDraft({ ...identity });
    setDraftTags(identity.tags.join(', '));
  };

  const cancelEdit = () => {
    setEditingId(null);
    setDraft({});
    setDraftTags('');
  };

  const saveEdit = async () => {
    if (!editingIdentity) return;
    const name = (draft.name || '').trim();
    if (!name) return;

    const tags = Array.from(
      new Set(
        draftTags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      ),
    );

    const updated: Identity = {
      ...editingIdentity,
      ...draft,
      name,
      identity_type: (draft.identity_type as string) || editingIdentity.identity_type,
      tags,
    };

    const res = await updateIdentity(updated);
    if (res) cancelEdit();
  };

  const handleDelete = async (identity: Identity) => {
    const confirmed = window.confirm(
      t('settings.deleteIdentityConfirm', { name: identity.name }),
    );
    if (!confirmed) return;
    await deleteIdentity(identity.id);
    if (editingId === identity.id) cancelEdit();
  };

  if (!isOpen) return null;

  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'general', label: t('settings.tabGeneral') },
    { id: 'identities', label: t('settings.tabIdentities') },
  ];

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="p-6 pb-0 border-b border-gray-100 dark:border-gray-800">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{t('settings.title')}</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {tab === 'general' ? t('settings.subtitleGeneral') : t('settings.subtitleIdentities')}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
              title={t('settings.close')}
            >
              ✕
            </button>
          </div>

          <div className="flex gap-1 mt-4" role="tablist">
            {tabs.map((tabItem) => (
              <button
                key={tabItem.id}
                role="tab"
                aria-selected={tab === tabItem.id}
                onClick={() => setTab(tabItem.id)}
                className={`px-3 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  tab === tabItem.id
                    ? 'text-primary-700 dark:text-primary-300 border-b-2 border-primary-600'
                    : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                {tabItem.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {tab === 'general' ? (
            <GeneralPane
              changingPassword={changingPassword}
              setChangingPassword={setChangingPassword}
            />
          ) : (
            <div className="space-y-3">
              {identities.length === 0 ? (
                <div className="text-sm text-gray-500 dark:text-gray-400">{t('settings.noIdentitiesYet')}</div>
              ) : (
                identities.map((identity) => {
                  const isEditing = editingId === identity.id;
                  const isCurrent = currentIdentity?.id === identity.id;

                  return (
                    <div
                      key={identity.id}
                      className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-800/50"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          {isEditing ? (
                            <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="label mb-1 block">{t('settings.name')}</label>
                                  <input
                                    className="input"
                                    value={(draft.name as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">{t('settings.type')}</label>
                                  <select
                                    className="input"
                                    value={(draft.identity_type as string) || identity.identity_type}
                                    onChange={(e) =>
                                      setDraft({ ...draft, identity_type: e.target.value })
                                    }
                                  >
                                    {identityTypes.map((t) => (
                                      <option key={t} value={t}>
                                        {t}
                                      </option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <label className="label mb-1 block">{t('settings.email')}</label>
                                  <input
                                    className="input"
                                    value={(draft.email as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, email: e.target.value })}
                                  />
                                </div>
                                <div>
                                  <label className="label mb-1 block">{t('settings.phone')}</label>
                                  <input
                                    className="input"
                                    value={(draft.phone as string) || ''}
                                    onChange={(e) => setDraft({ ...draft, phone: e.target.value })}
                                  />
                                </div>
                              </div>

                              <div>
                                <label className="label mb-1 block">{t('settings.description')}</label>
                                <textarea
                                  className="input h-20 resize-none"
                                  value={(draft.description as string) || ''}
                                  onChange={(e) =>
                                    setDraft({ ...draft, description: e.target.value })
                                  }
                                />
                              </div>

                              <div>
                                <label className="label mb-1 block">{t('settings.tags')}</label>
                                <input
                                  className="input"
                                  value={draftTags}
                                  onChange={(e) => setDraftTags(e.target.value)}
                                  placeholder={t('settings.commaSeparated')}
                                />
                              </div>

                              {/* 旅行模式标记：即时生效（enter 时随之移出本设备）。
                                  enter 之后该身份已从列表移除，故"激活中"的
                                  disabled 天然不可达，无需全局 travel 状态。 */}
                              <div className="flex items-center justify-between gap-3">
                                <div className="min-w-0">
                                  <label className="label mb-1 block">
                                    {t('settings.travel.markLabel')}
                                  </label>
                                  <p className="text-xs text-gray-500 dark:text-gray-400">
                                    {t('settings.travel.markHint')}
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  role="switch"
                                  aria-checked={identity.travel_marked}
                                  aria-label={t('settings.travel.markLabel')}
                                  data-testid={`travel-mark-toggle-${identity.id}`}
                                  disabled={markBusyId === identity.id}
                                  onClick={() => void toggleTravelMark(identity)}
                                  className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                                    identity.travel_marked
                                      ? 'bg-primary-600'
                                      : 'bg-gray-200 dark:bg-gray-700'
                                  }`}
                                >
                                  <span
                                    className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                                      identity.travel_marked ? 'translate-x-6' : 'translate-x-1'
                                    }`}
                                  />
                                </button>
                              </div>

                              <div className="flex gap-2 pt-2">
                                <button
                                  type="button"
                                  onClick={cancelEdit}
                                  className="btn-secondary"
                                >
                                  {t('common.cancel')}
                                </button>
                                <button
                                  type="button"
                                  onClick={saveEdit}
                                  disabled={isLoading || !(draft.name as string)?.trim()}
                                  className="btn-primary"
                                >
                                  {isLoading ? t('settings.saving') : t('common.save')}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <p className="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">
                                  {identity.name}
                                </p>
                                {isCurrent && (
                                  <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-primary-100 text-primary-700 dark:bg-primary-500/20 dark:text-primary-300">
                                    {t('settings.current')}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                {identity.identity_type}
                                {identity.email ? ` • ${identity.email}` : ''}
                                {identity.phone ? ` • ${identity.phone}` : ''}
                              </p>
                              {identity.description && (
                                <p className="text-xs text-gray-600 dark:text-gray-300">
                                  {identity.description}
                                </p>
                              )}
                              {identity.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 pt-1">
                                  {identity.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 rounded-full"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </div>

                        {!isEditing && (
                          <div className="flex items-center gap-1">
                            <button
                              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
                              onClick={() => startEdit(identity)}
                              title={t('common.edit')}
                            >
                              <PencilSquareIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                            </button>
                            <button
                              className="p-2 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg"
                              onClick={() => handleDelete(identity)}
                              title={t('common.delete')}
                            >
                              <TrashIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
