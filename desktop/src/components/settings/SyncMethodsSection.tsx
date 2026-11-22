import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';

/** 同步方式区块：两个独立开关（跨设备同步默认开 / 账号同步默认关）。
 *
 * 语义红线（2026-11-23 用户令「设置页需要对应的设置选项，同步的方式哪些开启」）：
 * - 与 `settings.sync.enabled`（审计事件上报）是**两套独立语义，绝不合并**。
 * - 开关只控设置页入口可用性，**不删 keyring、不触发网络**——关闭 ≠ 离开
 *   同步组、组密钥仍在钥匙串。
 * - 派生态（实际是否入组）是运行时 keyring 事实，只读展示；读取失败静默。
 * - 关闭不乐观翻转：保存成功由服务端真相回填，失败保持真实状态。
 */
const SyncMethodsSection: React.FC = () => {
  const { t } = useTranslation();
  // 偏好来自服务端真相（旧 JSON 缺键由后端 serde 回退默认：跨设备开、账号关）
  const [crossDevice, setCrossDevice] = useState<boolean | null>(null);
  const [account, setAccount] = useState<boolean | null>(null);
  // 派生态（只读、免解锁）：keyring 事实
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
        // 读取失败静默：开关保持禁用态，不打断设置页（同 SyncDevicesSection 口径）
      }
    };
    const loadCrossJoined = async (): Promise<void> => {
      try {
        // 跨设备派生态 = keyring 组密钥条目（sync_group_status）
        const resp = await personaAPI.syncGroupStatus();
        if (!cancelled && resp.success) setCrossJoined(Boolean(resp.data));
      } catch {
        // 免解锁只读；失败静默（派生态未展示，不影响偏好开关）
      }
    };
    const loadAccountJoined = async (): Promise<void> => {
      try {
        const resp = await personaAPI.syncDeviceStatus();
        if (!cancelled && resp.success) setAccountJoined(Boolean(resp.data?.joined));
      } catch {
        // 同上
      }
    };
    void loadPreferences();
    void loadCrossJoined();
    void loadAccountJoined();
    return () => {
      cancelled = true;
    };
  }, []);

  /** 窄写偏好；成功回填服务端真相，失败保持真实状态（不乐观翻转）。 */
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
    // 关闭但仍在组内：如实告知——只停用入口，不离开同步组、不删组密钥。
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
