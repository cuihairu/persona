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

/** General 面板的密码安全区块：过期策略（NIST 取向默认不过期）+ 手动改密。 */
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


export default SecurityPane;
