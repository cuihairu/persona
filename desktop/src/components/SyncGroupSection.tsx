import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { personaAPI } from '@/utils/api';
import type { SyncJoinBeginOutcome, SyncPairingCreateOutcome } from '@/types';

/** 同步组配对节（S1 桌面接线）：出码 / 输码 / 指纹比对 / 入组。 */
export default function SyncGroupSection() {
  const { t } = useTranslation();
  const [joined, setJoined] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  /** host 出码会话（None = 未发起） */
  const [pairing, setPairing] = useState<SyncPairingCreateOutcome | null>(null);
  /** host 侧等待结果：指纹到位即配对完成 */
  const [hostFingerprint, setHostFingerprint] = useState<string | null>(null);
  const [hostError, setHostError] = useState<string | null>(null);
  /** guest 侧：join_begin 结果（指纹待比对） */
  const [joining, setJoining] = useState<SyncJoinBeginOutcome | null>(null);
  const [guestLink, setGuestLink] = useState('');
  const [guestError, setGuestError] = useState<string | null>(null);
  // poll 在途标记（防重入；取消后 poll 以错误返回，不覆盖新状态）
  const pollInFlight = useRef(false);

  const refreshStatus = useCallback(async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncGroupStatus();
      if (resp.success && resp.data !== undefined) setJoined(resp.data);
    } catch {
      // 状态读取失败保持旧值（同 SyncDevicesSection 口径），不打断 UI
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  /** host：出码后立即挂起等待（阻塞至完成/90s；cancel 后本调用报错返回） */
  const driveHost = useCallback(async (sessionId: string) => {
    if (pollInFlight.current) return;
    pollInFlight.current = true;
    try {
      const resp = await personaAPI.syncGroupPairingPoll(sessionId);
      // 会话被取消/被新会话替换时后端返回错误；此时不覆盖当前状态
      if (resp.success && resp.data?.completed) {
        setHostFingerprint(resp.data.fingerprint);
        setHostError(null);
        await refreshStatus();
      } else if (resp.success) {
        setHostError(t('settings.syncGroup.waitAgain'));
      } else {
        setHostError(resp.error ?? t('settings.syncGroup.pairFailed'));
      }
    } catch (err) {
      setHostError(err instanceof Error ? err.message : t('settings.syncGroup.pairFailed'));
    } finally {
      pollInFlight.current = false;
    }
  }, [refreshStatus, t]);

  const startHost = async (): Promise<void> => {
    setBusy(true);
    setHostError(null);
    setHostFingerprint(null);
    try {
      const resp = await personaAPI.syncGroupPairingCreate();
      if (resp.success && resp.data) {
        setPairing(resp.data);
        void driveHost(resp.data.session_id);
      } else {
        toast.error(resp.error || t('settings.syncGroup.createFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncGroup.createFailed'));
    } finally {
      setBusy(false);
    }
  };

  const cancelPairing = async (): Promise<void> => {
    if (pairing) {
      try {
        await personaAPI.syncGroupPairingCancel(pairing.session_id);
      } catch {
        // 本地状态无论如何复位（中转信箱过期由 TTL 兜底）
      }
    }
    setPairing(null);
    setHostFingerprint(null);
    setHostError(null);
  };

  const startGuest = async (): Promise<void> => {
    if (!guestLink.trim()) {
      toast.error(t('settings.syncGroup.linkRequired'));
      return;
    }
    setBusy(true);
    setGuestError(null);
    try {
      const resp = await personaAPI.syncGroupJoinBegin(guestLink.trim());
      if (resp.success && resp.data) {
        setJoining(resp.data);
      } else {
        setGuestError(resp.error || t('settings.syncGroup.beginFailed'));
      }
    } catch (err) {
      setGuestError(err instanceof Error ? err.message : t('settings.syncGroup.beginFailed'));
    } finally {
      setBusy(false);
    }
  };

  const confirmJoin = async (): Promise<void> => {
    if (!joining) return;
    setBusy(true);
    try {
      const resp = await personaAPI.syncGroupJoinConfirm(joining.session_id);
      if (resp.success) {
        toast.success(t('settings.syncGroup.joinedDone'));
        setJoining(null);
        setGuestLink('');
        await refreshStatus();
      } else {
        setGuestError(resp.error || t('settings.syncGroup.confirmFailed'));
      }
    } catch (err) {
      setGuestError(err instanceof Error ? err.message : t('settings.syncGroup.confirmFailed'));
    } finally {
      setBusy(false);
    }
  };

  const cancelJoin = async (): Promise<void> => {
    if (joining) {
      try {
        await personaAPI.syncGroupJoinCancel(joining.session_id);
      } catch {
        // 同 cancelPairing：本地状态复位优先
      }
    }
    setJoining(null);
    setGuestError(null);
  };

  const copyLink = async (): Promise<void> => {
    if (!pairing) return;
    try {
      await navigator.clipboard.writeText(pairing.invite_link);
      toast.success(t('settings.syncGroup.linkCopied'));
    } catch {
      toast.error(t('settings.syncGroup.copyFailed'));
    }
  };

  return (
    <div data-testid="sync-group-section">
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.syncGroup.title')}
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.syncGroup.description')}
          </p>
        </div>
      </div>

      {hostFingerprint ? (
        // 完成面优先于组状态面：配对刚结束时用户要看到指纹与结果，
        // 不能被入组状态面直接顶掉（关闭后回组状态面）
        <div
          className="border border-green-200 rounded-lg p-4 dark:border-green-800"
          data-testid="sync-group-host-done"
        >
          <p className="text-sm font-medium text-green-800 dark:text-green-300">
            {t('settings.syncGroup.pairedDone')}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {t('settings.syncGroup.fingerprintHint')}
          </p>
          <p
            className="mt-2 text-2xl font-mono tracking-widest text-gray-900 dark:text-gray-100"
            data-testid="sync-group-host-fingerprint"
          >
            {hostFingerprint}
          </p>
          <button
            type="button"
            className="btn btn-secondary mt-3"
            onClick={() => void cancelPairing()}
          >
            {t('settings.syncGroup.close')}
          </button>
        </div>
      ) : joined === true ? (
        <div className="mt-3 border border-green-200 rounded-lg p-4 dark:border-green-800" data-testid="sync-group-joined">
          <p className="text-sm font-medium text-green-800 dark:text-green-300">
            {t('settings.syncGroup.joinedTitle')}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {t('settings.syncGroup.joinedHint')}
          </p>
        </div>
      ) : (
        <div className="mt-3 space-y-3">
          {pairing ? (
            <div
              className="border border-gray-200 rounded-lg p-4 space-y-3 dark:border-gray-700"
              data-testid="sync-group-host-waiting"
            >
              <div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t('settings.syncGroup.codeLabel')}
                </p>
                <p
                  className="text-xl font-mono tracking-widest text-gray-900 dark:text-gray-100"
                  data-testid="sync-group-host-code"
                >
                  {pairing.code}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t('settings.syncGroup.linkLabel')}
                </p>
                <div className="flex items-start gap-2">
                  <code
                    className="flex-1 break-all text-xs text-gray-700 dark:text-gray-300 bg-gray-50 rounded p-2 dark:bg-gray-800"
                    data-testid="sync-group-host-link"
                  >
                    {pairing.invite_link}
                  </code>
                  <button
                    type="button"
                    className="btn btn-secondary flex-shrink-0"
                    onClick={() => void copyLink()}
                  >
                    {t('settings.syncGroup.copyLink')}
                  </button>
                </div>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400" data-testid="sync-group-host-wait">
                {t('settings.syncGroup.waiting')}
              </p>
              {hostError && (
                <p className="text-xs text-red-600 dark:text-red-400" data-testid="sync-group-host-error">
                  {hostError}
                </p>
              )}
              <div className="flex gap-2">
                {hostError && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => void driveHost(pairing.session_id)}
                  >
                    {t('settings.syncGroup.retryWait')}
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => void cancelPairing()}
                >
                  {t('settings.syncGroup.cancelPairing')}
                </button>
              </div>
            </div>
          ) : (
            <div
              className="border border-gray-200 rounded-lg p-4 dark:border-gray-700"
              data-testid="sync-group-idle"
            >
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() => void startHost()}
              >
                {t('settings.syncGroup.hostAction')}
              </button>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                {t('settings.syncGroup.hostHint')}
              </p>
            </div>
          )}

          {!joining && (
            <div className="border border-gray-200 rounded-lg p-4 dark:border-gray-700" data-testid="sync-group-guest">
              <label
                htmlFor="sync-group-invite"
                className="text-xs text-gray-500 dark:text-gray-400"
              >
                {t('settings.syncGroup.guestAction')}
              </label>
              <textarea
                id="sync-group-invite"
                data-testid="sync-group-guest-input"
                className="input mt-1 w-full font-mono text-xs"
                rows={3}
                value={guestLink}
                placeholder={t('settings.syncGroup.guestPlaceholder')}
                onChange={(e) => setGuestLink(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-primary mt-2"
                disabled={busy}
                onClick={() => void startGuest()}
              >
                {t('settings.syncGroup.guestStart')}
              </button>
              {guestError && (
                <p className="text-xs text-red-600 dark:text-red-400 mt-2" data-testid="sync-group-guest-error">
                  {guestError}
                </p>
              )}
            </div>
          )}

          {joining && (
            <div
              className="border border-gray-200 rounded-lg p-4 space-y-2 dark:border-gray-700"
              data-testid="sync-group-guest-confirm"
            >
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {t('settings.syncGroup.guestCode', { code: joining.code })}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {t('settings.syncGroup.fingerprintHint')}
              </p>
              <p
                className="text-2xl font-mono tracking-widest text-gray-900 dark:text-gray-100"
                data-testid="sync-group-guest-fingerprint"
              >
                {joining.fingerprint}
              </p>
              {guestError && (
                <p className="text-xs text-red-600 dark:text-red-400" data-testid="sync-group-guest-confirm-error">
                  {guestError}
                </p>
              )}
              <div className="flex gap-2">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy}
                  onClick={() => void confirmJoin()}
                >
                  {t('settings.syncGroup.confirmJoin')}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => void cancelJoin()}
                >
                  {t('settings.syncGroup.mismatchCancel')}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
