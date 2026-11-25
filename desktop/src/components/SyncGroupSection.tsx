import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { personaAPI } from '@/utils/api';
import DataLossWarning from './DataLossWarning';
import type { SyncJoinBeginOutcome, SyncPairingCreateOutcome } from '@/types';

/** Sync group pairing section (S1 desktop wiring): emit code / enter code / fingerprint comparison / join. */
export default function SyncGroupSection() {
  const { t } = useTranslation();
  const [joined, setJoined] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  /** Host code-emitting session (None = not started) */
  const [pairing, setPairing] = useState<SyncPairingCreateOutcome | null>(null);
  /** Host-side wait result: pairing is done once the fingerprint arrives */
  const [hostFingerprint, setHostFingerprint] = useState<string | null>(null);
  const [hostError, setHostError] = useState<string | null>(null);
  /** Guest side: join_begin result (fingerprint awaiting comparison) */
  const [joining, setJoining] = useState<SyncJoinBeginOutcome | null>(null);
  const [guestLink, setGuestLink] = useState('');
  const [guestError, setGuestError] = useState<string | null>(null);
  // Poll in-flight flag (prevents re-entry; after a cancel the poll returns an error and must not overwrite newer state)
  const pollInFlight = useRef(false);

  const refreshStatus = useCallback(async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncGroupStatus();
      if (resp.success && resp.data !== undefined) setJoined(resp.data);
    } catch {
      // A failed status read keeps the old value (same policy as SyncDevicesSection), so the UI is not interrupted
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  /** Host: suspend and wait right after emitting the code (blocks until completion / 90s; after a cancel this call returns an error) */
  const driveHost = useCallback(async (sessionId: string) => {
    if (pollInFlight.current) return;
    pollInFlight.current = true;
    try {
      const resp = await personaAPI.syncGroupPairingPoll(sessionId);
      // The backend returns an error when the session was cancelled or superseded by a newer one; do not overwrite the current state in that case
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
        // Reset the local state regardless (an expired relay mailbox is backstopped by its TTL)
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
        // Same as cancelPairing: resetting the local state takes priority
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
        // The completion view takes priority over the group status view: right after pairing finishes the user needs
        // to see the fingerprint and the result, so it must not be pushed aside by the join status view
        // (closing returns to the group status view)
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
          {/* S5-b first-enable strong prompt: resident while in place on a single device with no backup
              (not a one-shot dialog); it disappears as soon as a second device or a backup credential arrives */}
          <DataLossWarning variant="strong" />
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
