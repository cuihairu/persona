import { useCallback, useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import toast from 'react-hot-toast';
import i18n from '@/i18n';
import { personaAPI } from '@/utils/api';
import type { PasskeyApprovalRequest } from '@/types';

/** Backend passkey approval event channel name (matches Rust's TauriApprovalSink) */
export const PASSKEY_APPROVAL_EVENT = 'persona://passkey-approval';

/** Notification title varies by operation type (create vs assert concern different things) */
const notificationTitle = (operation: string): string =>
  operation === 'passkey_create'
    ? i18n.t('notif.passkeyCreateTitle')
    : i18n.t('notif.passkeySignTitle');

/**
 * Subscribes to passkey approval requests forwarded by the bridge (via the desktop Unix socket server):
 * - Requests enter a FIFO queue, one surfaced at a time (the backend awaits each request on its own oneshot)
 * - Allow/Deny is sent back over `passkey_approval_respond`; unanswered requests are
 *   auto-denied by the backend 120s timeout, with a 150s fallback on the bridge side,
 *   so browser requests never hang
 *
 * The listener is only attached while unlocked (callers gate this via enabled; locked sessions get
 * `locked` straight back from the server).
 */
export const usePasskeyApprovals = (enabled: boolean) => {
  const [queue, setQueue] = useState<PasskeyApprovalRequest[]>([]);

  useEffect(() => {
    if (!enabled) {
      setQueue([]);
      return;
    }

    let unlisten: (() => void) | undefined;
    let disposed = false;

    listen<PasskeyApprovalRequest>(PASSKEY_APPROVAL_EVENT, (event) => {
      setQueue((prev) =>
        prev.some((r) => r.request_id === event.payload.request_id)
          ? prev
          : [...prev, event.payload],
      );
      // Alert via a system notification when the window is unfocused (the modal would not be visible)
      if (document.hidden) {
        import('@tauri-apps/plugin-notification')
          .then(({ isPermissionGranted, requestPermission, sendNotification }) =>
            Promise.all([isPermissionGranted(), requestPermission()]).then(
              ([granted, requested]) => {
                if (granted || requested) {
                  sendNotification({
                    title: notificationTitle(event.payload.operation),
                    body: i18n.t('notif.openToApprove', { source: event.payload.origin }),
                  });
                }
              },
            ),
          )
          .catch(() => {
            // Notifications being unavailable does not affect the approval flow
          });
      }
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [enabled]);

  /** Responds to the head-of-queue request (duplicate or unknown ids are treated as deny by the backend).
   *  Queue removal follows server confirmation: when the response fails the request stays queued for retry,
   *  and the failure goes to a toast—a silently lost Allow would leave the browser side hanging
   *  until the backend 120s timeout. */
  const respond = useCallback(async (requestId: string, allow: boolean) => {
    try {
      const response = await personaAPI.passkeyApprovalRespond(requestId, allow);
      if (!response.success) {
        toast.error(response.error || i18n.t('svc.approvalRespondFailed'));
        return;
      }
      setQueue((prev) => prev.filter((r) => r.request_id !== requestId));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : i18n.t('svc.approvalRespondFailed'));
    }
  }, []);

  return {
    /** The request currently awaiting approval (head of queue), or null if none */
    pending: queue[0] ?? null,
    /** Total number of requests the backend is still waiting on */
    pendingCount: queue.length,
    respond,
  };
};
