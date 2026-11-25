import { useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '@/stores/appStore';
import type { AutoLockEventPayload } from '@/types';

/** Backend auto-lock event channel name (matches the Rust-side emit) */
export const AUTO_LOCK_EVENT = 'persona://auto-lock';

/** Throttle interval for reporting user activity */
const ACTIVITY_THROTTLE_MS = 30_000;

/**
 * Subscribes to the backend auto-lock event stream:
 * - `lock_pending` -> expose the remaining seconds to the top countdown banner
 * - `locked`       -> clear the frontend store and return to the unlock screen (the backend already locked inside the callback)
 *
 * Also reports user activity (pointer/keydown, 30s throttled) back over `touch_activity`,
 * deferring the server-side inactivity lock. The listener is only attached while unlocked.
 */
export const useAutoLockEvents = (enabled: boolean) => {
  const [pendingSeconds, setPendingSeconds] = useState<number | null>(null);
  const lastTouchRef = useRef(0);

  const setUnlocked = useAppStore((s) => s.setUnlocked);
  const setIdentities = useAppStore((s) => s.setIdentities);
  const setCurrentIdentity = useAppStore((s) => s.setCurrentIdentity);
  const setCredentials = useAppStore((s) => s.setCredentials);
  const clearFaviconCache = useAppStore((s) => s.clearFaviconCache);
  const clearPendingCredentialSelection = useAppStore((s) => s.clearPendingCredentialSelection);
  const setSelectedCredentialId = useAppStore((s) => s.setSelectedCredentialId);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  const setCredentialSearchQuery = useAppStore((s) => s.setCredentialSearchQuery);

  useEffect(() => {
    if (!enabled) {
      setPendingSeconds(null);
      return;
    }

    let unlisten: (() => void) | undefined;
    let disposed = false;

    listen<AutoLockEventPayload>(AUTO_LOCK_EVENT, (event) => {
      const payload = event.payload;
      switch (payload.type) {
        case 'lock_pending':
          setPendingSeconds(payload.seconds_remaining);
          break;
        case 'locked':
          // The backend has already locked: the frontend only cleans up local state and returns to the unlock screen
          // (the cleanup items mirror manual lockService: favicon cache, selection, and pending injections all get invalidated)
          setPendingSeconds(null);
          setUnlocked(false);
          setIdentities([]);
          setCurrentIdentity(null);
          setCredentials([]);
          clearFaviconCache();
          clearPendingCredentialSelection();
          setSelectedCredentialId(null);
          // The editing dialog is invalidated with the lock too (a decrypted payload must not survive across locks)
          setEditingCredential(null);
          // Sidebar category selection is also reset with the lock (mirroring manual lockService)
          resetSidebarFilter();
          setCredentialSearchQuery('');
          break;
        case 'unlocked':
          setPendingSeconds(null);
          break;
        case 'activity':
          break;
      }
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [
    enabled,
    setUnlocked,
    setIdentities,
    setCurrentIdentity,
    setCredentials,
    clearFaviconCache,
    clearPendingCredentialSelection,
    setSelectedCredentialId,
    setEditingCredential,
    resetSidebarFilter,
    setCredentialSearchQuery,
  ]);

  useEffect(() => {
    if (!enabled) return;

    const reportActivity = () => {
      const now = Date.now();
      if (now - lastTouchRef.current < ACTIVITY_THROTTLE_MS) return;
      lastTouchRef.current = now;
      invoke('touch_activity').catch(() => {
        // Ignore when the service is not initialized; local use is unaffected
      });
    };

    window.addEventListener('pointerdown', reportActivity);
    window.addEventListener('keydown', reportActivity);
    return () => {
      window.removeEventListener('pointerdown', reportActivity);
      window.removeEventListener('keydown', reportActivity);
    };
  }, [enabled]);

  return { pendingSeconds };
};
