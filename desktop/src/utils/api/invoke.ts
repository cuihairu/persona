import { invoke as tauriInvoke } from '@tauri-apps/api/core';

/**
 * Unlock gate for SERVICE_LOCKED: the backend's auto-lock is decided lazily
 * (the timeout is only checked when an operation runs), and no locked event is
 * emitted — the frontend's isUnlocked is still true, so the operation just hits
 * "Session is auto-locked" and dead-ends the user. The gate intercepts that
 * error code at the shared invoke exit: it pops the unlock dialog and suspends
 * the current operation, retries once on a successful unlock, and returns the
 * error as-is when cancelled. Unlock / status-query commands bypass the gate
 * (they would recurse).
 */
const UNLOCK_GATE_BYPASS = new Set([
  'init_service',
  'is_service_unlocked',
  'biometric_status',
  'biometric_unlock',
  'biometric_enable',
  'biometric_disable',
  'lock_service',
  'get_auto_lock_status',
  'check_passkey_support',
]);

let unlockGate: Promise<boolean> | null = null;

/** Requests a guided unlock (idempotent, concurrent calls coalesce): resolves true on a successful unlock, false when the user cancels. */
export function requestUnlockGate(): Promise<boolean> {
  if (!unlockGate) {
    unlockGate = new Promise<boolean>((resolve) => {
      window.dispatchEvent(
        new CustomEvent('persona:need-unlock', { detail: { resolve } }),
      );
    }).finally(() => {
      unlockGate = null;
    });
  }
  return unlockGate;
}

/**
 * Shared invoke exit: Tauri 2 rejects the promise with a plain string rather
 * than an Error instance for command errors (Err(String) at the command layer,
 * IPC-layer failures such as "invalid args ... missing required key"). Callers
 * writing `err instanceof Error ? err.message : generic message` never see the
 * underlying cause and are left with a bare "save failed". This normalizes any
 * rejection into an Error so every call site can surface the real error text.
 */
export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    // An argless call omits the second parameter: keeps the same argument shape as calling tauriInvoke directly
    let res =
      args === undefined ? await tauriInvoke<T>(cmd) : await tauriInvoke<T>(cmd, args);
    const envelope = res as { success?: boolean; error_code?: string } | null;
    if (
      envelope !== null &&
      typeof envelope === 'object' &&
      envelope.success === false &&
      envelope.error_code === 'SERVICE_LOCKED' &&
      !UNLOCK_GATE_BYPASS.has(cmd)
    ) {
      if (await requestUnlockGate()) {
        res =
          args === undefined ? await tauriInvoke<T>(cmd) : await tauriInvoke<T>(cmd, args);
      }
    }
    return res;
  } catch (e) {
    if (e instanceof Error) throw e;
    throw new Error(
      typeof e === 'string' && e.length > 0 ? e : JSON.stringify(e),
      { cause: e },
    );
  }
}
