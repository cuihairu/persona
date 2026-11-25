/**
 * persona bridge (HarmonyOS side): the interface semantics line up with the
 * Android JNI / iOS C ABI layers — out parameters are uniformly the
 * {"success":bool,"error":string|null} JSON envelope.
 *
 * Wiring status: **the napi wrapper layer is still to be wired**. The standard
 * path is to add napi exports on the Rust side in mobile/rust (the ohos backend
 * of napi-rs) to build libpersona_mobile_napi.so, then swap this file for real
 * calls after loadLibrary; the current stub returns a bridge-not-wired error
 * under the same signatures, so the UI skeleton can be verified independently
 * (features take priority over tests — never commit something half-finished).
 */
export interface BridgeResult {
  success: boolean;
  error: string | null;
}

const NOT_WIRED: BridgeResult = {
  success: false,
  error: '桥未接入：napi 包装层待接（见 PersonaBridge.ets 头注）'
};

export class PersonaBridge {
  static version(): string {
    return 'napi 未接入';
  }

  static serviceInit(_dbPath: string, _masterPassword: string): BridgeResult {
    return NOT_WIRED;
  }

  static serviceUnlock(_masterPassword: string): BridgeResult {
    return NOT_WIRED;
  }

  static serviceLock(): BridgeResult {
    return NOT_WIRED;
  }

  static serviceIsUnlocked(): boolean {
    return false;
  }
}
