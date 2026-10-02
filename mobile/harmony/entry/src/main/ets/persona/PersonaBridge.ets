/**
 * persona 桥（鸿蒙侧）：接口语义与 Android JNI / iOS C ABI 层对齐——
 * 出参统一 {"success":bool,"error":string|null} JSON 包络。
 *
 * 接线状态：**napi 包装层待接**。标准路径是 Rust 侧 mobile/rust 增加
 * napi 导出（napi-rs 的 ohos 后端）编出 libpersona_mobile_napi.so，
 * 本文件换为 loadLibrary 后的真实调用；当前 stub 按同签名返回
 * 桥未接入错误，保证 UI 骨架可独立验收（功能优先于测试，不提交半截）。
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
