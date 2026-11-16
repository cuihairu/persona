import { invoke as tauriInvoke } from '@tauri-apps/api/core';

/**
 * SERVICE_LOCKED 引导解锁：后端 auto-lock 是惰性判定（操作时才检查
 * 超时），不发 locked 事件——前端 isUnlocked 仍 true，操作直接撞
 * 「Session is auto-locked」把用户堵死。gate 在统一 invoke 出口拦截
 * 该错误码：弹解锁框挂起当前操作，解锁成功自动重试一次；取消则
 * 原样返回错误。解锁/状态查询类命令本身不走 gate（会递归）。
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

/** 请求一次引导解锁（幂等并发合并）：resolve(true)=解锁成功，false=用户取消。 */
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
 * 统一 invoke 出口：Tauri 2 的命令错误（命令层 Err(String)、
 * "invalid args ... missing required key" 等 IPC 层失败）以字符串
 * reject promise，不是 Error 实例——调用方的
 * `err instanceof Error ? err.message : 通用文案` 会拿不到底层原因，
 * 只剩一句"保存失败"。这里把任何 rejection 归一成 Error，让全部
 * 调用点都能透出真实错误文本。
 */
export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    // 无参调用不传第二个参数：保持与直调 tauriInvoke 相同的实参形态
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
