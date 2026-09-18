import { useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '@/stores/appStore';
import type { AutoLockEventPayload } from '@/types';

/** 后端 auto-lock 事件通道名（与 Rust 侧 emit 一致） */
export const AUTO_LOCK_EVENT = 'persona://auto-lock';

/** 用户活动回传节流间隔 */
const ACTIVITY_THROTTLE_MS = 30_000;

/**
 * 订阅后端 auto-lock 事件流：
 * - `lock_pending` → 暴露剩余秒数给顶部倒计时横幅
 * - `locked`       → 清空前端 store、回到解锁屏（后端已在回调中落锁）
 *
 * 同时把用户活动（pointer/keydown，30s 节流）回传 `touch_activity`，
 * 推迟服务端的不活动锁定。仅在解锁状态下挂监听。
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
          // 后端已落锁：前端只负责清理本地状态，回到解锁屏
          // （清理项与手动 lockService 对齐：favicon 缓存、选中、待注入跳转一并作废）
          setPendingSeconds(null);
          setUnlocked(false);
          setIdentities([]);
          setCurrentIdentity(null);
          setCredentials([]);
          clearFaviconCache();
          clearPendingCredentialSelection();
          setSelectedCredentialId(null);
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
  ]);

  useEffect(() => {
    if (!enabled) return;

    const reportActivity = () => {
      const now = Date.now();
      if (now - lastTouchRef.current < ACTIVITY_THROTTLE_MS) return;
      lastTouchRef.current = now;
      invoke('touch_activity').catch(() => {
        // 服务未初始化时忽略；不影响本地使用
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
