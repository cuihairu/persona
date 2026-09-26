import { useEffect } from 'react';
import { listen } from '@tauri-apps/api/event';
import { useAppStore } from '@/stores/appStore';
import { personaAPI } from '@/utils/api';
import type { QuickAccessOpenCredential } from '@/types';

/** 浮窗 → 主窗口跳转事件（quick_access.rs OPEN_CREDENTIAL_EVENT） */
const OPEN_CREDENTIAL_EVENT = 'persona://quick-access-open-credential';

/**
 * Quick Access 浮窗的跨窗跳转接收端（只挂主窗口）。
 *
 * 两个窗口各有独立 JS store，浮窗没法直接改主窗口的选中态，只能让 Rust
 * 定向 emit 到主窗口（浮窗那边同时把主窗口拉到前台）。收到后：
 * 写 pendingCredentialSelection（跨身份时顺带 switchIdentity，由
 * CredentialList 消费注入），语义与 QuickSearch 的应用内跳转完全一致。
 *
 * 身份不在本地列表里（另一台机器同步过来的、或已被删）时**只报错不跳**：
 * 静默 switch 到不存在的身份只会把主界面带进空态。
 */
export const useQuickAccessBridge = () => {
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    const apply = async (payload: QuickAccessOpenCredential) => {
      const { identities, setPendingCredentialSelection, setCurrentIdentity } =
        useAppStore.getState();
      const target = identities.find((identity) => identity.id === payload.identity_id);
      if (!target) {
        return;
      }
      setPendingCredentialSelection({
        identityId: target.id,
        credentialId: payload.credential_id,
      });
      const current = useAppStore.getState().currentIdentity;
      if (!current || current.id !== target.id) {
        setCurrentIdentity(target);
        try {
          await personaAPI.setActiveIdentity(target.id);
        } catch {
          // 落库失败不阻断跳转：主界面按内存态继续切
        }
      }
    };

    try {
      const pending = listen<QuickAccessOpenCredential>(OPEN_CREDENTIAL_EVENT, (event) => {
        void apply(event.payload);
      });
      // 第二个 handler 吃掉 rejection：非 Tauri 环境（jsdom/浏览器直开）
      // listen 会直接 reject，悬空 rejection 会污染无关用例的输出
      pending.then(
        (fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        },
        () => {},
      );
    } catch {
      // 非 Tauri 环境（jest/jsdom）无 listen：主窗口单窗口场景不受影响
    }

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);
};
