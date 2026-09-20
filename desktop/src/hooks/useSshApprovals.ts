import { useCallback, useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import i18n from '@/i18n';
import { personaAPI } from '@/utils/api';
import type { SshApprovalRequest } from '@/types';

/** 后端 SSH 审批事件通道名（与 Rust 侧 DesktopApprovalHandler 一致） */
export const SSH_APPROVAL_EVENT = 'persona://ssh-approval';

/**
 * 订阅内嵌 SSH agent 的签名审批请求：
 * - 请求进入先进先出队列，一次弹一个（后端每个请求独立 oneshot 等待）
 * - Allow/Deny 回传 `ssh_approval_respond`；未应答的请求由后端
 *   120s 超时自动拒绝，不会挂死 agent 连接
 *
 * 仅在解锁 + agent 运行期间挂监听（由调用方通过 enabled 控制）。
 */
export const useSshApprovals = (enabled: boolean) => {
  const [queue, setQueue] = useState<SshApprovalRequest[]>([]);

  useEffect(() => {
    if (!enabled) {
      setQueue([]);
      return;
    }

    let unlisten: (() => void) | undefined;
    let disposed = false;

    listen<SshApprovalRequest>(SSH_APPROVAL_EVENT, (event) => {
      setQueue((prev) =>
        prev.some((r) => r.request_id === event.payload.request_id)
          ? prev
          : [...prev, event.payload],
      );
      // 窗口失焦时用系统通知提醒（modal 看不见）
      if (document.hidden) {
        import('@tauri-apps/plugin-notification')
          .then(({ isPermissionGranted, requestPermission, sendNotification }) =>
            Promise.all([isPermissionGranted(), requestPermission()]).then(
              ([granted, requested]) => {
                if (granted || requested) {
                  sendNotification({
                    title: i18n.t('notif.sshTitle'),
                    body: i18n.t('notif.openToApprove', {
                      source: event.payload.peer ?? i18n.t('notif.unknownHost'),
                    }),
                  });
                }
              },
            ),
          )
          .catch(() => {
            // 通知不可用不影响审批流
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

  /** 应答队首请求（重复 id / 未知 id 由后端按拒绝处理） */
  const respond = useCallback(async (requestId: string, allow: boolean) => {
    setQueue((prev) => prev.filter((r) => r.request_id !== requestId));
    try {
      await personaAPI.sshApprovalRespond(requestId, allow);
    } catch {
      // 命令失败（未知/过期 id）不影响本地队列清理
    }
  }, []);

  return {
    /** 当前待审批请求（队首），无则为 null */
    pending: queue[0] ?? null,
    /** 后端还在等待应答的请求总数 */
    pendingCount: queue.length,
    respond,
  };
};
