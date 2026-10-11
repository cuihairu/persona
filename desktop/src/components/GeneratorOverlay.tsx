import React, { useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { getCurrentWindow } from '@tauri-apps/api/window';
import GeneratorPanel from './GeneratorPanel';

/**
 * 非 Tauri 环境（jest/jsdom）下 getCurrentWindow 同步抛错，隐藏动作降级为空操作
 */
const hideSelf = async () => {
  try {
    await getCurrentWindow().hide();
  } catch {
    // jsdom / 非 Tauri 环境：__TAURI_INTERNALS__ 缺失
  }
};

/**
 * 生成器浮窗（gap #9 余项：OS 级任意应用内呼出）。
 *
 * 直接承载主窗口用的 GeneratorPanel——生成是纯计算不触碰库，锁定态也能用，
 * 所以不需要复刻 QuickAccessPanel 的解锁门禁（浮窗保持"打开即用"）。
 * 浮窗是常驻窗口（初始 visible:false，热键/托盘随时唤起），React 树一直
 * 活着，选项与上一次结果跨次唤起保留；Esc 收起（同 Quick Access 浮窗）。
 * Toaster 要自己挂：浮窗是独立 webview，主窗口里的 Toaster 到不了这里。
 */
const GeneratorOverlay: React.FC = () => {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        void hideSelf();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  return (
    <div
      className="min-h-screen bg-gray-50 dark:bg-gray-950 overflow-y-auto p-4"
      data-testid="generator-overlay"
    >
      <GeneratorPanel />
      <Toaster position="top-center" />
    </div>
  );
};

export default GeneratorOverlay;
