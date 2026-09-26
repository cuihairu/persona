import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import QuickAccessPanel from './components/QuickAccessPanel';
import { useTheme } from './hooks/useTheme';
import { getCurrentWindow } from '@tauri-apps/api/window';
import '@/i18n';
import './index.css';

/** Quick Access 浮窗的窗口标签（与 tauri.conf.json / quick_access.rs 一致） */
const QUICK_ACCESS_LABEL = 'quick-access';

/**
 * 读当前窗口标签。**非 Tauri 环境（jest/jsdom）恒返回 null**：
 * `getCurrentWindow()` 在缺 `__TAURI_INTERNALS__` 时同步抛错，测试里
 * 一律落到主窗口分支（等价于"只有一个窗口"的旧行为）。
 */
const currentWindowLabel = (): string | null => {
  try {
    return getCurrentWindow().label;
  } catch {
    return null;
  }
};

/**
 * 浮窗壳：主题联动在这里补一次——`useTheme` 原先只挂在 App（主窗口），
 * 浮窗是独立 webview，得自己把 <html>.dark 与原生窗口主题接上（主题偏好
 * 走 localStorage，两窗口同源共享，不需要额外同步）
 */
const QuickAccessRoot: React.FC = () => {
  useTheme();
  return <QuickAccessPanel />;
};

/**
 * 同一份 index.html 服务两个窗口：主窗口（App）与 Quick Access 浮窗
 * （标签 quick-access，OS 级全局热键唤起）。分流在**挂载点**做而不是
 * App 内部早退——浮窗不该把主界面的侧栏/审批弹窗/auto-lock 监控整套
 * 逻辑与 store 副作用都挂一遍。
 */
const Root: React.FC = () => {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    setLabel(currentWindowLabel());
  }, []);

  if (label === QUICK_ACCESS_LABEL) {
    return <QuickAccessRoot />;
  }
  // label 未就绪（首帧）与非 Tauri 环境都先渲染主窗口：浮窗首帧闪一下
  // 主界面比反过来更糟（用户是被热键唤起的一方）
  return <App />;
};

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
