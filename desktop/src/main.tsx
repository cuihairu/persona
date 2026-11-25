import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import QuickAccessPanel from './components/QuickAccessPanel';
import GeneratorOverlay from './components/GeneratorOverlay';
import { useTheme } from './hooks/useTheme';
import { getCurrentWindow } from '@tauri-apps/api/window';
import '@/i18n';
import './index.css';

/** Window label of the Quick Access floating panel (matches tauri.conf.json / quick_access.rs) */
const QUICK_ACCESS_LABEL = 'quick-access';

/** Window label of the generator floating panel (as above, GENERATOR_WINDOW_LABEL in quick_access.rs) */
const GENERATOR_PANEL_LABEL = 'generator-panel';

/**
 * Reads the current window label. **Always returns null outside Tauri
 * (jest/jsdom)**: `getCurrentWindow()` throws synchronously when
 * `__TAURI_INTERNALS__` is missing, so tests always fall into the main-window
 * branch (equivalent to the old "there is only one window" behavior).
 */
const currentWindowLabel = (): string | null => {
  try {
    return getCurrentWindow().label;
  } catch {
    return null;
  }
};

/**
 * Floating-panel shell: theme wiring is patched in here — `useTheme` was only
 * mounted on App (the main window), but the panel is a separate webview and has
 * to connect <html>.dark to the native window theme itself (the theme
 * preference goes through localStorage, shared by both windows same-origin, so
 * no extra synchronization is needed).
 */
const QuickAccessRoot: React.FC = () => {
  useTheme();
  return <QuickAccessPanel />;
};

/** Generator floating-panel shell: same as QuickAccessRoot; the theme preference goes through localStorage and needs no extra sync */
const GeneratorPanelRoot: React.FC = () => {
  useTheme();
  return <GeneratorOverlay />;
};

/**
 * The same index.html serves three windows: the main window (App), the Quick
 * Access search panel (label quick-access) and the generator panel (label
 * generator-panel), each raised by an OS-level global hotkey. The branching
 * happens at the **mount point** rather than as an early return inside App —
 * the floating panel must not mount the main UI's whole sidebar / approval
 * dialog / auto-lock monitoring logic and store side effects.
 */
const Root: React.FC = () => {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    setLabel(currentWindowLabel());
  }, []);

  if (label === QUICK_ACCESS_LABEL) {
    return <QuickAccessRoot />;
  }
  if (label === GENERATOR_PANEL_LABEL) {
    return <GeneratorPanelRoot />;
  }
  // Render the main window first for both a not-yet-ready label (first frame)
  // and non-Tauri environments: flashing the main UI for a frame is less bad
  // than the reverse (the user was summoned by the hotkey on the panel side)
  return <App />;
};

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);