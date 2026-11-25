import React, { useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { getCurrentWindow } from '@tauri-apps/api/window';
import GeneratorPanel from './GeneratorPanel';

/**
 * In a non-Tauri environment (jest/jsdom) getCurrentWindow throws synchronously,
 * so the hide action degrades to a no-op
 */
const hideSelf = async () => {
  try {
    await getCurrentWindow().hide();
  } catch {
    // jsdom / non-Tauri environment: __TAURI_INTERNALS__ missing
  }
};

/**
 * Generator overlay (remaining item from gap #9: OS-level summon from any app).
 *
 * Hosts the same GeneratorPanel the main window uses — generation is pure
 * computation that never touches the vault, so it works while locked and there
 * is no need to replicate QuickAccessPanel's unlock gate (the overlay stays
 * "open and ready"). The overlay is a resident window (initially visible:false,
 * summoned anytime via hotkey/tray); its React tree stays alive, so options and
 * the previous result persist across summons. Esc collapses it (same as the
 * Quick Access overlay). The Toaster must be mounted here: the overlay is a
 * separate webview and the main window's Toaster never reaches it.
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
