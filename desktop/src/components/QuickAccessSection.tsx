import React, { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '../utils/api';
import type { QuickAccessStatus } from '../types';

/**
 * Quick Access settings section (matrix benchmark #22: OS-level global hotkey + floating panel).
 *
 * Three things: the toggle, rewriting the binding string, and an honest display of "is it
 * actually in effect". The backend returns config truth (DB) and runtime state (the OS grab
 * result) separately, so this section can tell two failures apart: syntax errors (the backend
 * rejects them, config unchanged) vs grab failures (config saved but the hotkey is not live;
 * `error` carries the reason — no portal on Wayland, taken by another app, etc.).
 * The status surface is readable without unlocking; even locked you can see "whether the hotkey is alive".
 */
const QuickAccessSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<QuickAccessStatus | null>(null);
  const [hotkeyInput, setHotkeyInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const resp = await personaAPI.quickAccessStatus();
      if (resp.success && resp.data) {
        setStatus(resp.data);
        setHotkeyInput(resp.data.configured_accelerator);
      }
    } catch {
      // A status read failure doesn't disrupt the panel (keep the last value; null on first load = not loaded)
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const apply = async (enabled: boolean, accelerator: string | null) => {
    setSaving(true);
    setError(null);
    try {
      const resp = await personaAPI.quickAccessSet(enabled, accelerator);
      if (resp.success && resp.data) {
        setStatus(resp.data);
        setHotkeyInput(resp.data.configured_accelerator);
        if (resp.data.error) {
          // Persisted but the OS grab failed: the binding changed, it just isn't active right now
          toast.error(t('settings.quickAccess.savedButNotActive'));
        } else {
          toast.success(t('settings.quickAccess.saved'));
        }
      } else {
        setError(resp.error || t('settings.saveFailed'));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('settings.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const enabled = status?.enabled ?? false;
  // Active check: toggle on + grab succeeded. When the grab fails, configured and registered disagree
  const active = enabled && status?.registered_accelerator !== null && status?.registered_accelerator !== undefined;

  return (
    <section data-testid="quick-access-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.quickAccess.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        {t('settings.quickAccess.description')}
      </p>
      <div className="border border-gray-200 rounded-lg p-4 space-y-4 dark:border-gray-700">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.quickAccess.enable')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.quickAccess.enableHint')}
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={t('settings.quickAccess.enable')}
            data-testid="quick-access-toggle"
            disabled={status === null || saving}
            onClick={() => void apply(!enabled, hotkeyInput || null)}
            className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
              enabled ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                enabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        <div>
          <label
            className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-1"
            htmlFor="quick-access-hotkey"
          >
            {t('settings.quickAccess.hotkey')}
          </label>
          <div className="flex items-center gap-2">
            <input
              id="quick-access-hotkey"
              type="text"
              data-testid="quick-access-hotkey"
              value={hotkeyInput}
              spellCheck={false}
              onChange={(e) => setHotkeyInput(e.target.value)}
              className="input flex-1 font-mono text-sm"
              placeholder="Control+Shift+Space"
            />
            <button
              type="button"
              data-testid="quick-access-save"
              disabled={saving || status === null}
              onClick={() => void apply(enabled, hotkeyInput.trim() || null)}
              className="whitespace-nowrap rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('common.save')}
            </button>
            <button
              type="button"
              data-testid="quick-access-reset"
              disabled={saving || status === null}
              onClick={() => void apply(enabled, null)}
              className="whitespace-nowrap rounded-md border border-gray-300 dark:border-gray-600 text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('settings.quickAccess.resetDefault')}
            </button>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {t('settings.quickAccess.hotkeyHint')}
          </p>
        </div>

        {/* Active status: when the grab fails, surface the backend reason verbatim (it's the OS/plugin's
            original English text; don't translate it into "unknown error" — the user needs it to check WM
            occupancy or pick a different key) */}
        <div className="text-xs" data-testid="quick-access-status">
          {status === null ? (
            <span className="text-gray-400 dark:text-gray-500">
              {t('settings.quickAccess.statusUnknown')}
            </span>
          ) : !enabled ? (
            <span className="text-gray-500 dark:text-gray-400">
              {t('settings.quickAccess.statusDisabled')}
            </span>
          ) : active ? (
            <span className="text-green-600 dark:text-green-400">
              {t('settings.quickAccess.statusActive', {
                accelerator: status.registered_accelerator ?? '',
              })}
            </span>
          ) : (
            <span className="text-amber-600 dark:text-amber-400">
              {t('settings.quickAccess.statusNotActive', {
                accelerator: status.configured_accelerator,
                reason: status.error ?? t('settings.quickAccess.statusUnknown'),
              })}
            </span>
          )}
        </div>

        {error && (
          <p className="text-xs text-red-600 dark:text-red-400" data-testid="quick-access-error">
            {error}
          </p>
        )}

        <button
          type="button"
          data-testid="quick-access-open"
          onClick={() => void personaAPI.quickAccessOpen()}
          className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
        >
          {t('settings.quickAccess.openNow')}
        </button>
      </div>
    </section>
  );
};

export default QuickAccessSection;
