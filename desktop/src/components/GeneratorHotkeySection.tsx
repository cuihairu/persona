import React, { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '../utils/api';
import type { GeneratorStatus } from '../types';

/**
 * Generator hotkey settings section (remaining item from gap #9: OS-level
 * summon of the generator overlay from any app).
 *
 * Mirrors QuickAccessSection: toggle, binding rewrite, and an honest display
 * of "is it actually active". The status panel is readable without unlocking,
 * so even when locked you can tell whether the hotkey is alive.
 */
const GeneratorHotkeySection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<GeneratorStatus | null>(null);
  const [hotkeyInput, setHotkeyInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const resp = await personaAPI.generatorStatus();
      if (resp.success && resp.data) {
        setStatus(resp.data);
        setHotkeyInput(resp.data.configured_accelerator);
      }
    } catch {
      // A failed status read doesn't break the panel (keep the last value; null on first load = not loaded)
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const apply = async (enabled: boolean, accelerator: string | null) => {
    setSaving(true);
    setError(null);
    try {
      const resp = await personaAPI.generatorSet(enabled, accelerator);
      if (resp.success && resp.data) {
        setStatus(resp.data);
        setHotkeyInput(resp.data.configured_accelerator);
        if (resp.data.error) {
          // Persisted but OS registration failed: the binding changed, it is just not active right now
          toast.error(t('settings.generatorHotkey.savedButNotActive'));
        } else {
          toast.success(t('settings.generatorHotkey.saved'));
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
  // Active check: toggle on + registration succeeded. On registration failure configured and registered diverge
  const active =
    enabled && status?.registered_accelerator !== null && status?.registered_accelerator !== undefined;

  return (
    <section data-testid="generator-hotkey-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.generatorHotkey.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        {t('settings.generatorHotkey.description')}
      </p>
      <div className="border border-gray-200 rounded-lg p-4 space-y-4 dark:border-gray-700">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.generatorHotkey.enable')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {t('settings.generatorHotkey.enableHint')}
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={t('settings.generatorHotkey.enable')}
            data-testid="generator-hotkey-toggle"
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
            htmlFor="generator-hotkey"
          >
            {t('settings.generatorHotkey.hotkey')}
          </label>
          <div className="flex items-center gap-2">
            <input
              id="generator-hotkey"
              type="text"
              data-testid="generator-hotkey"
              value={hotkeyInput}
              spellCheck={false}
              onChange={(e) => setHotkeyInput(e.target.value)}
              className="input flex-1 font-mono text-sm"
              placeholder="Control+Shift+G"
            />
            <button
              type="button"
              data-testid="generator-hotkey-save"
              disabled={saving || status === null}
              onClick={() => void apply(enabled, hotkeyInput.trim() || null)}
              className="whitespace-nowrap rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('common.save')}
            </button>
            <button
              type="button"
              data-testid="generator-hotkey-reset"
              disabled={saving || status === null}
              onClick={() => void apply(enabled, null)}
              className="whitespace-nowrap rounded-md border border-gray-300 dark:border-gray-600 text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('settings.generatorHotkey.resetDefault')}
            </button>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {t('settings.generatorHotkey.hotkeyHint')}
          </p>
        </div>

        {/* Active status: when registration fails, pass the backend reason through
            verbatim (the English is the OS/plugin's own text — don't rewrite it as
            "unknown error"; the user needs it to check WM grabs or pick another key) */}
        <div className="text-xs" data-testid="generator-hotkey-status">
          {status === null ? (
            <span className="text-gray-400 dark:text-gray-500">
              {t('settings.generatorHotkey.statusUnknown')}
            </span>
          ) : !enabled ? (
            <span className="text-gray-500 dark:text-gray-400">
              {t('settings.generatorHotkey.statusDisabled')}
            </span>
          ) : active ? (
            <span className="text-green-600 dark:text-green-400">
              {t('settings.generatorHotkey.statusActive', {
                accelerator: status.registered_accelerator ?? '',
              })}
            </span>
          ) : (
            <span className="text-amber-600 dark:text-amber-400">
              {t('settings.generatorHotkey.statusNotActive', {
                accelerator: status.configured_accelerator,
                reason: status.error ?? t('settings.generatorHotkey.statusUnknown'),
              })}
            </span>
          )}
        </div>

        {error && (
          <p className="text-xs text-red-600 dark:text-red-400" data-testid="generator-hotkey-error">
            {error}
          </p>
        )}

        <button
          type="button"
          data-testid="generator-hotkey-open"
          onClick={() => void personaAPI.generatorOpen()}
          className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
        >
          {t('settings.generatorHotkey.openNow')}
        </button>
      </div>
    </section>
  );
};

export default GeneratorHotkeySection;
