import React, { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '../utils/api';
import type { QuickAccessStatus } from '../types';

/**
 * Quick Access 设置区（对标矩阵 #22：OS 级全局热键 + 浮窗）。
 *
 * 三件事：开关、绑定串改写、"到底生效没有"的如实展示。后端把配置真值
 * （DB）与运行态（OS 抢注结果）分开返回，所以这一区能区分两种失败：
 * 语法错（后端拒收，配置不变）与抢注失败（配置已存、热键没生效，
 * `error` 带原因——Wayland 无 portal、被别的应用占用都走这里）。
 * 状态面免解锁可读，锁定后仍能看出"热键是不是活的"。
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
      // 状态读取失败不打断面板（保持上次值；首次为 null = 未加载）
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
          // 落库成功但 OS 抢注失败：绑定已改，只是此刻不生效
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
  // 生效判定：开关开 + 抢注成功。抢注失败时 configured 与 registered 不一致
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
              className="rounded-md bg-primary-600 hover:bg-primary-700 text-white text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('common.save')}
            </button>
            <button
              type="button"
              data-testid="quick-access-reset"
              disabled={saving || status === null}
              onClick={() => void apply(enabled, null)}
              className="rounded-md border border-gray-300 dark:border-gray-600 text-sm px-3 py-2 disabled:opacity-50"
            >
              {t('settings.quickAccess.resetDefault')}
            </button>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {t('settings.quickAccess.hotkeyHint')}
          </p>
        </div>

        {/* 生效状态：抢注失败时把后端原因原样透出（英文是 OS/插件原文，
            不翻译成"未知错误"——用户要照着它去查 WM 占用或换键） */}
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
