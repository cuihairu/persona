import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '@/utils/api';
import DataScopeConsentModal from '../DataScopeConsentModal';

/** Sync server section: report audit events to persona-server (enabled + url + token). */
const SyncServerPane: React.FC = () => {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [tokenPlaceholder, setTokenPlaceholder] = useState('API token');
  const [saving, setSaving] = useState(false);
  // Privacy red line: the data-scope disclosure must pass before enabling; only confirmation expands the config form (cancel = stays off)
  const [consentOpen, setConsentOpen] = useState(false);

  // Token truth lives in the OS keyring (the backend's sync.server_token always returns an empty
  // string); the placeholder is driven by sync_token_present; the token is never backfilled
  // (so an existing token doesn't sit in frontend memory permanently; submitting an empty string
  // = the backend keeps the old keyring token)
  const refreshTokenPlaceholder = async (): Promise<void> => {
    try {
      const resp = await personaAPI.syncTokenPresent();
      setTokenPlaceholder(
        resp.success && resp.data ? t('settings.sync.tokenSavedPlaceholder') : t('settings.sync.tokenPlaceholder'),
      );
    } catch {
      setTokenPlaceholder(t('settings.sync.tokenPlaceholder'));
    }
  };

  // Initial values come from server truth
  useEffect(() => {
    let cancelled = false;
    personaAPI
      .getWorkspaceSettings()
      .then((resp) => {
        if (cancelled || !resp.success || !resp.data?.sync) return;
        setEnabled(resp.data.sync.enabled);
        setUrl(resp.data.sync.server_url);
      })
      .catch(() => {});
    refreshTokenPlaceholder();
    return () => {
      cancelled = true;
    };
  }, []);

  const save = async (nextEnabled: boolean) => {
    if (nextEnabled && !url.trim()) {
      toast.error(t('settings.sync.urlRequired'));
      return;
    }
    setSaving(true);
    try {
      const resp = await personaAPI.setSyncConfig({
        enabled: nextEnabled,
        server_url: url.trim(),
        server_token: token,
      });
      if (resp.success && resp.data) {
        // Backfill server truth; clear the token input (an empty-string submit = the backend keeps the
        // old keyring value; disabling = the backend clears the token). Re-query the keyring for the placeholder.
        const sync = resp.data.sync;
        if (sync) {
          setEnabled(sync.enabled);
          setUrl(sync.server_url);
        }
        setToken('');
        await refreshTokenPlaceholder();
        toast.success(t('settings.sync.saved'));
      } else {
        toast.error(resp.error || t('settings.sync.saveFailed'));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.sync.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between gap-4 mb-2">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">{t('settings.sync.title')}</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.sync.description')}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label={t('settings.sync.enable')}
          data-testid="sync-toggle"
          disabled={saving}
          onClick={() => {
            if (!enabled) {
              // Privacy red line: enabling = disclose the data scope first; only confirmation expands the config form
              setConsentOpen(true);
              return;
            }
            // No early optimistic flip on disable: after a successful save, server truth is backfilled;
            // on failure the real state stays (2026-11-13 deep-review Major fix); the button is disabled
            // during saving so no stacked writes happen
            void save(false);
          }}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors ${
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

      {enabled && (
        <div className="space-y-3 border border-gray-200 rounded-lg p-4 dark:border-gray-700">
          <div>
            <label className="label mb-1 block" htmlFor="sync-server-url">
              {t('settings.sync.serverUrl')}
            </label>
            <input
              id="sync-server-url"
              className="input"
              data-testid="sync-url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://sync.example.com"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div>
            <label className="label mb-1 block" htmlFor="sync-server-token">
              {t('settings.sync.apiToken')}
            </label>
            <input
              id="sync-server-token"
              className="input"
              data-testid="sync-token-input"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={tokenPlaceholder}
              autoComplete="new-password"
            />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              data-testid="sync-save"
              onClick={() => save(true)}
              disabled={saving}
              className="btn-primary"
            >
              {saving ? t('settings.saving') : t('common.save')}
            </button>
          </div>
        </div>
      )}

      {consentOpen && (
        <DataScopeConsentModal
          scope="audit"
          onConfirm={() => {
            setConsentOpen(false);
            setEnabled(true);
          }}
          onCancel={() => setConsentOpen(false)}
        />
      )}
    </div>
  );
};


export default SyncServerPane;
