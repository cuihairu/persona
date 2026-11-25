import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';

type Transport = 'server' | 'cloud';

/** Sync transport section: whether the command stream goes through persona-server or cloud-drive folder file exchange.
 *
 * Semantic boundary with the existing toggles (2026-11-23 user directive "cloud sync UI + watcher"):
 * - `settings.sync_methods` (sync methods) controls **entry availability**; this controls **which
 *   transport the engine uses** — two independent semantics, never merged (`SyncConfig.sync_transport`).
 * - Cloud transport needs a folder chosen first (backend validation: cloud must come with a non-empty
 *   folder); an empty folder = keep the old value, so switching back to server and then to cloud
 *   doesn't require re-picking.
 * - No optimistic flip on switching: a successful save is backfilled from server truth; on failure
 *   the real state stays.
 * - Saving takes effect immediately: the watcher (host side) watches the cloud folder for changes
 *   under this config and runs sync cycles automatically.
 */
const SyncTransportSection: React.FC = () => {
  const { t } = useTranslation();
  // null = not yet loaded (server truth hasn't arrived) — controls disabled, avoiding an overwrite with default values
  const [transport, setTransport] = useState<Transport | null>(null);
  const [dir, setDir] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    personaAPI
      .getWorkspaceSettings()
      .then((resp) => {
        if (cancelled || !resp.success) return;
        const sync = resp.data?.sync;
        // A missing key in old JSON falls back to the default server via backend serde; a missing
        // sync section entirely (fresh vault) is likewise presented as the default server
        setTransport(sync?.sync_transport ?? 'server');
        setDir(sync?.cloud_drive_dir ?? null);
      })
      .catch(() => {
        // On read failure stay disabled, don't disrupt the settings page (same policy as SyncMethodsSection)
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const save = async (nextTransport: Transport, nextDir: string | null): Promise<boolean> => {
    if (nextTransport === 'cloud' && !nextDir) {
      toast.error(t('settings.syncTransport.dirRequired'));
      return false;
    }
    setSaving(true);
    try {
      const resp = await personaAPI.setSyncTransport(nextTransport, nextDir);
      if (resp.success && resp.data) {
        const sync = resp.data.sync;
        setTransport(sync?.sync_transport ?? nextTransport);
        setDir(sync?.cloud_drive_dir ?? nextDir);
        toast.success(t('settings.syncTransport.saved'));
        return true;
      }
      toast.error(resp.error || t('settings.syncTransport.saveFailed'));
      return false;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('settings.syncTransport.saveFailed'));
      return false;
    } finally {
      setSaving(false);
    }
  };

  /** Open the system folder picker; a pick saves immediately (cloud transport cannot work without a folder). */
  const pickDir = async (): Promise<void> => {
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked !== 'string' || !picked) return;
    setDir(picked);
    await save('cloud', picked);
  };

  const chooseServer = (): void => {
    if (transport === null) return;
    // Keep the existing cloud folder (no need to re-pick when switching back to cloud)
    void save('server', dir);
  };

  const chooseCloud = (): void => {
    if (transport === null) return;
    if (!dir) {
      // No folder: pick one first, saving right after the pick (the backend rejects cloud without a folder)
      void pickDir();
      return;
    }
    void save('cloud', dir);
  };

  const disabled = saving || transport === null;
  const optionClasses = (active: boolean) =>
    `flex items-center gap-3 rounded-md border px-3 py-2 text-left transition-colors ${
      active
        ? 'border-primary-600 bg-primary-50 dark:border-primary-500 dark:bg-primary-950/30'
        : 'border-gray-200 hover:border-gray-300 dark:border-gray-700 dark:hover:border-gray-600'
    }`;

  return (
    <div data-testid="sync-transport-section">
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
        {t('settings.syncTransport.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        {t('settings.syncTransport.description')}
      </p>
      <div className="space-y-2">
        <button
          type="button"
          role="radio"
          aria-checked={transport === 'server'}
          data-testid="sync-transport-server"
          disabled={disabled}
          onClick={chooseServer}
          className={optionClasses(transport === 'server')}
        >
          <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.syncTransport.server')}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.syncTransport.serverDesc')}
          </span>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={transport === 'cloud'}
          data-testid="sync-transport-cloud"
          disabled={disabled}
          onClick={chooseCloud}
          className={optionClasses(transport === 'cloud')}
        >
          <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {t('settings.syncTransport.cloud')}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {t('settings.syncTransport.cloudDesc')}
          </span>
        </button>
      </div>

      {transport === 'cloud' && (
        <div className="mt-3 border border-gray-200 rounded-lg p-4 dark:border-gray-700">
          <label className="label mb-1 block" htmlFor="sync-cloud-dir">
            {t('settings.syncTransport.dirLabel')}
          </label>
          <div className="flex items-center gap-2">
            <input
              id="sync-cloud-dir"
              className="input flex-1 font-mono text-xs"
              data-testid="sync-cloud-dir-input"
              value={dir ?? ''}
              placeholder={t('settings.syncTransport.dirNotSet')}
              readOnly
              spellCheck={false}
            />
            <button
              type="button"
              data-testid="sync-cloud-pick-dir"
              onClick={() => void pickDir()}
              disabled={disabled}
              className="btn-secondary flex-shrink-0"
            >
              {t('settings.syncTransport.pickDir')}
            </button>
          </div>
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            {t('settings.syncTransport.dirHint')}
          </p>
        </div>
      )}
    </div>
  );
};

export default SyncTransportSection;
