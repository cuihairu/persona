import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { personaAPI } from '@/utils/api';

type Transport = 'server' | 'cloud';

/** 同步传输区块：指令流走 persona-server 还是云盘目录文件交换。
 *
 * 与既有开关的语义边界（2026-11-23 用户令「云盘同步 UI + watcher」）：
 * - `settings.sync_methods`（同步方式）控**入口可用性**；这里控**引擎用哪条
 *   传输**——两套独立语义，绝不合并（`SyncConfig.sync_transport`）。
 * - 云盘传输需先选目录（后端校验：cloud 必须带非空目录）；空目录 = 保留旧值，
 *   切回 server 再切回 cloud 不必重选。
 * - 切换不乐观翻转：保存成功由服务端真相回填，失败保持真实状态。
 * - 保存即生效：watcher（宿主侧）按此配置监听云盘目录变更并自动跑同步周期。
 */
const SyncTransportSection: React.FC = () => {
  const { t } = useTranslation();
  // null = 尚未加载（服务端真相未到）——控件禁用，避免拿默认值盖写
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
        // 旧 JSON 缺键由后端 serde 回退默认 server；sync 整段缺失（fresh vault）
        // 同样按默认 server 呈现
        setTransport(sync?.sync_transport ?? 'server');
        setDir(sync?.cloud_drive_dir ?? null);
      })
      .catch(() => {
        // 读取失败保持禁用态，不打断设置页（同 SyncMethodsSection 口径）
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

  /** 打开系统目录选择器；选定即保存（云盘传输无目录无从工作）。 */
  const pickDir = async (): Promise<void> => {
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked !== 'string' || !picked) return;
    setDir(picked);
    await save('cloud', picked);
  };

  const chooseServer = (): void => {
    if (transport === null) return;
    // 保留既有云盘目录（切回 cloud 时不必重选）
    void save('server', dir);
  };

  const chooseCloud = (): void => {
    if (transport === null) return;
    if (!dir) {
      // 无目录：先选目录，选完即存（后端拒绝无目录的 cloud）
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
