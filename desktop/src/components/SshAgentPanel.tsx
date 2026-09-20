import React, { useEffect, useState } from 'react';
import { ArrowPathIcon, PlayIcon, StopIcon, KeyIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import { usePersonaService } from '@/hooks/usePersonaService';
import { clsx } from 'clsx';

const SshAgentPanel: React.FC = () => {
  const { t } = useTranslation();
  const {
    sshAgentStatus,
    sshKeys,
    refreshSshAgentStatus,
    startSshAgent,
    stopSshAgent,
    loadSshKeys,
  } = usePersonaService();

  const [masterPassword, setMasterPassword] = useState('');
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);

  useEffect(() => {
    refreshSshAgentStatus();
    loadSshKeys();
  }, []);

  const handleStart = async () => {
    setIsStarting(true);
    await startSshAgent(masterPassword || undefined);
    await refreshSshAgentStatus();
    setMasterPassword('');
    setIsStarting(false);
  };

  const handleStop = async () => {
    setIsStopping(true);
    await stopSshAgent();
    await refreshSshAgentStatus();
    setIsStopping(false);
  };

  return (
    <div className="space-y-6">
      <section className="bg-white dark:bg-gray-900 shadow rounded-xl p-6 border border-gray-100 dark:border-gray-800">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">SSH Agent</p>
            <div className="flex items-center mt-1">
              <span
                className={clsx(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold',
                  sshAgentStatus?.running ? 'bg-green-100 dark:bg-green-500/10 text-green-800 dark:text-green-300' : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300',
                )}
              >
                {sshAgentStatus?.running ? t('sshAgent.running') : t('sshAgent.stopped')}
              </span>
              {sshAgentStatus?.socket_path && (
                <span className="ml-3 text-sm text-gray-600 dark:text-gray-300 truncate">
                  {t('sshAgent.socket')} <span className="font-medium">{sshAgentStatus.socket_path}</span>
                </span>
              )}
            </div>
            {sshAgentStatus?.key_count !== undefined && (
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {t('sshAgent.loadedKeys')} <span className="font-medium">{sshAgentStatus.key_count}</span>
              </p>
            )}
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex gap-2">
              <input
                type="password"
                placeholder={t('sshAgent.passwordPlaceholder')}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                className="input-field w-full sm:w-64"
              />
              <button
                onClick={handleStart}
                disabled={isStarting}
                className="btn-primary inline-flex items-center"
              >
                <PlayIcon className="w-4 h-4 mr-1" />
                {isStarting ? t('sshAgent.starting') : t('sshAgent.start')}
              </button>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleStop}
                disabled={isStopping}
                className="btn-ghost inline-flex items-center text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
              >
                <StopIcon className="w-4 h-4 mr-1" />
                {isStopping ? t('sshAgent.stopping') : t('sshAgent.stop')}
              </button>
              <button
                onClick={refreshSshAgentStatus}
                className="btn-ghost inline-flex items-center"
              >
                <ArrowPathIcon className="w-4 h-4 mr-1" />
                {t('sshAgent.refresh')}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="bg-white dark:bg-gray-900 shadow rounded-xl border border-gray-100 dark:border-gray-800">
        <div className="p-6 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div>
            <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{t('sshAgent.keysTitle')}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('sshAgent.keysSubtitle')}</p>
          </div>
          <button onClick={loadSshKeys} className="btn-ghost inline-flex items-center">
            <ArrowPathIcon className="w-4 h-4 mr-1" />
            {t('sshAgent.reload')}
          </button>
        </div>
        {sshKeys.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-500 dark:text-gray-400">
            {t('sshAgent.noKeys')}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.identityCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.credentialCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.tagsCol')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    {t('sshAgent.updatedCol')}
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {sshKeys.map((key) => (
                  <tr key={key.id}>
                    <td className="px-6 py-3 text-sm text-gray-900 dark:text-gray-100 font-medium flex items-center gap-2">
                      <KeyIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                      {key.identity_name}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-700 dark:text-gray-300">{key.name}</td>
                    <td className="px-6 py-3 text-sm text-gray-500 dark:text-gray-400">
                      {key.tags.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {key.tags.map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded-full"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-400 dark:text-gray-500">—</span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-500 dark:text-gray-400">
                      {new Date(key.updated_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default SshAgentPanel;
