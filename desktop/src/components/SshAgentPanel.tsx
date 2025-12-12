import React, { useEffect, useState } from 'react';
import { ArrowPathIcon, PlayIcon, StopIcon, KeyIcon } from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';
import { clsx } from 'clsx';

const SshAgentPanel: React.FC = () => {
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
      <section className="bg-white shadow rounded-xl p-6 border border-gray-100">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-medium text-gray-500">SSH Agent</p>
            <div className="flex items-center mt-1">
              <span
                className={clsx(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold',
                  sshAgentStatus?.running ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600',
                )}
              >
                {sshAgentStatus?.running ? 'Running' : 'Stopped'}
              </span>
              {sshAgentStatus?.socket_path && (
                <span className="ml-3 text-sm text-gray-600 truncate">
                  Socket: <span className="font-medium">{sshAgentStatus.socket_path}</span>
                </span>
              )}
            </div>
            {sshAgentStatus?.key_count !== undefined && (
              <p className="mt-1 text-sm text-gray-500">
                Loaded keys: <span className="font-medium">{sshAgentStatus.key_count}</span>
              </p>
            )}
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex gap-2">
              <input
                type="password"
                placeholder="Master password (optional)"
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
                {isStarting ? 'Starting...' : 'Start'}
              </button>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleStop}
                disabled={isStopping}
                className="btn-ghost inline-flex items-center text-red-600 hover:text-red-700"
              >
                <StopIcon className="w-4 h-4 mr-1" />
                {isStopping ? 'Stopping...' : 'Stop'}
              </button>
              <button
                onClick={refreshSshAgentStatus}
                className="btn-ghost inline-flex items-center"
              >
                <ArrowPathIcon className="w-4 h-4 mr-1" />
                Refresh
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="bg-white shadow rounded-xl border border-gray-100">
        <div className="p-6 border-b border-gray-100 flex items-center justify-between">
          <div>
            <p className="text-lg font-semibold text-gray-900">SSH Keys in Vault</p>
            <p className="text-sm text-gray-500">Keys available to the agent</p>
          </div>
          <button onClick={loadSshKeys} className="btn-ghost inline-flex items-center">
            <ArrowPathIcon className="w-4 h-4 mr-1" />
            Reload
          </button>
        </div>
        {sshKeys.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-500">
            No SSH keys found. Create SSH key credentials to use the agent.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Identity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Credential
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Tags
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Updated
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {sshKeys.map((key) => (
                  <tr key={key.id}>
                    <td className="px-6 py-3 text-sm text-gray-900 font-medium flex items-center gap-2">
                      <KeyIcon className="w-4 h-4 text-gray-400" />
                      {key.identity_name}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-700">{key.name}</td>
                    <td className="px-6 py-3 text-sm text-gray-500">
                      {key.tags.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {key.tags.map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-600 rounded-full"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-500">
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
