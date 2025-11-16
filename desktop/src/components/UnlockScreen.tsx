import React, { useState } from 'react';
import { EyeIcon, EyeSlashIcon, KeyIcon } from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';

interface UnlockScreenProps {
  onUnlock: () => void;
}

const UnlockScreen: React.FC<UnlockScreenProps> = ({ onUnlock }) => {
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [dbPath, setDbPath] = useState('');
  const [useCustomPath, setUseCustomPath] = useState(false);

  const { initializeService, isLoading, error } = usePersonaService();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterPassword.trim()) return;

    await initializeService(masterPassword, useCustomPath ? dbPath : undefined);
    if (!error) {
      onUnlock();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="mx-auto w-20 h-20 bg-primary-600 rounded-full flex items-center justify-center mb-4">
            <KeyIcon className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-secondary-900 mb-2">Persona</h1>
          <p className="text-secondary-600">Master your digital identity</p>
        </div>

        {/* Unlock Form */}
        <div className="card p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="master-password" className="label text-secondary-700 mb-2 block">
                Master Password
              </label>
              <div className="relative">
                <input
                  id="master-password"
                  type={showPassword ? 'text' : 'password'}
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="input pr-10"
                  placeholder="Enter your master password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                >
                  {showPassword ? (
                    <EyeSlashIcon className="h-5 w-5 text-gray-400" />
                  ) : (
                    <EyeIcon className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>

            {/* Advanced Options */}
            <div>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={useCustomPath}
                  onChange={(e) => setUseCustomPath(e.target.checked)}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <span className="ml-2 text-sm text-secondary-700">Use custom database path</span>
              </label>
            </div>

            {useCustomPath && (
              <div>
                <label htmlFor="db-path" className="label text-secondary-700 mb-2 block">
                  Database Path
                </label>
                <input
                  id="db-path"
                  type="text"
                  value={dbPath}
                  onChange={(e) => setDbPath(e.target.value)}
                  className="input"
                  placeholder="/path/to/persona.db"
                />
              </div>
            )}

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-md p-3">
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !masterPassword.trim()}
              className="btn-primary w-full"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Unlocking...
                </div>
              ) : (
                'Unlock Persona'
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-xs text-secondary-500">
              Don't have a master password? It will be created on first use.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UnlockScreen;