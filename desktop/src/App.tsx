import React, { useState, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { LockClosedIcon, Cog6ToothIcon, ChartBarIcon } from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';
import UnlockScreen from '@/components/UnlockScreen';
import { IdentitySwitcher, CreateIdentityModal } from '@/components/IdentitySwitcher';
import CredentialList from '@/components/CredentialList';
import CreateCredentialModal from '@/components/CreateCredentialModal';
import { ErrorBoundary, ErrorDisplay, LoadingSpinner } from '@/components/ErrorHandling';
import SshAgentPanel from '@/components/SshAgentPanel';
import WalletPanel from '@/components/WalletPanel';

const App: React.FC = () => {
  const {
    isUnlocked,
    currentIdentity,
    error,
    isLoading,
    lockService,
    loadCredentialsForIdentity,
    clearError,
  } = usePersonaService();

  const [showCreateIdentity, setShowCreateIdentity] = useState(false);
  const [showCreateCredential, setShowCreateCredential] = useState(false);
  const [currentView, setCurrentView] = useState<'credentials' | 'statistics' | 'sshAgent' | 'wallets'>('credentials');

  // Load credentials when identity changes
  useEffect(() => {
    if (currentIdentity) {
      loadCredentialsForIdentity(currentIdentity.id);
    }
  }, [currentIdentity]);

  // Show loading state during initialization
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <LoadingSpinner message="Initializing Persona..." />
      </div>
    );
  }

  // Show unlock screen if not unlocked
  if (!isUnlocked) {
    return (
      <ErrorBoundary>
        <div className="min-h-screen bg-gray-50">
          {error && (
            <div className="p-4">
              <ErrorDisplay
                error={error}
                type="error"
                onDismiss={clearError}
              />
            </div>
          )}
          <UnlockScreen onUnlock={() => {}} />
          <Toaster position="top-right" />
        </div>
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gray-50">
        {/* Global error display */}
        {error && (
          <div className="p-4">
            <ErrorDisplay
              error={error}
              type="error"
              onDismiss={clearError}
            />
          </div>
        )}

        {/* Header */}
        <header className="bg-white border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              {/* Logo and Identity Switcher */}
              <div className="flex items-center space-x-4">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-primary-600 rounded-lg flex items-center justify-center mr-3">
                    <span className="text-white font-bold text-sm">P</span>
                  </div>
                  <h1 className="text-xl font-semibold text-gray-900">Persona</h1>
                </div>

                <div className="w-px h-6 bg-gray-300"></div>

                <div className="w-80">
                  <IdentitySwitcher onCreateIdentity={() => setShowCreateIdentity(true)} />
                </div>
              </div>

              {/* Navigation and Actions */}
              <div className="flex items-center space-x-4">
                {/* View Toggle */}
                <div className="flex bg-gray-100 rounded-lg p-1">
                  <button
                    onClick={() => setCurrentView('credentials')}
                    className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                      currentView === 'credentials'
                        ? 'bg-white text-gray-900 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    Credentials
                  </button>
                  <button
                    onClick={() => setCurrentView('statistics')}
                    className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                      currentView === 'statistics'
                        ? 'bg-white text-gray-900 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    Statistics
                  </button>
                  <button
                    onClick={() => setCurrentView('sshAgent')}
                    className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                      currentView === 'sshAgent'
                        ? 'bg-white text-gray-900 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    SSH Agent
                  </button>
                  <button
                    onClick={() => setCurrentView('wallets')}
                    className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                      currentView === 'wallets'
                        ? 'bg-white text-gray-900 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    Wallets
                  </button>
                </div>

                {/* Action Buttons */}
                <button className="btn-ghost">
                  <Cog6ToothIcon className="w-4 h-4" />
                </button>

                <button
                  onClick={lockService}
                  className="btn-ghost text-red-600 hover:text-red-700 hover:bg-red-50"
                >
                  <LockClosedIcon className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {currentView === 'credentials' && (
            <CredentialList onCreateCredential={() => setShowCreateCredential(true)} />
          )}
          {currentView === 'statistics' && <StatisticsView />}
          {currentView === 'sshAgent' && <SshAgentPanel />}
          {currentView === 'wallets' && <WalletPanel />}
        </main>

        {/* Modals */}
        <CreateIdentityModal
          isOpen={showCreateIdentity}
          onClose={() => setShowCreateIdentity(false)}
        />

        <CreateCredentialModal
          isOpen={showCreateCredential}
          onClose={() => setShowCreateCredential(false)}
        />

        {/* Toast Notifications */}
        <Toaster position="top-right" />
      </div>
    </ErrorBoundary>
  );
};

const StatisticsView: React.FC = () => {
  const [statistics, setStatistics] = useState<any>(null);

  useEffect(() => {
    // Load statistics when component mounts
    loadStatistics();
  }, []);

  const loadStatistics = async () => {
    try {
      const response = await import('@/utils/api').then(module =>
        module.personaAPI.getStatistics()
      );
      if (response.success && response.data) {
        setStatistics(response.data);
      }
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  };

  if (!statistics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium text-gray-900 mb-4">Statistics</h2>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Total Identities</p>
              <p className="text-2xl font-bold text-gray-900">{statistics.total_identities}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Total Credentials</p>
              <p className="text-2xl font-bold text-gray-900">{statistics.total_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-yellow-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Active Credentials</p>
              <p className="text-2xl font-bold text-gray-900">{statistics.active_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-red-600" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Favorites</p>
              <p className="text-2xl font-bold text-gray-900">{statistics.favorite_credentials}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Credential Types Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Credential Types</h3>
          <div className="space-y-3">
            {Object.entries(statistics.credential_types).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm text-gray-600">{type}</span>
                <span className="text-sm font-medium text-gray-900">{count as number}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Security Levels</h3>
          <div className="space-y-3">
            {Object.entries(statistics.security_levels).map(([level, count]) => (
              <div key={level} className="flex items-center justify-between">
                <span className="text-sm text-gray-600">{level}</span>
                <span className="text-sm font-medium text-gray-900">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
