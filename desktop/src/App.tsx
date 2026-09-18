import React, { useState, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { LockClosedIcon, Cog6ToothIcon, ChartBarIcon } from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useAutoLockEvents } from '@/hooks/useAutoLockEvents';
import { useSshApprovals } from '@/hooks/useSshApprovals';
import { usePasskeyApprovals } from '@/hooks/usePasskeyApprovals';
import { useTheme } from '@/hooks/useTheme';
import { personaAPI } from '@/utils/api';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import UnlockScreen from '@/components/UnlockScreen';
import { IdentitySwitcher, CreateIdentityModal } from '@/components/IdentitySwitcher';
import CredentialList from '@/components/CredentialList';
import CreateCredentialModal from '@/components/CreateCredentialModal';
import { ErrorBoundary, ErrorDisplay, LoadingSpinner } from '@/components/ErrorHandling';
import SshApprovalModal from '@/components/SshApprovalModal';
import PasskeyApprovalModal from '@/components/PasskeyApprovalModal';
import SshAgentPanel from '@/components/SshAgentPanel';
import WalletPanel from '@/components/WalletPanel';
import WatchtowerPanel from '@/components/WatchtowerPanel';
import PasskeyPanel from '@/components/PasskeyPanel';
import SettingsModal from '@/components/SettingsModal';
import type { FeatureFlags } from '@/types';

type ViewId = 'credentials' | 'statistics' | 'sshAgent' | 'wallets' | 'watchtower' | 'passkeys';

interface NavItem {
  id: ViewId;
  label: string;
  /** 对应 workspace 功能开关；不带的为主航道视图，恒可见 */
  flag?: keyof FeatureFlags;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'credentials', label: 'Credentials' },
  { id: 'statistics', label: 'Statistics' },
  { id: 'sshAgent', label: 'SSH Agent', flag: 'ssh_agent' },
  { id: 'wallets', label: 'Wallets', flag: 'wallet' },
  { id: 'watchtower', label: 'Watchtower' },
  { id: 'passkeys', label: 'Passkeys', flag: 'passkeys' },
];

/** 两个 Toaster（锁定态/主界面）共用的气泡样式；配色走 .persona-toast 的 CSS 变量随主题翻转 */
const TOAST_OPTIONS = { className: 'persona-toast' };

const App: React.FC = () => {
  // 主题联动：偏好 → <html>.dark + localStorage + 原生窗口主题（挂在早退 return 之前）
  useTheme();

  const {
    isUnlocked,
    currentIdentity,
    error,
    isLoading,
    lockService,
    loadCredentialsForIdentity,
    clearError,
  } = usePersonaService();

  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);

  const [showCreateIdentity, setShowCreateIdentity] = useState(false);
  const [showCreateCredential, setShowCreateCredential] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [currentView, setCurrentView] = useState<ViewId>('credentials');

  const visibleNav = NAV_ITEMS.filter((item) => !item.flag || featureFlags[item.flag]);

  // Auto-lock 事件流：lock_pending 倒计时横幅 + locked 回解锁屏（hook 内处理）
  const { pendingSeconds } = useAutoLockEvents(isUnlocked);

  // SSH 签名审批队列：内嵌 agent 请求确认时弹窗（Allow/Deny）
  const { pending: pendingApproval, pendingCount, respond } = useSshApprovals(isUnlocked);

  // Passkey 审批队列：bridge 转来的 create/assert 请求弹窗（Allow/Deny）
  const {
    pending: pendingPasskeyApproval,
    pendingCount: pendingPasskeyCount,
    respond: respondPasskey,
  } = usePasskeyApprovals(isUnlocked);

  // 解锁后启动后端 auto-lock 监控，锁定后停止
  useEffect(() => {
    if (isUnlocked) {
      personaAPI.startAutoLockMonitoring().catch(() => {});
    } else {
      personaAPI.stopAutoLockMonitoring().catch(() => {});
    }
  }, [isUnlocked]);

  // 解锁后拉取 workspace 功能开关；锁定时回到默认（全关）。
  // 读取失败静默保持默认：解锁流程不因设置读取中断。
  useEffect(() => {
    if (!isUnlocked) {
      setFeatureFlags({ ...DEFAULT_FEATURE_FLAGS });
      return;
    }
    (async () => {
      try {
        const resp = await personaAPI.getWorkspaceSettings();
        if (resp.success && resp.data) {
          setFeatureFlags(resp.data.features);
        }
      } catch {
        // keep defaults
      }
    })();
  }, [isUnlocked, setFeatureFlags]);

  // 当前视图对应的功能被关闭时回退 credentials（导航按钮已消失，避免停在不可达视图）
  useEffect(() => {
    const current = NAV_ITEMS.find((item) => item.id === currentView);
    if (current?.flag && !featureFlags[current.flag]) {
      setCurrentView('credentials');
    }
  }, [currentView, featureFlags]);

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
          <Toaster position="top-right" toastOptions={TOAST_OPTIONS} />
        </div>
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gray-50">
        {/* Auto-lock 倒计时横幅 */}
        {pendingSeconds !== null && (
          <div
            data-testid="auto-lock-banner"
            className="bg-amber-50 border-b border-amber-200 px-4 py-2 text-center text-sm text-amber-800"
          >
            检测到长时间无操作，将在 {pendingSeconds} 秒后自动锁定（移动鼠标或按键可保持解锁）
          </div>
        )}

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
                  {visibleNav.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => setCurrentView(item.id)}
                      className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                        currentView === item.id
                          ? 'bg-white text-gray-900 shadow-sm'
                          : 'text-gray-500 hover:text-gray-700'
                      }`}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>

                {/* Action Buttons */}
                <button className="btn-ghost" onClick={() => setShowSettings(true)}>
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
          {currentView === 'watchtower' && <WatchtowerPanel />}
          {currentView === 'passkeys' && <PasskeyPanel />}
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

        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
        />

        {/* SSH 签名审批弹窗 */}
        <SshApprovalModal
          request={pendingApproval}
          pendingCount={pendingCount}
          onRespond={respond}
        />

        {/* Passkey 审批弹窗（bridge 请求） */}
        <PasskeyApprovalModal
          request={pendingPasskeyApproval}
          pendingCount={pendingPasskeyCount}
          onRespond={respondPasskey}
        />

        {/* Toast Notifications */}
        <Toaster position="top-right" toastOptions={TOAST_OPTIONS} />
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
