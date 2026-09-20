import React, { useState, useEffect } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { ChartBarIcon } from '@heroicons/react/24/outline';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { useAutoLockEvents } from '@/hooks/useAutoLockEvents';
import { useSshApprovals } from '@/hooks/useSshApprovals';
import { usePasskeyApprovals } from '@/hooks/usePasskeyApprovals';
import { useTheme } from '@/hooks/useTheme';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import UnlockScreen from '@/components/UnlockScreen';
import { CreateIdentityModal } from '@/components/IdentitySwitcher';
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
import QuickSearch from '@/components/QuickSearch';
import Sidebar, { NAV_ITEMS } from '@/components/Sidebar';
import type { ViewId } from '@/components/Sidebar';

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
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  // 编辑中的凭据（DetailPane Edit 按钮写入；modal 消费，null = 创建模式）
  const editingCredential = useAppStore((s) => s.editingCredential);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);

  const [showCreateIdentity, setShowCreateIdentity] = useState(false);
  const [showCreateCredential, setShowCreateCredential] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [currentView, setCurrentView] = useState<ViewId>('credentials');

  // ⌘L 锁定：App 恒挂载，enabled=isUnlocked 保证锁定屏无监听。
  // 顺带修既有边界：锁前开着的 modal 在解锁后会自动重开（App 不卸载、
  // 本地 bool 残留），锁定时一并复位。
  const handleLock = () => {
    setShowCreateIdentity(false);
    setShowCreateCredential(false);
    setShowSettings(false);
    setEditingCredential(null);
    void lockService();
  };
  useGlobalShortcut('l', handleLock, isUnlocked);

  // ⌘, 开/关设置 modal
  useGlobalShortcut(',', () => setShowSettings((v) => !v), isUnlocked);

  // ⌘E 复制当前选中凭据的用户名（按键时现读 store，不订阅、无陈旧闭包）
  const handleCopyUsername = () => {
    const { credentials, selectedCredentialId, currentIdentity } = useAppStore.getState();
    const selected = credentials.find((c) => c.id === selectedCredentialId);
    // 无选中 / 选中已悬空（停在别的视图时切身份会残留跨身份 id）都按"未选中"提示
    if (!selected || (currentIdentity && selected.identity_id !== currentIdentity.id)) {
      toast.error('Select an entry first');
      return;
    }
    if (!selected.username) {
      toast.error('This entry has no username');
      return;
    }
    void copyToClipboardWithToast(selected.username, 'Username');
  };
  useGlobalShortcut('e', handleCopyUsername, isUnlocked);

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
    // 换身份丢弃旧分类树选中（新身份未必还有该类型/标签）
    resetSidebarFilter();
  }, [currentIdentity]);

  // Show loading state during initialization
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center">
        <LoadingSpinner message="Initializing Persona..." />
      </div>
    );
  }

  // Show unlock screen if not unlocked
  if (!isUnlocked) {
    return (
      <ErrorBoundary>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
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
      {/* app shell：固定视口高度，滚动收进侧栏与主列各自的内部容器 */}
      <div className="h-screen flex flex-col overflow-hidden bg-gray-50 dark:bg-gray-950">
        {/* Auto-lock 倒计时横幅 */}
        {pendingSeconds !== null && (
          <div
            data-testid="auto-lock-banner"
            className="bg-amber-50 dark:bg-amber-500/10 border-b border-amber-200 dark:border-amber-500/20 px-4 py-2 text-center text-sm text-amber-800 dark:text-amber-300"
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

        <div className="flex flex-1 min-h-0">
          <Sidebar
            currentView={currentView}
            onNavigate={setCurrentView}
            onCreateIdentity={() => setShowCreateIdentity(true)}
            onOpenSettings={() => setShowSettings(true)}
            onLock={handleLock}
          />

          {/* 主列：窄工具栏 + 独立滚动的主区 */}
          <div className="flex-1 min-w-0 flex flex-col">
            <div className="h-12 shrink-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 flex items-center px-4 sm:px-6 lg:px-8">
              <h1
                data-testid="view-title"
                className="text-sm font-semibold text-gray-900 dark:text-gray-100"
              >
                {NAV_ITEMS.find((item) => item.id === currentView)?.label}
              </h1>
              <QuickSearch />
            </div>

            <main className="flex-1 overflow-y-auto">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                {currentView === 'credentials' && (
                  <CredentialList onCreateCredential={() => setShowCreateCredential(true)} />
                )}
                {currentView === 'statistics' && <StatisticsView />}
                {currentView === 'sshAgent' && <SshAgentPanel />}
                {currentView === 'wallets' && <WalletPanel />}
                {currentView === 'watchtower' && <WatchtowerPanel />}
                {currentView === 'passkeys' && <PasskeyPanel />}
              </div>
            </main>
          </div>
        </div>

        {/* Modals */}
        <CreateIdentityModal
          isOpen={showCreateIdentity}
          onClose={() => setShowCreateIdentity(false)}
        />

        <CreateCredentialModal
          isOpen={showCreateCredential || editingCredential !== null}
          editCredential={editingCredential}
          onClose={() => {
            setShowCreateCredential(false);
            setEditingCredential(null);
          }}
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
        <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Statistics</h2>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-500/10 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Total Identities</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.total_identities}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 dark:bg-green-500/10 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Total Credentials</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.total_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-500/10 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Active Credentials</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.active_credentials}</p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 dark:bg-red-500/10 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">Favorites</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.favorite_credentials}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Credential Types Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Credential Types</h3>
          <div className="space-y-3">
            {Object.entries(statistics.credential_types).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{type}</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{count as number}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">Security Levels</h3>
          <div className="space-y-3">
            {Object.entries(statistics.security_levels).map(([level, count]) => (
              <div key={level} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{level}</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
