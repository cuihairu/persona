import React, { useEffect, useMemo, useRef, useState } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { ChartBarIcon, KeyIcon } from '@heroicons/react/24/outline';
import { useTranslation } from 'react-i18next';
import i18n, { normalizeLocale } from '@/i18n';
import { usePersonaService } from '@/hooks/usePersonaService';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { useAutoLockEvents } from '@/hooks/useAutoLockEvents';
import { useQuickAccessBridge } from '@/hooks/useQuickAccessBridge';
import { useSshApprovals } from '@/hooks/useSshApprovals';
import { usePasskeyApprovals } from '@/hooks/usePasskeyApprovals';
import { useTheme } from '@/hooks/useTheme';
import { personaAPI } from '@/utils/api';
import { copyToClipboardWithToast } from '@/utils/clipboard';
import { checkForUpdate, isUpdateCheckEnabled } from '@/utils/updateCheck';
import { useAppStore, DEFAULT_FEATURE_FLAGS } from '@/stores/appStore';
import UnlockScreen from '@/components/UnlockScreen';
import { CreateIdentityModal } from '@/components/IdentitySwitcher';
import CredentialList from '@/components/CredentialList';
import CredentialDetailPane from '@/components/CredentialDetailPane';
import CreateCredentialModal from '@/components/CreateCredentialModal';
import { ErrorBoundary, ErrorDisplay, LoadingSpinner } from '@/components/ErrorHandling';
import SshApprovalModal from '@/components/SshApprovalModal';
import PasskeyApprovalModal from '@/components/PasskeyApprovalModal';
import SshAgentPanel from '@/components/SshAgentPanel';
import WalletPanel from '@/components/WalletPanel';
import WatchtowerPanel from '@/components/WatchtowerPanel';
import PasskeyPanel from '@/components/PasskeyPanel';
import GeneratorPanel from '@/components/GeneratorPanel';
import SettingsModal from '@/components/SettingsModal';
import QuickSearch from '@/components/QuickSearch';
import Sidebar from '@/components/Sidebar';
import {
  ALL_ITEMS_FILTER,
  FLAG_BY_VIEW,
  filterLabel,
  viewForFilter,
} from '@/components/sidebarNav';
import type { SidebarFilter } from '@/components/sidebarNav';
import { credentialTypeLabel, securityLevelLabel } from '@/components/credentialDisplay';

/** 两个 Toaster（锁定态/主界面）共用的气泡样式；配色走 .persona-toast 的 CSS 变量随主题翻转 */
const TOAST_OPTIONS = { className: 'persona-toast' };

const App: React.FC = () => {
  // 主题联动：偏好 → <html>.dark + localStorage + 原生窗口主题（挂在早退 return 之前）
  useTheme();
  const { t } = useTranslation();

  const {
    isUnlocked,
    currentIdentity,
    error,
    isLoading,
    lockService,
    loadCredentialsForIdentity,
    switchIdentity,
    getCredentialData,
    clearError,
  } = usePersonaService();

  // 语言偏好恢复：get_workspace_settings 免解锁可读，锁屏阶段即生效；
  // mount 时已解锁则跳过（解锁路径的 settings 读取见下方 flags effect，会一并应用
  // locale），避免同帧重复调用 workspace 设置。读取失败静默保持默认 zh-CN。
  useEffect(() => {
    if (isUnlocked) {
      return;
    }
    (async () => {
      try {
        const resp = await personaAPI.getWorkspaceSettings();
        if (resp.success && resp.data) {
          void i18n.changeLanguage(normalizeLocale(resp.data.locale));
        }
      } catch {
        // keep default
      }
    })();
    // 仅 mount 时判断初始锁定态（effect 内只引用模块级导入，无响应式依赖）
  }, []);

  const featureFlags = useAppStore((s) => s.featureFlags);
  const setFeatureFlags = useAppStore((s) => s.setFeatureFlags);
  const resetSidebarFilter = useAppStore((s) => s.resetSidebarFilter);
  const sidebarFilter = useAppStore((s) => s.sidebarFilter);
  const setSidebarFilter = useAppStore((s) => s.setSidebarFilter);
  const identities = useAppStore((s) => s.identities);
  // 编辑中的凭据（DetailPane Edit 按钮写入；modal 消费，null = 创建模式）
  const editingCredential = useAppStore((s) => s.editingCredential);
  const setEditingCredential = useAppStore((s) => s.setEditingCredential);
  // 详情面板：选中 id 在 store（列表/⌘E/全局搜索共用），数据由这里统一加载
  const credentials = useAppStore((s) => s.credentials);
  const selectedCredentialId = useAppStore((s) => s.selectedCredentialId);
  const setSelectedCredentialId = useAppStore((s) => s.setSelectedCredentialId);
  const selectedCredential = useMemo(
    () => credentials.find((c) => c.id === selectedCredentialId) ?? null,
    [credentials, selectedCredentialId],
  );
  const [credentialData, setCredentialData] = useState<any>(null);
  // hook 非 useCallback，用 ref 持有最新加载函数：effect 只依赖选中 id，
  // 避免每次渲染都重发请求
  const loadCredentialDataRef = useRef(getCredentialData);
  loadCredentialDataRef.current = getCredentialData;
  useEffect(() => {
    let cancelled = false;
    setCredentialData(null);
    if (!selectedCredentialId) return;
    void loadCredentialDataRef.current(selectedCredentialId).then((data) => {
      if (!cancelled) setCredentialData(data);
    });
    return () => {
      cancelled = true;
    };
  }, [selectedCredentialId]);

  const [showCreateIdentity, setShowCreateIdentity] = useState(false);
  const [showCreateCredential, setShowCreateCredential] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // 导航只有一个事实源：侧栏筛选态 → 主区视图（工具/通行密钥是面板，其余是列表）
  const currentView = viewForFilter(sidebarFilter);

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

  // ⌘G 呼出密码生成器（主航道视图；生成是纯计算，无需选中身份）
  useGlobalShortcut('g', () => setSidebarFilter({ kind: 'generator' }), isUnlocked);

  // ⌘E 复制当前选中凭据的用户名（按键时现读 store，不订阅、无陈旧闭包）
  const handleCopyUsername = () => {
    const { credentials, selectedCredentialId, currentIdentity } = useAppStore.getState();
    const selected = credentials.find((c) => c.id === selectedCredentialId);
    // 无选中 / 选中已悬空（停在别的视图时切身份会残留跨身份 id）都按"未选中"提示
    if (!selected || (currentIdentity && selected.identity_id !== currentIdentity.id)) {
      toast.error(t('app.selectEntryFirst'));
      return;
    }
    if (!selected.username) {
      toast.error(t('app.noUsername'));
      return;
    }
    void copyToClipboardWithToast(selected.username, t('app.username'));
  };
  useGlobalShortcut('e', handleCopyUsername, isUnlocked);

  // Auto-lock 事件流：lock_pending 倒计时横幅 + locked 回解锁屏（hook 内处理）
  const { pendingSeconds } = useAutoLockEvents(isUnlocked);

  // Quick Access 浮窗的跨窗跳转（浮窗 → 主窗口切身份 + 选中条目）
  useQuickAccessBridge();

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

  // 启动时按构建渠道检查一次版本更新（设置里可关；dev 构建不比对）。
  // i18n.t 在回调时取当前语言，语言切换不重查。
  useEffect(() => {
    if (!isUpdateCheckEnabled()) return;
    void checkForUpdate()
      .then((outcome) => {
        if (outcome.status === 'update-available') {
          toast(
            i18n.t('settings.updateCheck.availableToast', {
              version: outcome.latestVersion ?? '',
            }),
            { duration: 8000, className: TOAST_OPTIONS.className },
          );
        }
      })
      .catch(() => {});
  }, []);

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
          // 同一次读取顺带刷新语言偏好（解锁前后设置可能变化，幂等）
          void i18n.changeLanguage(normalizeLocale(resp.data.locale));
        }
      } catch {
        // keep defaults
      }
    })();
  }, [isUnlocked, setFeatureFlags]);

  // 当前视图依赖的开关被关闭时回退到全部条目（侧栏入口同时消失，避免停在不可达视图）
  useEffect(() => {
    const flag = FLAG_BY_VIEW[currentView];
    if (flag && !featureFlags[flag]) {
      setSidebarFilter(ALL_ITEMS_FILTER);
    }
  }, [currentView, featureFlags, setSidebarFilter]);

  // 侧栏点保险库 = 切换当前身份（身份即保险库，条目按身份加载）
  const handleNavigate = (filter: SidebarFilter) => {
    if (filter.kind === 'identity') {
      const targetIdentity = identities.find((i) => i.id === filter.value);
      if (targetIdentity) {
        void switchIdentity(targetIdentity);
      }
    }
  };

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
        <LoadingSpinner message={t('app.initializing')} />
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
            {t('app.autoLockBanner', { seconds: pendingSeconds })}
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

        <div className="flex min-h-0 flex-1">
          <Sidebar
            onNavigate={handleNavigate}
            onCreateIdentity={() => setShowCreateIdentity(true)}
            onOpenSettings={() => setShowSettings(true)}
            onLock={handleLock}
          />

          {/* 主列：工具条（当前节点标题 + 全局搜索）+ 独立滚动的主区 */}
          <div className="flex min-w-0 flex-1 flex-col bg-background dark:bg-gray-950">
            <div className="flex h-12 shrink-0 items-center gap-3 border-b border-secondary-200 px-4 dark:border-gray-800">
              <h1
                data-testid="view-title"
                className="truncate text-sm font-semibold text-secondary-900 dark:text-secondary-50"
              >
                {filterLabel(t, sidebarFilter, identities)}
              </h1>
              <QuickSearch />
            </div>

            {currentView === 'credentials' ? (
              <main className="min-h-0 flex-1 overflow-hidden p-4">
                <div className="mx-auto flex h-full max-w-7xl overflow-hidden rounded-lg border border-secondary-200 bg-white dark:border-gray-800 dark:bg-gray-900">
                  <div className="flex h-full min-w-0 flex-1 flex-col">
                    <CredentialList onCreateCredential={() => setShowCreateCredential(true)} />
                  </div>
                  {/* 详情面板列：未选中时占位；窄屏（<lg）隐藏，详情在移动布局中省略 */}
                  <div className="hidden w-[360px] shrink-0 overflow-y-auto border-l border-secondary-200 dark:border-gray-800 lg:block">
                    {selectedCredential ? (
                      <CredentialDetailPane
                        credential={selectedCredential}
                        credentialData={credentialData}
                        onClose={() => {
                          setSelectedCredentialId(null);
                          setCredentialData(null);
                        }}
                        onCopy={copyToClipboardWithToast}
                      />
                    ) : (
                      <div
                        data-testid="detail-placeholder"
                        className="flex h-full items-center justify-center p-6 text-secondary-400 dark:text-secondary-500"
                      >
                        <div className="text-center">
                          <KeyIcon className="mx-auto mb-3 h-10 w-10 text-secondary-300 dark:text-secondary-600" />
                          <p>{t('credList.selectItem')}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </main>
            ) : (
              <main className="min-h-0 flex-1 overflow-y-auto">
                <div className="mx-auto max-w-7xl px-4 py-6">
                  {currentView === 'statistics' && <StatisticsView />}
                  {currentView === 'sshAgent' && <SshAgentPanel />}
                  {currentView === 'wallets' && <WalletPanel />}
                  {currentView === 'watchtower' && <WatchtowerPanel />}
                  {currentView === 'passkeys' && <PasskeyPanel />}
                  {currentView === 'generator' && <GeneratorPanel />}
                </div>
              </main>
            )}
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
  const { t } = useTranslation();
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
        <h2 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.title')}</h2>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 dark:bg-blue-500/10 rounded-lg mr-4">
              <ChartBarIcon className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.totalIdentities')}</p>
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
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.totalCredentials')}</p>
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
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.activeCredentials')}</p>
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
              <p className="text-sm font-medium text-gray-600 dark:text-gray-300">{t('statistics.favorites')}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{statistics.favorite_credentials}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Credential Types Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.credentialTypes')}</h3>
          <div className="space-y-3">
            {Object.entries(statistics.credential_types).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{credentialTypeLabel(t, type)}</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{count as number}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">{t('statistics.securityLevels')}</h3>
          <div className="space-y-3">
            {Object.entries(statistics.security_levels).map(([level, count]) => (
              <div key={level} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-300">{securityLevelLabel(t, level)}</span>
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
