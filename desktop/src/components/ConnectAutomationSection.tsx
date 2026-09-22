import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { personaAPI } from '../utils/api';
import type {
  ConnectServerStatus,
  ConnectTokenCreatedView,
  ConnectTokenScope,
  ConnectTokenView,
  Identity,
} from '../types';
import ReauthModal from './ReauthModal';

/**
 * Connect 本机自动化设置区（CONNECT_AUTOMATION_DESIGN DR-5：桌面设置页
 * token 管理面）。listener 默认关闭 = 后端不创建 listener；token 创建/吊销
 * 走 reauth 门禁（core 权威），明文只在创建响应里出现一次。
 */

/** 可授权类型词汇表（与 core ConnectItemType snake_case 一致；passkey/
 * wallet/ssh/custom 恒不可授权，不在列） */
const CONNECT_ITEM_TYPES: { value: string; label: string }[] = [
  { value: 'password', label: 'settings.connect.typePassword' },
  { value: 'api_key', label: 'settings.connect.typeApiKey' },
  { value: 'totp', label: 'settings.connect.typeTotp' },
  { value: 'note', label: 'settings.connect.typeNote' },
  { value: 'bank_card', label: 'settings.connect.typeBankCard' },
  { value: 'server_config', label: 'settings.connect.typeServerConfig' },
  { value: 'certificate', label: 'settings.connect.typeCertificate' },
  { value: 'game_account', label: 'settings.connect.typeGameAccount' },
  { value: 'identity', label: 'settings.connect.typeIdentity' },
  { value: 'software_license', label: 'settings.connect.typeSoftwareLicense' },
];

/** scope 摘要（列表行）：身份 + 类型 + 只读 */
function scopeSummary(t: (k: string, o?: Record<string, unknown>) => string, scope: ConnectTokenScope): string {
  const identityPart =
    scope.identities.length === 0
      ? t('settings.connect.scopeAllIdentitiesShort')
      : t('settings.connect.scopePickedIdentitiesShort', { count: scope.identities.length });
  const typePart =
    scope.item_types.length === 0
      ? t('settings.connect.scopeAllTypesShort')
      : scope.item_types.join(', ');
  return `${identityPart} · ${typePart} · ${t('settings.connect.readOnly')}`;
}

const ConnectAutomationSection: React.FC = () => {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ConnectServerStatus | null>(null);
  const [tokens, setTokens] = useState<ConnectTokenView[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 创建流：表单 →（REAUTH_REQUIRED 时先 reauth）→ 明文一次性展示
  const [createOpen, setCreateOpen] = useState(false);
  const [label, setLabel] = useState('');
  const [allIdentities, setAllIdentities] = useState(true);
  const [pickedIdentities, setPickedIdentities] = useState<Set<string>>(new Set());
  const [allTypes, setAllTypes] = useState(false);
  const [pickedTypes, setPickedTypes] = useState<Set<string>>(new Set(['password']));
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [reauthOpen, setReauthOpen] = useState(false);
  const [reauthError, setReauthError] = useState<string | null>(null);
  const [created, setCreated] = useState<ConnectTokenCreatedView | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const statusResp = await personaAPI.connectServerStatus();
      if (statusResp.success && statusResp.data) setStatus(statusResp.data);
      const tokensResp = await personaAPI.connectTokenList();
      if (tokensResp.success && tokensResp.data) setTokens(tokensResp.data);
      const idResp = await personaAPI.getIdentities();
      if (idResp.success && idResp.data) setIdentities(idResp.data);
    } catch {
      // 状态读取失败不打断面板
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const toggleServer = async () => {
    setBusy(true);
    setError(null);
    try {
      const resp = status?.running
        ? await personaAPI.connectServerStop()
        : await personaAPI.connectServerStart(null);
      if (resp.success && resp.data) {
        setStatus(resp.data);
      } else {
        setError(resp.error || t('settings.connect.operationFailed'));
      }
    } catch {
      setError(t('settings.connect.operationFailed'));
    } finally {
      setBusy(false);
    }
  };

  const openCreate = () => {
    setLabel('');
    setAllIdentities(true);
    setPickedIdentities(new Set());
    setAllTypes(false);
    setPickedTypes(new Set(['password']));
    setFormError(null);
    setCreated(null);
    setCopied(false);
    setCreateOpen(true);
  };

  /** 组装 scope 并创建；REAUTH_REQUIRED → 关表单弹 reauth，成功后原样重试 */
  const submitCreate = async () => {
    if (!label.trim()) {
      setFormError(t('settings.connect.labelRequired'));
      return;
    }
    if (!allIdentities && pickedIdentities.size === 0) {
      setFormError(t('settings.connect.pickAtLeastOneIdentity'));
      return;
    }
    if (!allTypes && pickedTypes.size === 0) {
      setFormError(t('settings.connect.pickAtLeastOneType'));
      return;
    }
    const scope: ConnectTokenScope = {
      identities: allIdentities ? [] : Array.from(pickedIdentities),
      item_types: allTypes ? [] : Array.from(pickedTypes),
      verbs: ['read'],
    };
    setSubmitting(true);
    setFormError(null);
    try {
      const resp = await personaAPI.connectTokenCreate(label.trim(), scope);
      if (resp.success && resp.data) {
        setCreateOpen(false);
        setCreated(resp.data);
        setCopied(false);
        await refresh();
      } else if (resp.error_code === 'REAUTH_REQUIRED') {
        setCreateOpen(false);
        setReauthError(null);
        setReauthOpen(true);
      } else {
        setFormError(resp.error || t('settings.connect.operationFailed'));
      }
    } catch {
      setFormError(t('settings.connect.operationFailed'));
    } finally {
      setSubmitting(false);
    }
  };

  /** reauth 成功后按原表单意图重开创建流（表单态未销毁） */
  const handleReauth = async (masterPassword: string) => {
    setSubmitting(true);
    try {
      const resp = await personaAPI.reauthVerify(masterPassword);
      if (resp.success && resp.data) {
        setReauthOpen(false);
        setCreateOpen(true);
      } else {
        setReauthError(resp.error || t('settings.connect.operationFailed'));
      }
    } catch {
      setReauthError(t('settings.connect.operationFailed'));
    } finally {
      setSubmitting(false);
    }
  };

  const revoke = async (token: ConnectTokenView) => {
    if (!window.confirm(t('settings.connect.revokeConfirm', { label: token.label }))) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await personaAPI.connectTokenRevoke(token.id);
      if (resp.success) {
        await refresh();
      } else if (resp.error_code === 'REAUTH_REQUIRED') {
        setError(t('settings.connect.reauthHint'));
      } else {
        setError(resp.error || t('settings.connect.revokeFailed'));
      }
    } catch {
      setError(t('settings.connect.revokeFailed'));
    } finally {
      setBusy(false);
    }
  };

  const copyToken = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div>
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
        {t('settings.connect.title')}
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        {t('settings.connect.description')}
      </p>
      <div className="border border-gray-200 rounded-lg p-4 space-y-4 dark:border-gray-700" data-testid="connect-section">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100" data-testid="connect-status">
              {status?.running
                ? t('settings.connect.statusRunning', { port: status.port ?? '?' })
                : t('settings.connect.statusStopped')}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">{t('settings.connect.statusHint')}</p>
            {error && (
              <p className="text-xs text-red-600 dark:text-red-400 mt-1" data-testid="connect-error">
                {error}
              </p>
            )}
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={status?.running ?? false}
            data-testid="connect-server-toggle"
            disabled={busy || !status}
            onClick={() => void toggleServer()}
            className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              status?.running ? 'bg-primary-600' : 'bg-gray-200 dark:bg-gray-700'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                status?.running ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        {status?.running && (
          <div className="rounded-md bg-yellow-50 px-3 py-2 text-xs text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200">
            {t('settings.connect.runningWarning')}
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{t('settings.connect.tokensTitle')}</p>
            <button type="button" data-testid="connect-create-token" onClick={openCreate} className="btn-secondary text-xs">
              {t('settings.connect.createButton')}
            </button>
          </div>
          {tokens.length === 0 ? (
            <p className="text-xs text-gray-500 dark:text-gray-400" data-testid="connect-tokens-empty">
              {t('settings.connect.tokenNone')}
            </p>
          ) : (
            <ul className="divide-y divide-gray-100 dark:divide-gray-800 border border-gray-100 rounded-md dark:border-gray-800" data-testid="connect-tokens-list">
              {tokens.map((token) => (
                <li key={token.id} className="flex items-center justify-between gap-4 px-3 py-2">
                  <div className="min-w-0">
                    <p className="text-sm text-gray-900 dark:text-gray-100 truncate">
                      {token.label}
                      {token.revoked_at && (
                        <span className="ml-2 text-xs text-gray-400">({t('settings.connect.tokenRevoked')})</span>
                      )}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                      {token.fingerprint}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{scopeSummary(t, token.scope)}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500">
                      {token.last_used_at
                        ? t('settings.connect.tokenLastUsed', { time: new Date(token.last_used_at).toLocaleString() })
                        : t('settings.connect.tokenNeverUsed')}
                    </p>
                  </div>
                  {!token.revoked_at && (
                    <button
                      type="button"
                      data-testid={`connect-revoke-${token.id}`}
                      disabled={busy}
                      onClick={() => void revoke(token)}
                      className="btn-secondary flex-shrink-0 text-xs text-red-600 dark:text-red-400"
                    >
                      {t('settings.connect.revokeButton')}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {createOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" data-testid="connect-create-modal">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 p-5 space-y-4">
            <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.connect.createTitle')}
            </h4>
            <p className="text-xs text-gray-500 dark:text-gray-400">{t('settings.connect.createDescription')}</p>

            <div>
              <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="connect-token-label">
                {t('settings.connect.labelField')}
              </label>
              <input
                id="connect-token-label"
                data-testid="connect-token-label"
                className="input w-full"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder={t('settings.connect.labelPlaceholder')}
              />
            </div>

            <fieldset>
              <legend className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                {t('settings.connect.scopeIdentities')}
              </legend>
              <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                <input
                  type="radio"
                  name="connect-scope-identities"
                  data-testid="connect-identities-all"
                  checked={allIdentities}
                  onChange={() => setAllIdentities(true)}
                />
                {t('settings.connect.allIdentities')}
              </label>
              <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                <input
                  type="radio"
                  name="connect-scope-identities"
                  data-testid="connect-identities-pick"
                  checked={!allIdentities}
                  onChange={() => setAllIdentities(false)}
                />
                {t('settings.connect.pickedIdentities')}
              </label>
              {allIdentities && (
                <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1" data-testid="connect-all-identities-warning">
                  {t('settings.connect.allIdentitiesWarning')}
                </p>
              )}
              {!allIdentities && (
                <div className="mt-1 max-h-32 overflow-y-auto border border-gray-200 rounded-md p-2 space-y-1 dark:border-gray-700">
                  {identities.map((identity) => (
                    <label key={identity.id} className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                      <input
                        type="checkbox"
                        data-testid={`connect-identity-${identity.id}`}
                        checked={pickedIdentities.has(identity.id)}
                        onChange={(e) => {
                          const next = new Set(pickedIdentities);
                          if (e.target.checked) next.add(identity.id);
                          else next.delete(identity.id);
                          setPickedIdentities(next);
                        }}
                      />
                      {identity.name}
                    </label>
                  ))}
                </div>
              )}
            </fieldset>

            <fieldset>
              <legend className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                {t('settings.connect.scopeTypes')}
              </legend>
              <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                <input
                  type="radio"
                  name="connect-scope-types"
                  data-testid="connect-types-all"
                  checked={allTypes}
                  onChange={() => setAllTypes(true)}
                />
                {t('settings.connect.allTypes')}
              </label>
              <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                <input
                  type="radio"
                  name="connect-scope-types"
                  data-testid="connect-types-pick"
                  checked={!allTypes}
                  onChange={() => setAllTypes(false)}
                />
                {t('settings.connect.pickedTypes')}
              </label>
              {!allTypes && (
                <div className="mt-1 grid grid-cols-2 gap-1 border border-gray-200 rounded-md p-2 dark:border-gray-700">
                  {CONNECT_ITEM_TYPES.map((item) => (
                    <label key={item.value} className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                      <input
                        type="checkbox"
                        data-testid={`connect-type-${item.value}`}
                        checked={pickedTypes.has(item.value)}
                        onChange={(e) => {
                          const next = new Set(pickedTypes);
                          if (e.target.checked) next.add(item.value);
                          else next.delete(item.value);
                          setPickedTypes(next);
                        }}
                      />
                      {t(item.label)}
                    </label>
                  ))}
                </div>
              )}
            </fieldset>

            {formError && (
              <p className="text-xs text-red-600 dark:text-red-400" data-testid="connect-create-error">
                {formError}
              </p>
            )}

            <div className="flex justify-end gap-2">
              <button type="button" data-testid="connect-create-cancel" onClick={() => setCreateOpen(false)} className="btn-secondary text-xs">
                {t('common.cancel')}
              </button>
              <button
                type="button"
                data-testid="connect-create-submit"
                disabled={submitting}
                onClick={() => void submitCreate()}
                className="btn-primary text-xs disabled:opacity-50"
              >
                {t('settings.connect.submitCreate')}
              </button>
            </div>
          </div>
        </div>
      )}

      {created && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" data-testid="connect-created-modal">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 p-5 space-y-4">
            <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {t('settings.connect.createdTitle')}
            </h4>
            <p className="text-xs text-red-600 dark:text-red-400" data-testid="connect-created-warning">
              {t('settings.connect.createdOnceWarning')}
            </p>
            <code className="block break-all rounded-md bg-gray-100 px-3 py-2 text-xs text-gray-900 dark:bg-gray-900 dark:text-gray-100" data-testid="connect-created-token">
              {created.token}
            </code>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {scopeSummary(t, created.info.scope)}
            </p>
            <div className="flex justify-end gap-2">
              <button type="button" data-testid="connect-created-copy" onClick={() => void copyToken()} className="btn-secondary text-xs">
                {copied ? t('settings.connect.copied') : t('settings.connect.copyButton')}
              </button>
              <button type="button" data-testid="connect-created-done" onClick={() => setCreated(null)} className="btn-primary text-xs">
                {t('settings.connect.createdDone')}
              </button>
            </div>
          </div>
        </div>
      )}

      <ReauthModal
        isOpen={reauthOpen}
        error={reauthError}
        isVerifying={submitting}
        onSubmit={(pw) => void handleReauth(pw)}
        onClose={() => setReauthOpen(false)}
      />
    </div>
  );
};

export default ConnectAutomationSection;
